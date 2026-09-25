//! Full dependency-graph resolution through the Rivet registry. The registry
//! picks versions (semver, cooldown, skipping unsafe releases) and signs each
//! choice; the resolver walks the graph from signed manifests only.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Mutex,
};

use anyhow::{anyhow, bail, Context, Result};
use time::OffsetDateTime;

use super::{
    attestation::{Envelope, Statement, TrustedKey},
    lockfile::{LockedPackage, LockedRoot, Lockfile},
    policy::{Policy, Refusal},
    registry_client::RegistryClient,
};

const WORKERS: usize = 8;

#[derive(Debug, Clone)]
pub struct Node {
    pub statement: Statement,
    pub envelope: Envelope,
    /// alias as it appears in node_modules -> package id
    pub deps: BTreeMap<String, String>,
    pub optional: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub roots: BTreeMap<String, LockedRoot>,
    pub nodes: BTreeMap<String, Node>,
    pub warnings: Vec<String>,
    /// Versions the registry skipped (cooldown, unsafe) and optional
    /// dependencies left out, for display.
    pub notes: Vec<String>,
    /// Optional platform packages (e.g. @esbuild/win32-x64) left out.
    pub other_platforms: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Normal,
    Optional,
    Peer,
}

#[derive(Debug, Clone)]
struct Request {
    parent: Option<String>,
    alias: String,
    name: String,
    spec: String,
    kind: Kind,
}

/// Splits a dependency spec into (package name, range), expanding
/// "npm:<name>@<range>" aliases.
pub fn parse_spec(alias: &str, spec: &str) -> Result<(String, String)> {
    validate_package_name(alias)?;
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix("npm:") {
        let (name, range) = split_name_version(rest);
        if name.is_empty() {
            bail!("invalid npm alias {spec:?} for {alias}");
        }
        validate_package_name(&name)?;
        return Ok((name, range.unwrap_or_else(|| "latest".into())));
    }
    let spec = if spec.is_empty() { "latest" } else { spec };
    Ok((alias.to_string(), spec.to_string()))
}

/// Package names are also filesystem paths. Validate each component before
/// using an alias or a signed name to build a node_modules destination.
pub fn validate_package_name(name: &str) -> Result<()> {
    let parts: Vec<&str> = if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped
            .split_once('/')
            .context("invalid scoped package name")?;
        vec![scope, package]
    } else {
        vec![name]
    };
    if name.len() > 214
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.starts_with('.')
                || part.starts_with('_')
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~!*'()".contains(&b))
        })
        || name.matches('/').count() != parts.len() - 1
    {
        bail!("unsafe package name or dependency alias {name:?}");
    }
    Ok(())
}

/// The "@scope" directory of a scoped package name, if any.
pub fn package_scope(name: &str) -> Option<&str> {
    name.starts_with('@')
        .then(|| name.split_once('/').map(|(scope, _)| scope))
        .flatten()
}

/// Splits "name@version", keeping the leading "@" of scoped names.
pub fn split_name_version(value: &str) -> (String, Option<String>) {
    let search_from = usize::from(value.starts_with('@'));
    match value[search_from..].find('@') {
        Some(index) => {
            let index = index + search_from;
            let version = &value[index + 1..];
            (
                value[..index].to_string(),
                (!version.is_empty()).then(|| version.to_string()),
            )
        }
        None => (value.to_string(), None),
    }
}

pub fn current_platform() -> (&'static str, &'static str) {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    let cpu = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "ia32",
        other => other,
    };
    (os, cpu)
}

/// npm os/cpu matching: positive entries must include the current value,
/// "!value" entries exclude it.
pub fn platform_matches(list: &[String], current: &str) -> bool {
    if list.is_empty() {
        return true;
    }
    if list
        .iter()
        .any(|entry| entry.strip_prefix('!') == Some(current))
    {
        return false;
    }
    let positives: Vec<_> = list.iter().filter(|e| !e.starts_with('!')).collect();
    positives.is_empty() || positives.iter().any(|e| e.as_str() == current)
}

pub struct Resolver<'a> {
    pub client: &'a RegistryClient,
    pub key: &'a TrustedKey,
    pub policy: &'a Policy,
    pub locked: Option<&'a Lockfile>,
}

impl Resolver<'_> {
    /// Resolves `roots` (alias -> spec) into a verified graph.
    pub fn resolve(&self, roots: &BTreeMap<String, String>) -> Result<Graph> {
        let mut graph = Graph::default();
        let mut queue = Vec::new();
        for (alias, spec) in roots {
            let (name, range) = parse_spec(alias, spec)?;
            queue.push(Request {
                parent: None,
                alias: alias.clone(),
                name,
                spec: range,
                kind: Kind::Normal,
            });
            graph.roots.insert(
                alias.clone(),
                LockedRoot {
                    spec: spec.clone(),
                    package: String::new(),
                },
            );
        }
        let mut memo: HashMap<(String, String), std::result::Result<String, String>> =
            HashMap::new();
        let mut expanded: BTreeSet<String> = BTreeSet::new();
        let (os, cpu) = current_platform();
        let now = OffsetDateTime::now_utc();

        while !queue.is_empty() {
            let batch = std::mem::take(&mut queue);
            let mut wanted: Vec<(String, String, Vec<String>)> = Vec::new();
            let mut seen = BTreeSet::new();
            for request in &batch {
                let key = (request.name.clone(), request.spec.clone());
                if memo.contains_key(&key) || !seen.insert(key.clone()) {
                    continue;
                }
                wanted.push((
                    request.name.clone(),
                    request.spec.clone(),
                    self.prefer(&graph, &request.name),
                ));
            }
            for (key, outcome) in self.fetch_all(wanted, now) {
                let outcome = outcome.and_then(|(statement, envelope)| {
                    let id = statement.id();
                    if !graph.nodes.contains_key(&id) {
                        let warnings =
                            self.policy
                                .check(&statement, self.is_locked(&id))
                                .map_err(|e| {
                                    if e.downcast_ref::<Refusal>().is_some() {
                                        format!("refused: {e}")
                                    } else {
                                        e.to_string()
                                    }
                                })?;
                        graph.warnings.extend(warnings);
                        graph.nodes.insert(
                            id.clone(),
                            Node {
                                statement,
                                envelope,
                                deps: BTreeMap::new(),
                                optional: true,
                            },
                        );
                    }
                    Ok(id)
                });
                memo.insert(key, outcome);
            }

            for request in batch {
                let key = (request.name.clone(), request.spec.clone());
                let outcome = memo
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| Err("not resolved".into()));
                let id = match outcome {
                    Ok(id) => id,
                    Err(error) if request.kind == Kind::Optional => {
                        graph.notes.push(format!(
                            "skipped optional dependency {}@{}: {error}",
                            request.name, request.spec
                        ));
                        continue;
                    }
                    Err(error) => {
                        let via = request
                            .parent
                            .as_deref()
                            .map(|p| format!(" (required by {p})"))
                            .unwrap_or_default();
                        bail!(
                            "cannot install {}@{}{via}: {error}",
                            request.name,
                            request.spec
                        );
                    }
                };
                let manifest = graph.nodes[&id].statement.manifest.clone();
                let platform_ok =
                    platform_matches(&manifest.os, os) && platform_matches(&manifest.cpu, cpu);
                if !platform_ok {
                    if request.kind == Kind::Optional {
                        graph.other_platforms.push(id.clone());
                        continue;
                    }
                    graph.warnings.push(format!(
                        "{id} declares os {:?} cpu {:?}; installing anyway",
                        manifest.os, manifest.cpu
                    ));
                }
                if request.kind != Kind::Optional {
                    graph.nodes.get_mut(&id).expect("node exists").optional = false;
                }
                match &request.parent {
                    None => {
                        graph
                            .roots
                            .get_mut(&request.alias)
                            .expect("root exists")
                            .package = id.clone();
                    }
                    Some(parent) => {
                        graph
                            .nodes
                            .get_mut(parent)
                            .expect("parent exists")
                            .deps
                            .insert(request.alias.clone(), id.clone());
                    }
                }
                if expanded.insert(id.clone()) {
                    self.enqueue_children(&id, &manifest, &graph, &mut queue)?;
                }
            }
        }
        prune_unlinked(&mut graph);
        graph.other_platforms.sort();
        graph.other_platforms.dedup();
        Ok(graph)
    }

    fn enqueue_children(
        &self,
        id: &str,
        manifest: &super::attestation::PackageManifest,
        graph: &Graph,
        queue: &mut Vec<Request>,
    ) -> Result<()> {
        for (alias, spec) in &manifest.dependencies {
            let (name, range) =
                parse_spec(alias, spec).with_context(|| format!("dependency of {id}"))?;
            queue.push(Request {
                parent: Some(id.into()),
                alias: alias.clone(),
                name,
                spec: range,
                kind: Kind::Normal,
            });
        }
        for (alias, spec) in &manifest.optional_dependencies {
            match parse_spec(alias, spec) {
                Ok((name, range)) => queue.push(Request {
                    parent: Some(id.into()),
                    alias: alias.clone(),
                    name,
                    spec: range,
                    kind: Kind::Optional,
                }),
                Err(_) => continue,
            }
        }
        for (alias, spec) in &manifest.peer_dependencies {
            if manifest.dependencies.contains_key(alias)
                || manifest.optional_dependencies.contains_key(alias)
            {
                continue;
            }
            let (name, range) = parse_spec(alias, spec)?;
            let optional_peer = manifest.peer_optional.contains(alias);
            if optional_peer && !graph.nodes.values().any(|n| n.statement.name == name) {
                continue;
            }
            queue.push(Request {
                parent: Some(id.into()),
                alias: alias.clone(),
                name,
                spec: range,
                kind: if optional_peer {
                    Kind::Optional
                } else {
                    Kind::Peer
                },
            });
        }
        Ok(())
    }

    fn is_locked(&self, id: &str) -> bool {
        self.locked
            .is_some_and(|lock| lock.packages.contains_key(id))
    }

    /// Versions of `name` already chosen, so the registry reuses them when
    /// they satisfy a range (deduplication and peer consistency).
    fn prefer(&self, graph: &Graph, name: &str) -> Vec<String> {
        let mut out: Vec<String> = graph
            .nodes
            .values()
            .filter(|n| n.statement.name == name)
            .map(|n| n.statement.version.clone())
            .collect();
        if let Some(lock) = self.locked {
            out.extend(
                lock.packages
                    .values()
                    .filter(|p| p.name == name)
                    .map(|p| p.version.clone()),
            );
        }
        out.sort();
        out.dedup();
        out
    }

    #[allow(clippy::type_complexity)]
    fn fetch_all(
        &self,
        wanted: Vec<(String, String, Vec<String>)>,
        now: OffsetDateTime,
    ) -> Vec<(
        (String, String),
        std::result::Result<(Statement, Envelope), String>,
    )> {
        let results = Mutex::new(Vec::new());
        let work = Mutex::new(wanted.into_iter());
        std::thread::scope(|scope| {
            for _ in 0..WORKERS {
                scope.spawn(|| loop {
                    let next = work.lock().expect("work queue").next();
                    let Some((name, spec, prefer)) = next else {
                        break;
                    };
                    let outcome = self
                        .fetch_one(&name, &spec, &prefer, now)
                        .map_err(|e| format!("{e:#}"));
                    results
                        .lock()
                        .expect("results")
                        .push(((name, spec), outcome));
                });
            }
        });
        results.into_inner().expect("results")
    }

    fn fetch_one(
        &self,
        name: &str,
        spec: &str,
        prefer: &[String],
        now: OffsetDateTime,
    ) -> Result<(Statement, Envelope)> {
        let response =
            self.client
                .resolve(name, spec, self.policy.min_release_age_hours, prefer)?;
        let statement = response.attestation.verify(self.key, now)?;
        validate_package_name(&statement.name)?;
        for alias in statement
            .manifest
            .dependencies
            .keys()
            .chain(statement.manifest.optional_dependencies.keys())
            .chain(statement.manifest.peer_dependencies.keys())
        {
            validate_package_name(alias)?;
        }
        if statement.name != name {
            bail!(
                "registry answered {} for a request for {name}",
                statement.id()
            );
        }
        if let Some(skipped) = response.skipped.filter(|s| !s.is_empty()) {
            eprintln!("rivet: {name}@{spec}: skipped {}", skipped.join("; "));
        }
        Ok((statement, response.attestation))
    }

    /// Rebuilds a graph from a lockfile, refreshing and verifying every
    /// statement. Fails if the registry now describes different content.
    pub fn load_lockfile(&self, lock: &Lockfile) -> Result<Graph> {
        let now = OffsetDateTime::now_utc();
        let ids: Vec<(String, String)> = lock
            .packages
            .values()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        let batch = self.client.attestations(&ids)?;
        let mut graph = Graph {
            roots: lock.roots.clone(),
            ..Default::default()
        };
        for (id, locked) in &lock.packages {
            let envelope = batch.attestations.get(id).ok_or_else(|| {
                anyhow!(
                    "registry has no attestation for locked {id}: {}",
                    batch.errors.get(id).cloned().unwrap_or_default()
                )
            })?;
            let statement = envelope.verify(self.key, now)?;
            validate_package_name(&statement.name)?;
            for alias in statement
                .manifest
                .dependencies
                .keys()
                .chain(statement.manifest.optional_dependencies.keys())
                .chain(statement.manifest.peer_dependencies.keys())
            {
                validate_package_name(alias)?;
            }
            check_locked(id, locked, &statement)?;
            match self.policy.check(&statement, true) {
                Ok(warnings) => graph.warnings.extend(warnings),
                Err(err) if locked.optional => {
                    graph.notes.push(format!("skipped optional {id}: {err}"));
                    continue;
                }
                Err(err) => return Err(err),
            }
            graph.nodes.insert(
                id.clone(),
                Node {
                    statement,
                    envelope: envelope.clone(),
                    deps: locked.dependencies.clone(),
                    optional: locked.optional,
                },
            );
        }
        let present: BTreeSet<String> = graph.nodes.keys().cloned().collect();
        for node in graph.nodes.values_mut() {
            node.deps.retain(|_, dep| present.contains(dep));
        }
        for (alias, root) in &graph.roots {
            let (name, spec) = parse_spec(alias, &root.spec)?;
            self.validate_locked_edge(&name, &spec, &root.package, &graph)?;
        }
        for (id, node) in &graph.nodes {
            for (alias, spec) in &node.statement.manifest.dependencies {
                if !node.deps.contains_key(alias) {
                    bail!("frozen lock omits required dependency {alias} of {id}");
                }
                let (name, range) = parse_spec(alias, spec)?;
                self.validate_locked_edge(&name, &range, &node.deps[alias], &graph)?;
            }
            for (alias, spec) in &node.statement.manifest.peer_dependencies {
                if node.statement.manifest.dependencies.contains_key(alias)
                    || node
                        .statement
                        .manifest
                        .optional_dependencies
                        .contains_key(alias)
                    || node.statement.manifest.peer_optional.contains(alias)
                {
                    continue;
                }
                let dep = node
                    .deps
                    .get(alias)
                    .with_context(|| format!("frozen lock omits required peer {alias} of {id}"))?;
                let (name, range) = parse_spec(alias, spec)?;
                self.validate_locked_edge(&name, &range, dep, &graph)?;
            }
            for (alias, dep) in &node.deps {
                let spec = node
                    .statement
                    .manifest
                    .dependency_spec(alias)
                    .with_context(|| {
                        format!("frozen lock adds undeclared dependency {alias} to {id}")
                    })?;
                let (name, range) = parse_spec(alias, spec)?;
                self.validate_locked_edge(&name, &range, dep, &graph)?;
            }
        }
        Ok(graph)
    }

    fn validate_locked_edge(&self, name: &str, spec: &str, id: &str, graph: &Graph) -> Result<()> {
        let node = graph
            .nodes
            .get(id)
            .with_context(|| format!("frozen lock refers to absent {id}"))?;
        if node.statement.name != name {
            bail!("frozen lock routes {name} to unrelated package {id}");
        }
        if !version_satisfies(spec, &node.statement.version)? {
            bail!("frozen lock chooses {id} outside declared range {name}@{spec}");
        }
        Ok(())
    }
}

pub(crate) fn version_satisfies(spec: &str, version: &str) -> Result<bool> {
    let version: node_semver::Version = version
        .parse()
        .with_context(|| format!("invalid locked version {version:?}"))?;
    match spec.parse::<node_semver::Range>() {
        Ok(range) => Ok(version.satisfies(&range)),
        Err(_)
            if spec
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                && spec.bytes().next().is_some_and(|b| b.is_ascii_alphabetic()) =>
        {
            // Mutable dist tags cannot be reconstructed from historical
            // lock data. The signed lock still pins the exact version.
            Ok(true)
        }
        Err(err) => bail!("unsupported frozen dependency range {spec:?}: {err}"),
    }
}

fn check_locked(id: &str, locked: &LockedPackage, statement: &Statement) -> Result<()> {
    if statement.id() != id {
        bail!("registry returned {} for locked {id}", statement.id());
    }
    if statement.artifact.hash != locked.artifact
        || statement.artifact.tree_digest != locked.tree_digest
    {
        bail!(
            "registry content for {id} no longer matches rivet.lock (artifact {} vs locked {}); refusing",
            statement.artifact.hash,
            locked.artifact
        );
    }
    Ok(())
}

/// Drops nodes that ended up unreachable (e.g. optional deps for another
/// platform).
fn prune_unlinked(graph: &mut Graph) {
    let mut reachable = BTreeSet::new();
    let mut stack: Vec<String> = graph.roots.values().map(|r| r.package.clone()).collect();
    while let Some(id) = stack.pop() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        if let Some(node) = graph.nodes.get(&id) {
            stack.extend(node.deps.values().cloned());
        }
    }
    graph.nodes.retain(|id, _| reachable.contains(id));
}

impl Graph {
    pub fn to_lockfile(&self, registry: &str, key: &TrustedKey) -> Lockfile {
        Lockfile {
            version: super::lockfile::LOCKFILE_VERSION,
            registry: registry.to_string(),
            registry_key: key.keyid.clone(),
            roots: self.roots.clone(),
            packages: self
                .nodes
                .iter()
                .map(|(id, node)| {
                    let s = &node.statement;
                    (
                        id.clone(),
                        LockedPackage {
                            name: s.name.clone(),
                            version: s.version.clone(),
                            artifact: s.artifact.hash.clone(),
                            tree_digest: s.artifact.tree_digest.clone(),
                            state: s.state.clone(),
                            verdict: s.verdict().to_string(),
                            provenance: s.provenance_status().to_string(),
                            dependencies: node.deps.clone(),
                            optional: node.optional,
                            install_scripts: s.manifest.install_scripts.keys().cloned().collect(),
                        },
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aliases_and_scoped_names() {
        assert_eq!(
            parse_spec("react", "^19").unwrap(),
            ("react".into(), "^19".into())
        );
        assert_eq!(
            parse_spec("string-width-cjs", "npm:string-width@^4.2.0").unwrap(),
            ("string-width".into(), "^4.2.0".into())
        );
        assert_eq!(
            parse_spec("b", "npm:@babel/core@7").unwrap(),
            ("@babel/core".into(), "7".into())
        );
        assert_eq!(parse_spec("x", "").unwrap(), ("x".into(), "latest".into()));
        assert_eq!(
            split_name_version("@scope/pkg"),
            ("@scope/pkg".into(), None)
        );
        assert_eq!(
            split_name_version("@scope/pkg@1.0.0"),
            ("@scope/pkg".into(), Some("1.0.0".into()))
        );
    }

    #[test]
    fn platform_matching_follows_npm() {
        let list = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(platform_matches(&[], "darwin"));
        assert!(platform_matches(&list(&["darwin", "linux"]), "darwin"));
        assert!(!platform_matches(&list(&["win32"]), "darwin"));
        assert!(!platform_matches(&list(&["!darwin"]), "darwin"));
        assert!(platform_matches(&list(&["!win32"]), "darwin"));
    }

    #[test]
    fn package_alias_rejects_traversal_and_absolute_components() {
        for alias in [
            "../../victim",
            "/tmp/victim",
            "@scope/..",
            "@../pkg",
            "@scope/.",
            "a\\b",
            "line\nfeed",
        ] {
            assert!(validate_package_name(alias).is_err(), "accepted {alias:?}");
        }
        assert!(validate_package_name("@scope/package").is_ok());
    }

    #[test]
    fn frozen_range_checks_follow_npm_semver_rules() {
        let cases = [
            ("1.2.3", "1.2.4", false),
            ("1.2.3", "1.2.3", true),
            ("1.2", "1.2.9", true),
            ("1.2", "1.3.0", false),
            ("1.x", "1.8.0", true),
            (">=1.0.0 <2.0.0", "2.0.0", false),
            ("1.0.0 - 2.0.0", "1.5.0", true),
            ("^1.0.0 || ^2.0.0", "2.4.0", true),
            ("^1.2.3-beta.1", "1.2.3-beta.2", true),
        ];
        for (range, version, expected) in cases {
            assert_eq!(
                version_satisfies(range, version).unwrap(),
                expected,
                "{version} in {range}"
            );
        }
    }
}
