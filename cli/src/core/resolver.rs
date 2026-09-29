//! Full dependency-graph resolution through the Rivet registry. The registry
//! picks versions (semver, cooldown, skipping unsafe releases) and signs each
//! choice; the resolver walks the graph from signed manifests only.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Mutex,
};

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::{
    attestation::{Envelope, Statement, TrustedKey},
    lockfile::{LockVariant, LockedPackage, LockedRoot, Lockfile, TARGETS},
    policy::{Policy, Refusal},
    registry_client::RegistryClient,
};

const WORKERS: usize = 8;
type ResolveMemo = HashMap<(String, String), std::result::Result<(Statement, Envelope), String>>;

#[derive(Debug)]
struct TargetUnsupported(String);

impl std::fmt::Display for TargetUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for TargetUnsupported {}

#[derive(Debug, Clone)]
pub struct Node {
    pub statement: Statement,
    pub envelope: Envelope,
    /// alias as it appears in node_modules -> package id
    pub deps: BTreeMap<String, String>,
    pub peer_bindings: BTreeMap<String, String>,
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

pub fn target_key() -> Result<String> {
    let (os, cpu) = current_platform();
    let target = format!("{os}-{cpu}");
    if !TARGETS.contains(&target.as_str()) {
        bail!(
            "unsupported target {target}; portable locks support {}",
            TARGETS.join(", ")
        );
    }
    Ok(target)
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
        let (os, cpu) = current_platform();
        self.resolve_target(roots, os, cpu, &mut HashMap::new())
    }

    /// Resolve every supported target with one shared signed-response cache.
    pub fn resolve_portable(&self, roots: &BTreeMap<String, String>) -> Result<Lockfile> {
        let mut memo = HashMap::new();
        let mut variants = BTreeMap::new();
        for target in TARGETS {
            let (os, cpu) = target.split_once('-').expect("static target");
            let graph = match self.resolve_target(roots, os, cpu, &mut memo) {
                Ok(graph) => graph,
                Err(error) if error.downcast_ref::<TargetUnsupported>().is_some() => {
                    variants.insert(
                        target.into(),
                        LockVariant {
                            unsupported: Some(error.to_string()),
                            ..Default::default()
                        },
                    );
                    continue;
                }
                Err(error) => return Err(error),
            };
            let selected = graph.to_lockfile(self.client.base_url(), self.key);
            variants.insert(
                target.into(),
                LockVariant {
                    roots: selected.roots,
                    packages: selected.packages,
                    unsupported: None,
                },
            );
        }
        let target = target_key()?;
        let selected = variants
            .get(&target)
            .with_context(|| format!("unsupported target {target}"))?;
        if let Some(reason) = &selected.unsupported {
            bail!("{reason}");
        }
        Ok(Lockfile {
            version: super::lockfile::LOCKFILE_VERSION,
            registry: self.client.base_url().into(),
            registry_key: self.key.keyid.clone(),
            roots: BTreeMap::new(),
            packages: BTreeMap::new(),
            variants,
        })
    }

    fn resolve_target(
        &self,
        roots: &BTreeMap<String, String>,
        os: &str,
        cpu: &str,
        memo: &mut ResolveMemo,
    ) -> Result<Graph> {
        let mut base = self.resolve_base_target(roots, os, cpu, memo)?;
        self.supplement_coherent_peers(&mut base, os, cpu, memo)?;
        contextualize(&base)
    }

    fn resolve_base_target(
        &self,
        roots: &BTreeMap<String, String>,
        os: &str,
        cpu: &str,
        memo: &mut ResolveMemo,
    ) -> Result<Graph> {
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
        let mut expanded: BTreeSet<String> = BTreeSet::new();
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
                memo.insert(key, outcome);
            }

            for request in batch {
                let key = (request.name.clone(), request.spec.clone());
                let outcome = memo
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| Err("not resolved".into()));
                let id = match outcome {
                    Ok((statement, envelope)) => {
                        let id = statement.id();
                        if !graph.nodes.contains_key(&id) {
                            let warnings = self
                                .policy
                                .check(&statement, self.is_locked(&id))
                                .map_err(|e| {
                                    if e.downcast_ref::<Refusal>().is_some() {
                                        format!("refused: {e}")
                                    } else {
                                        e.to_string()
                                    }
                                });
                            match warnings {
                                Ok(warnings) => graph.warnings.extend(warnings),
                                Err(error) if request.kind == Kind::Optional => {
                                    graph.notes.push(format!("skipped optional {id}: {error}"));
                                    continue;
                                }
                                Err(error) => bail!("cannot install {id}: {error}"),
                            }
                            graph.nodes.insert(
                                id.clone(),
                                Node {
                                    statement,
                                    envelope,
                                    deps: BTreeMap::new(),
                                    peer_bindings: BTreeMap::new(),
                                    optional: true,
                                },
                            );
                        }
                        id
                    }
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
                    return Err(TargetUnsupported(format!(
                        "required {id} excludes {os}-{cpu} (os {:?}, cpu {:?})",
                        manifest.os, manifest.cpu
                    ))
                    .into());
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
                    self.enqueue_children(
                        &id,
                        &manifest,
                        request.kind == Kind::Optional,
                        &graph,
                        &mut queue,
                    )?;
                }
            }
        }
        prune_unlinked(&mut graph);
        discard_broken_optional_branches(&mut graph)?;
        graph.other_platforms.sort();
        graph.other_platforms.dedup();
        Ok(graph)
    }

    fn supplement_coherent_peers(
        &self,
        base: &mut Graph,
        os: &str,
        cpu: &str,
        memo: &mut ResolveMemo,
    ) -> Result<()> {
        loop {
            let wanted = missing_coherent_candidates(base)?;
            if wanted.is_empty() {
                return Ok(());
            }
            let before = base.nodes.len();
            for (name, range) in wanted {
                let roots = BTreeMap::from([(name.clone(), range)]);
                let extra = self.resolve_base_target(&roots, os, cpu, memo)?;
                for (id, node) in extra.nodes {
                    if let Some(old) = base.nodes.get(&id) {
                        if old.statement != node.statement {
                            bail!("conflicting signed release for {id}");
                        }
                    } else {
                        base.nodes.insert(id, node);
                    }
                }
            }
            if base.nodes.len() == before {
                bail!("no coherent peer candidate could be added");
            }
        }
    }

    fn enqueue_children(
        &self,
        id: &str,
        manifest: &super::attestation::PackageManifest,
        inherited_optional: bool,
        graph: &Graph,
        queue: &mut Vec<Request>,
    ) -> Result<()> {
        for (alias, spec) in &manifest.dependencies {
            if manifest.optional_dependencies.contains_key(alias) {
                continue;
            }
            let (name, range) =
                parse_spec(alias, spec).with_context(|| format!("dependency of {id}"))?;
            queue.push(Request {
                parent: Some(id.into()),
                alias: alias.clone(),
                name,
                spec: range,
                kind: if inherited_optional {
                    Kind::Optional
                } else {
                    Kind::Normal
                },
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
                kind: if inherited_optional || optional_peer {
                    Kind::Optional
                } else {
                    Kind::Peer
                },
            });
        }
        Ok(())
    }

    fn is_locked(&self, id: &str) -> bool {
        self.locked.is_some_and(|lock| {
            lock.packages.contains_key(id)
                || lock
                    .variants
                    .values()
                    .any(|variant| variant.packages.contains_key(id))
        })
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
            out.extend(
                lock.variants
                    .values()
                    .flat_map(|variant| variant.packages.values())
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
        let (os, cpu) = current_platform();
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
        let mut policy_skipped = BTreeSet::new();
        for (id, locked) in &lock.packages {
            let release_id = format!("{}@{}", locked.name, locked.version);
            let envelope = batch.attestations.get(&release_id).ok_or_else(|| {
                anyhow!(
                    "registry has no attestation for locked {release_id}: {}",
                    batch.errors.get(&release_id).cloned().unwrap_or_default()
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
            if !platform_matches(&statement.manifest.os, os)
                || !platform_matches(&statement.manifest.cpu, cpu)
            {
                bail!("frozen graph pins {id} for an incompatible target {os}-{cpu}");
            }
            match self.policy.check(&statement, true) {
                Ok(warnings) => graph.warnings.extend(warnings),
                Err(err) if locked.optional => {
                    graph.notes.push(format!("skipped optional {id}: {err}"));
                    policy_skipped.insert(statement.id());
                }
                Err(err) => return Err(err),
            }
            graph.nodes.insert(
                id.clone(),
                Node {
                    statement,
                    envelope: envelope.clone(),
                    deps: locked.dependencies.clone(),
                    peer_bindings: locked.peer_bindings.clone(),
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
                if node
                    .statement
                    .manifest
                    .optional_dependencies
                    .contains_key(alias)
                {
                    continue;
                }
                if !node.deps.contains_key(alias) {
                    bail!("frozen lock omits required dependency {alias} of {id}");
                }
                let (name, range) = parse_spec(alias, spec)?;
                self.validate_locked_edge(&name, &range, &node.deps[alias], &graph)?;
            }
            for (alias, spec) in &node.statement.manifest.peer_dependencies {
                if (node.statement.manifest.dependencies.contains_key(alias)
                    && !node
                        .statement
                        .manifest
                        .optional_dependencies
                        .contains_key(alias))
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
        validate_contextual_lock_graph(&graph)?;
        for release in policy_skipped {
            if let Some(id) = graph
                .nodes
                .iter()
                .find(|(_, node)| node.statement.id() == release)
                .map(|(id, _)| id.clone())
            {
                graph = without_failed_optional(&graph, &id)?;
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
    let release_id = statement.id();
    if statement.name != locked.name
        || statement.version != locked.version
        || (id != release_id && !id.starts_with(&format!("{release_id}__peers_")))
    {
        bail!("registry returned {release_id} for locked {id}");
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
    if statement.state != locked.state
        || statement.verdict() != locked.verdict
        || statement.provenance_status() != locked.provenance
        || statement
            .manifest
            .install_scripts
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            != locked.install_scripts
    {
        bail!("signed release metadata for {id} differs from rivet.lock");
    }
    Ok(())
}

pub(crate) fn validate_contextual_lock_graph(graph: &Graph) -> Result<()> {
    let expected = canonical_context_graph(graph)?;
    if graph.roots != expected.roots || graph.nodes.len() != expected.nodes.len() {
        bail!("frozen lock has forged peer context or root routing");
    }
    for (id, node) in &graph.nodes {
        let Some(canonical) = expected.nodes.get(id) else {
            bail!("frozen lock has noncanonical instance {id}");
        };
        if node.deps != canonical.deps
            || node.peer_bindings != canonical.peer_bindings
            || node.optional != canonical.optional
        {
            bail!("frozen lock has forged dependencies or peer bindings for {id}");
        }
    }
    Ok(())
}

pub(crate) fn without_failed_optional(graph: &Graph, failed: &str) -> Result<Graph> {
    let mut reduced = graph.clone();
    let node = reduced
        .nodes
        .get(failed)
        .with_context(|| format!("absent optional {failed}"))?;
    if !node.optional {
        bail!("{failed} is required and cannot be skipped");
    }
    let release = node.statement.id();
    let removed: BTreeSet<_> = reduced
        .nodes
        .iter()
        .filter(|(_, node)| node.statement.id() == release)
        .map(|(id, _)| id.clone())
        .collect();
    if removed.iter().any(|id| !reduced.nodes[id].optional) {
        bail!("optional script failed for {release}, which is required in another peer context");
    }
    reduced.nodes.retain(|id, _| !removed.contains(id));
    reduced
        .roots
        .retain(|_, root| !removed.contains(&root.package));
    for node in reduced.nodes.values_mut() {
        node.deps.retain(|_, child| !removed.contains(child));
        node.peer_bindings
            .retain(|_, child| !removed.contains(child));
    }
    prune_unlinked(&mut reduced);
    discard_broken_optional_branches(&mut reduced)?;
    canonical_context_graph(&reduced)
}

fn canonical_context_graph(graph: &Graph) -> Result<Graph> {
    let mut base = Graph {
        warnings: graph.warnings.clone(),
        notes: graph.notes.clone(),
        other_platforms: graph.other_platforms.clone(),
        ..Default::default()
    };
    for (alias, root) in &graph.roots {
        let node = graph
            .nodes
            .get(&root.package)
            .with_context(|| format!("absent root {}", root.package))?;
        base.roots.insert(
            alias.clone(),
            LockedRoot {
                spec: root.spec.clone(),
                package: node.statement.id(),
            },
        );
    }
    for node in graph.nodes.values() {
        let release_id = node.statement.id();
        let mut collapsed = node.clone();
        collapsed.deps = node
            .deps
            .iter()
            .map(|(alias, target)| {
                graph
                    .nodes
                    .get(target)
                    .map(|other| (alias.clone(), other.statement.id()))
                    .with_context(|| format!("absent locked edge {target}"))
            })
            .collect::<Result<_>>()?;
        collapsed.peer_bindings.clear();
        if let Some(previous) = base.nodes.get(&release_id) {
            let earlier: BTreeMap<_, _> = normal_children(previous)
                .map(|(alias, child)| (alias.clone(), child.clone()))
                .collect();
            let current: BTreeMap<_, _> = normal_children(&collapsed)
                .map(|(alias, child)| (alias.clone(), child.clone()))
                .collect();
            if earlier != current {
                bail!("frozen contexts choose inconsistent dependency releases for {release_id}");
            }
        } else {
            base.nodes.insert(release_id, collapsed);
        }
    }
    contextualize(&base)
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

fn mark_required(graph: &mut Graph) {
    let mut required = BTreeSet::new();
    let mut stack: Vec<String> = graph.roots.values().map(|r| r.package.clone()).collect();
    while let Some(id) = stack.pop() {
        if !required.insert(id.clone()) {
            continue;
        }
        if let Some(node) = graph.nodes.get(&id) {
            for (alias, child) in &node.deps {
                if (node.statement.manifest.dependencies.contains_key(alias)
                    && !node
                        .statement
                        .manifest
                        .optional_dependencies
                        .contains_key(alias))
                    || (node
                        .statement
                        .manifest
                        .peer_dependencies
                        .contains_key(alias)
                        && !node.statement.manifest.peer_optional.contains(alias)
                        && !node.statement.manifest.dependencies.contains_key(alias)
                        && !node
                            .statement
                            .manifest
                            .optional_dependencies
                            .contains_key(alias))
                {
                    stack.push(child.clone());
                }
            }
        }
    }
    for (id, node) in &mut graph.nodes {
        node.optional = !required.contains(id);
    }
}

/// A failed required descendant invalidates its optional ancestor. Repeat
/// until all remaining nodes have their required edges.
fn discard_broken_optional_branches(graph: &mut Graph) -> Result<()> {
    loop {
        mark_required(graph);
        let broken: Vec<_> = graph
            .nodes
            .iter()
            .filter_map(|(id, node)| {
                let missing = node
                    .statement
                    .manifest
                    .dependencies
                    .keys()
                    .filter(|alias| {
                        !node
                            .statement
                            .manifest
                            .optional_dependencies
                            .contains_key(*alias)
                    })
                    .chain(
                        node.statement
                            .manifest
                            .peer_dependencies
                            .keys()
                            .filter(|alias| {
                                !node.statement.manifest.peer_optional.contains(*alias)
                                    && !node.statement.manifest.dependencies.contains_key(*alias)
                                    && !node
                                        .statement
                                        .manifest
                                        .optional_dependencies
                                        .contains_key(*alias)
                            }),
                    )
                    .find(|alias| !node.deps.contains_key(*alias));
                missing.map(|alias| (id.clone(), alias.clone(), node.optional))
            })
            .collect();
        if broken.is_empty() {
            return Ok(());
        }
        for (id, alias, optional) in &broken {
            if !optional {
                bail!("required {id} has unresolved dependency {alias}");
            }
        }
        let removed: BTreeSet<_> = broken.into_iter().map(|(id, _, _)| id).collect();
        graph.nodes.retain(|id, _| !removed.contains(id));
        for node in graph.nodes.values_mut() {
            node.deps.retain(|_, dep| !removed.contains(dep));
        }
        prune_unlinked(graph);
    }
}

const MAX_CONTEXT_INSTANCES: usize = 4096;
const MAX_CONTEXT_DEPTH: usize = 64;

fn contextualize(base: &Graph) -> Result<Graph> {
    let mut root_scope: Scope = base
        .roots
        .iter()
        .map(|(alias, root)| {
            (
                alias.clone(),
                ProviderRef {
                    base: root.package.clone(),
                    scope_id: 0,
                },
            )
        })
        .collect();
    let root_ids: Vec<_> = base
        .roots
        .values()
        .map(|root| root.package.clone())
        .collect();
    root_scope = coherent_scope(base, root_scope, &root_ids, 0)?;
    let mut builder = ContextBuilder {
        base,
        graph: Graph {
            warnings: base.warnings.clone(),
            notes: base.notes.clone(),
            other_platforms: base.other_platforms.clone(),
            ..Default::default()
        },
        scopes: vec![root_scope],
        peer_relevance: compute_peer_relevance(base),
        peer_specs: compute_peer_specs(base),
    };
    for (alias, root) in &base.roots {
        let instance = builder.instance(&root.package, 0, 0)?;
        builder.graph.roots.insert(
            alias.clone(),
            LockedRoot {
                spec: root.spec.clone(),
                package: instance,
            },
        );
    }
    prune_unlinked(&mut builder.graph);
    mark_required(&mut builder.graph);
    Ok(builder.graph)
}

#[derive(Clone)]
struct ProviderRef {
    base: String,
    scope_id: usize,
}
type Scope = BTreeMap<String, ProviderRef>;

fn normal_children(node: &Node) -> impl Iterator<Item = (&String, &String)> {
    node.deps.iter().filter(|(alias, _)| {
        node.statement.manifest.dependencies.contains_key(*alias)
            || node
                .statement
                .manifest
                .optional_dependencies
                .contains_key(*alias)
    })
}

fn missing_coherent_candidates(base: &Graph) -> Result<BTreeSet<(String, String)>> {
    let mut groups: Vec<Vec<String>> = vec![base
        .roots
        .values()
        .map(|root| root.package.clone())
        .collect()];
    groups.extend(base.nodes.iter().map(|(id, node)| {
        std::iter::once(id.clone())
            .chain(normal_children(node).map(|(_, child)| child.clone()))
            .collect()
    }));
    let mut wanted = BTreeSet::new();
    for group in groups {
        let mut peers: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for id in group {
            let node = &base.nodes[&id];
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
                peers
                    .entry(alias.clone())
                    .or_default()
                    .push(parse_spec(alias, spec)?);
            }
        }
        for (alias, specs) in peers {
            if specs.len() < 2 {
                continue;
            }
            let name = &specs[0].0;
            if specs.iter().any(|(other, _)| other != name) {
                bail!("conflicting peer package names for {alias}");
            }
            if base.nodes.values().any(|node| {
                node.statement.name == *name
                    && specs.iter().all(|(_, range)| {
                        version_satisfies(range, &node.statement.version).unwrap_or(false)
                    })
            }) {
                continue;
            }
            let mut ranges = specs
                .iter()
                .map(|(_, range)| range.parse::<node_semver::Range>());
            let mut intersection = ranges.next().expect("multiple ranges")?;
            for range in ranges {
                let Some(next) = intersection.intersect(&range?) else {
                    bail!(
                        "no compatible version can satisfy peer {alias}: {}",
                        specs
                            .iter()
                            .map(|(_, spec)| spec.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                };
                intersection = next;
            }
            wanted.insert((name.clone(), intersection.to_string()));
        }
    }
    Ok(wanted)
}

fn provider_for(
    base: &Graph,
    scope: &Scope,
    alias: &str,
    name: &str,
) -> Result<Option<ProviderRef>> {
    if let Some(id) = scope.get(alias) {
        return Ok(Some(id.clone()));
    }
    let matches: Vec<_> = scope
        .values()
        .filter(|provider| {
            base.nodes
                .get(&provider.base)
                .is_some_and(|node| node.statement.name == name)
        })
        .collect();
    let Some(nearest) = matches.iter().map(|provider| provider.scope_id).max() else {
        return Ok(None);
    };
    let found: BTreeSet<_> = matches
        .into_iter()
        .filter(|provider| provider.scope_id == nearest)
        .map(|provider| provider.base.clone())
        .collect();
    if found.len() > 1 {
        bail!(
            "ambiguous providers for peer {name}: {}",
            found.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    let id = found.into_iter().next().expect("nonempty");
    Ok(scope
        .values()
        .find(|provider| provider.base == id && provider.scope_id == nearest)
        .cloned())
}

/// Select one provider for every peer requested by siblings in this context.
fn coherent_scope(
    base: &Graph,
    mut scope: Scope,
    children: &[String],
    scope_id: usize,
) -> Result<Scope> {
    let mut wanted: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for child in children {
        let node = base
            .nodes
            .get(child)
            .with_context(|| format!("absent release {child}"))?;
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
            let (name, range) = parse_spec(alias, spec)?;
            wanted.entry(alias.clone()).or_default().push((name, range));
        }
    }
    for (alias, specs) in wanted {
        let name = &specs[0].0;
        if specs.iter().any(|(other, _)| other != name) {
            bail!("conflicting peer package names for {alias}");
        }
        let provider = if let Some(provider) = provider_for(base, &scope, &alias, name)? {
            provider
        } else {
            let mut candidates: Vec<_> = base
                .nodes
                .iter()
                .filter(|(_, node)| node.statement.name == *name)
                .filter(|(_, node)| {
                    specs.iter().all(|(_, range)| {
                        version_satisfies(range, &node.statement.version).unwrap_or(false)
                    })
                })
                .map(|(id, _)| id.clone())
                .collect();
            candidates.sort();
            ProviderRef {
                base: candidates.into_iter().next().with_context(|| {
                    format!(
                        "no coherent provider for peer {alias}: {}",
                        specs
                            .iter()
                            .map(|(_, s)| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?,
                scope_id,
            }
        };
        let selected = &base.nodes[&provider.base].statement;
        if selected.name != *name
            || !specs
                .iter()
                .all(|(_, range)| version_satisfies(range, &selected.version).unwrap_or(false))
        {
            bail!(
                "incompatible provider {} for peer {alias}; required {}",
                selected.id(),
                specs
                    .iter()
                    .map(|(_, s)| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        scope.insert(alias, provider);
    }
    Ok(scope)
}

struct ContextBuilder<'a> {
    base: &'a Graph,
    graph: Graph,
    scopes: Vec<Scope>,
    peer_relevance: BTreeMap<String, bool>,
    peer_specs: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
}

fn compute_peer_specs(base: &Graph) -> BTreeMap<String, BTreeMap<String, BTreeSet<String>>> {
    let mut specs: BTreeMap<_, _> = base
        .nodes
        .iter()
        .map(|(id, node)| {
            (
                id.clone(),
                node.statement
                    .manifest
                    .peer_dependencies
                    .iter()
                    .filter(|(alias, _)| {
                        !node.statement.manifest.dependencies.contains_key(*alias)
                            && !node
                                .statement
                                .manifest
                                .optional_dependencies
                                .contains_key(*alias)
                    })
                    .map(|(alias, spec)| (alias.clone(), BTreeSet::from([spec.clone()])))
                    .collect::<BTreeMap<_, _>>(),
            )
        })
        .collect();
    loop {
        let mut changed = false;
        for (id, node) in &base.nodes {
            let mut merged = specs[id].clone();
            for (_, child) in normal_children(node) {
                for (alias, child_specs) in &specs[child] {
                    merged
                        .entry(alias.clone())
                        .or_default()
                        .extend(child_specs.iter().cloned());
                }
            }
            if merged != specs[id] {
                specs.insert(id.clone(), merged);
                changed = true;
            }
        }
        if !changed {
            return specs;
        }
    }
}

fn compute_peer_relevance(base: &Graph) -> BTreeMap<String, bool> {
    let mut relevant: BTreeMap<_, _> = base
        .nodes
        .iter()
        .map(|(id, node)| {
            let direct = node
                .statement
                .manifest
                .peer_dependencies
                .keys()
                .any(|alias| {
                    !node.statement.manifest.dependencies.contains_key(alias)
                        && !node
                            .statement
                            .manifest
                            .optional_dependencies
                            .contains_key(alias)
                });
            (id.clone(), direct)
        })
        .collect();
    loop {
        let mut changed = false;
        for (id, node) in &base.nodes {
            if relevant[id] {
                continue;
            }
            if normal_children(node).any(|(_, child)| relevant.get(child).copied().unwrap_or(false))
            {
                relevant.insert(id.clone(), true);
                changed = true;
            }
        }
        if !changed {
            return relevant;
        }
    }
}

impl ContextBuilder<'_> {
    fn has_peer_descendant(&self, id: &str) -> bool {
        self.peer_relevance.get(id).copied().unwrap_or(false)
    }

    fn make_scope(&mut self, base_id: &str, inherited_id: usize) -> Result<usize> {
        if self.scopes.len() >= MAX_CONTEXT_INSTANCES * 16 {
            bail!(
                "peer context expansion exceeded {} scopes; simplify shared or cyclic dependencies",
                MAX_CONTEXT_INSTANCES * 16
            );
        }
        let node = &self.base.nodes[base_id];
        let local_id = self.scopes.len();
        let mut scope = self.scopes[inherited_id].clone();
        scope.insert(
            node.statement.name.clone(),
            ProviderRef {
                base: base_id.into(),
                scope_id: inherited_id,
            },
        );
        for (alias, child) in normal_children(node) {
            scope.insert(
                alias.clone(),
                ProviderRef {
                    base: child.clone(),
                    scope_id: local_id,
                },
            );
        }
        let siblings: Vec<_> = std::iter::once(base_id.to_string())
            .chain(normal_children(node).map(|(_, child)| child.clone()))
            .collect();
        scope = coherent_scope(self.base, scope, &siblings, local_id)?;
        self.scopes.push(scope);
        Ok(local_id)
    }

    fn projection(
        &mut self,
        base_id: &str,
        inherited_id: usize,
        active: &mut BTreeSet<String>,
        depth: usize,
    ) -> Result<String> {
        if depth >= MAX_CONTEXT_DEPTH {
            bail!("peer context depth exceeds {MAX_CONTEXT_DEPTH}; shorten the dependency or peer chain");
        }
        if !self.has_peer_descendant(base_id) {
            return Ok(String::new());
        }
        if !active.insert(base_id.into()) {
            return Ok(format!("cycle:{base_id}"));
        }
        let local_id = self.make_scope(base_id, inherited_id)?;
        let mut projected = BTreeMap::new();
        let specs = self.peer_specs[base_id].clone();
        for (alias, requirements) in specs {
            for spec in requirements {
                let (name, _) = parse_spec(&alias, &spec)?;
                if let Some(provider) =
                    provider_for(self.base, &self.scopes[local_id], &alias, &name)?
                {
                    let origin =
                        self.projection(&provider.base, provider.scope_id, active, depth + 1)?;
                    projected.insert(
                        serde_json::to_string(&(alias.as_str(), spec.as_str()))?,
                        (provider.base, origin),
                    );
                }
            }
        }
        active.remove(base_id);
        Ok(serde_json::to_string(&projected)?)
    }

    fn signature(
        &mut self,
        base_id: &str,
        inherited_id: usize,
        seen: &mut BTreeSet<(String, String)>,
        out: &mut BTreeMap<String, String>,
        depth: usize,
    ) -> Result<()> {
        if depth >= MAX_CONTEXT_DEPTH {
            bail!("peer context depth exceeds {MAX_CONTEXT_DEPTH}; shorten the dependency or peer chain");
        }
        if !self.has_peer_descendant(base_id) {
            return Ok(());
        }
        let projection = self.projection(base_id, inherited_id, &mut BTreeSet::new(), depth + 1)?;
        if !seen.insert((base_id.into(), projection.clone())) {
            return Ok(());
        }
        let local_id = self.make_scope(base_id, inherited_id)?;
        let node = &self.base.nodes[base_id];
        let normal: Vec<_> = normal_children(node).map(|(_, d)| d.clone()).collect();
        let peers = node.statement.manifest.peer_dependencies.clone();
        let shadowed = node
            .statement
            .manifest
            .dependencies
            .keys()
            .chain(node.statement.manifest.optional_dependencies.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        for (alias, spec) in peers {
            if shadowed.contains(&alias) {
                continue;
            }
            let (name, _) = parse_spec(&alias, &spec)?;
            if let Some(provider) = provider_for(self.base, &self.scopes[local_id], &alias, &name)?
            {
                let provider_projection = self.projection(
                    &provider.base,
                    provider.scope_id,
                    &mut BTreeSet::new(),
                    depth + 1,
                )?;
                out.insert(
                    format!("{base_id}:{projection}:{alias}"),
                    format!("{}:{provider_projection}", provider.base),
                );
                self.signature(&provider.base, provider.scope_id, seen, out, depth + 1)?;
            }
        }
        for child in normal {
            self.signature(&child, local_id, seen, out, depth + 1)?;
        }
        Ok(())
    }

    fn instance(&mut self, base_id: &str, inherited_id: usize, depth: usize) -> Result<String> {
        if depth >= MAX_CONTEXT_DEPTH {
            bail!("peer context depth exceeds {MAX_CONTEXT_DEPTH}; shorten the dependency or peer chain");
        }
        let mut bindings = BTreeMap::new();
        if self.has_peer_descendant(base_id) {
            self.signature(
                base_id,
                inherited_id,
                &mut BTreeSet::new(),
                &mut bindings,
                depth + 1,
            )?;
        }
        let id = if bindings.is_empty() {
            base_id.to_string()
        } else {
            let bytes = serde_json::to_vec(&bindings)?;
            format!("{base_id}__peers_{}", hex::encode(Sha256::digest(bytes)))
        };
        if self.graph.nodes.contains_key(&id) {
            return Ok(id);
        }
        if self.graph.nodes.len() >= MAX_CONTEXT_INSTANCES {
            bail!("peer contexts exceed {MAX_CONTEXT_INSTANCES} instances; simplify cyclic peer dependencies");
        }
        let local_id = self.make_scope(base_id, inherited_id)?;
        let base_node = self
            .base
            .nodes
            .get(base_id)
            .with_context(|| format!("absent release {base_id}"))?;
        let mut node = base_node.clone();
        node.deps.clear();
        node.peer_bindings.clear();
        self.graph.nodes.insert(id.clone(), node);

        let normal: Vec<_> = normal_children(base_node)
            .map(|(a, d)| (a.clone(), d.clone()))
            .collect();
        let peers = base_node.statement.manifest.peer_dependencies.clone();
        let shadowed = base_node
            .statement
            .manifest
            .dependencies
            .keys()
            .chain(base_node.statement.manifest.optional_dependencies.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        let optional_peers = base_node.statement.manifest.peer_optional.clone();
        let mut deps = BTreeMap::new();
        for (alias, child) in normal {
            deps.insert(alias, self.instance(&child, local_id, depth + 1)?);
        }
        let mut peer_bindings = BTreeMap::new();
        for (alias, spec) in peers {
            if shadowed.contains(&alias) {
                continue;
            }
            let (name, range) = parse_spec(&alias, &spec)?;
            let Some(provider) = provider_for(self.base, &self.scopes[local_id], &alias, &name)?
            else {
                if optional_peers.contains(&alias) {
                    continue;
                }
                bail!("missing required peer {alias} for {base_id}");
            };
            let statement = &self.base.nodes[&provider.base].statement;
            if statement.name != name || !version_satisfies(&range, &statement.version)? {
                bail!(
                    "incompatible provider {} for peer {alias} of {base_id}; needs {range}",
                    statement.id()
                );
            }
            let provider_id = self.instance(&provider.base, provider.scope_id, depth + 1)?;
            deps.insert(alias.clone(), provider_id.clone());
            peer_bindings.insert(alias, provider_id);
        }
        let instance = self.graph.nodes.get_mut(&id).expect("inserted");
        instance.deps = deps;
        instance.peer_bindings = peer_bindings;
        Ok(id)
    }
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
                            peer_bindings: node.peer_bindings.clone(),
                            optional: node.optional,
                            install_scripts: s.manifest.install_scripts.keys().cloned().collect(),
                        },
                    )
                })
                .collect(),
            variants: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::attestation::tests::{sample_statement, seal, test_key};
    use crate::core::linker::tests::unsigned_node;
    use crate::CommonFlags;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        thread::JoinHandle,
        time::Duration,
    };

    struct MockRegistry {
        client: RegistryClient,
        key: TrustedKey,
        resolves: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl Drop for MockRegistry {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
        }
    }

    fn mock_registry(mut statements: Vec<Statement>) -> MockRegistry {
        let (signing, key) = test_key();
        let now = OffsetDateTime::now_utc();
        for statement in &mut statements {
            statement.issued_at = (now - time::Duration::hours(1))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            statement.expires_at = (now + time::Duration::days(7))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
        }
        let releases: BTreeMap<_, _> = statements.into_iter().map(|s| (s.id(), s)).collect();
        let envelopes: BTreeMap<_, _> = releases
            .iter()
            .map(|(id, s)| (id.clone(), seal(&signing, &key.keyid, s)))
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client =
            RegistryClient::new(&format!("http://{}", listener.local_addr().unwrap()), None)
                .unwrap();
        let resolves = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_resolves = resolves.clone();
        let worker_stop = stop.clone();
        let handle = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(err) => panic!("mock registry accept: {err}"),
                };
                // Accepted sockets may inherit nonblocking mode on some hosts.
                // HTTP clients can also open a connection without sending a request.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut chunk = [0u8; 4096];
                    let size = match stream.read(&mut chunk) {
                        Ok(size) => size,
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(err)
                            if bytes.is_empty()
                                && matches!(
                                    err.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                        {
                            break None;
                        }
                        Err(err) => panic!("mock registry request read: {err}"),
                    };
                    if size == 0 {
                        break None;
                    }
                    bytes.extend_from_slice(&chunk[..size]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(end + 4);
                    }
                };
                let Some(header_end) = header_end else {
                    continue;
                };
                let header = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse().ok())
                    })
                    .unwrap_or(0);
                while bytes.len() < header_end + length {
                    let mut chunk = [0u8; 4096];
                    let size = stream.read(&mut chunk).unwrap();
                    if size == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..size]);
                }
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes[header_end..]).unwrap_or_default();
                let first = header.lines().next().unwrap_or("");
                let response = if first.contains("/v1/npm/resolve") {
                    worker_resolves.fetch_add(1, Ordering::Relaxed);
                    let name = request["name"].as_str().unwrap();
                    let spec = request["spec"].as_str().unwrap();
                    let chosen = releases
                        .values()
                        .filter(|s| {
                            s.name == name && version_satisfies(spec, &s.version).unwrap_or(false)
                        })
                        .max_by(|a, b| a.version.cmp(&b.version));
                    match chosen {
                        Some(s) => serde_json::json!({"attestation": envelopes[&s.id()]}),
                        None => {
                            serde_json::json!({"error": format!("no version for {name}@{spec}")})
                        }
                    }
                } else if first.contains("/v1/attestations") {
                    let ids = request["packages"].as_array().unwrap();
                    let found: BTreeMap<_, _> = ids
                        .iter()
                        .filter_map(|item| {
                            let id =
                                format!("{}@{}", item["name"].as_str()?, item["version"].as_str()?);
                            envelopes.get(&id).map(|envelope| (id, envelope.clone()))
                        })
                        .collect();
                    serde_json::json!({"attestations": found, "errors": {}})
                } else {
                    serde_json::json!({"error":"unknown path"})
                };
                let data = response.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{data}", data.len()).unwrap();
            }
        });
        MockRegistry {
            client,
            key,
            resolves,
            stop,
            handle: Some(handle),
        }
    }

    fn base_graph(roots: &[(&str, &str)], statements: Vec<Statement>) -> Graph {
        Graph {
            roots: roots
                .iter()
                .map(|(alias, id)| {
                    (
                        alias.to_string(),
                        LockedRoot {
                            spec: "1.0.0".into(),
                            package: id.to_string(),
                        },
                    )
                })
                .collect(),
            nodes: statements
                .into_iter()
                .map(|s| (s.id(), unsigned_node(s)))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn signed_portable_variants_keep_native_optional_closures_and_frozen_never_resolves() {
        let mut app = sample_statement("app", "1.0.0");
        app.manifest.optional_dependencies.extend([
            ("native-darwin".into(), "^1".into()),
            ("native-linux".into(), "^1".into()),
        ]);
        // npm treats an optionalDependencies entry as overriding a same-named
        // dependencies entry, including during frozen edge validation.
        app.manifest
            .dependencies
            .insert("native-darwin".into(), "^2".into());
        let mut darwin = sample_statement("native-darwin", "1.0.0");
        darwin.manifest.os.push("darwin".into());
        darwin
            .manifest
            .dependencies
            .insert("helper".into(), "^1".into());
        let mut linux = sample_statement("native-linux", "1.0.0");
        linux.manifest.os.push("linux".into());
        linux
            .manifest
            .dependencies
            .insert("helper".into(), "^1".into());
        let fixture = mock_registry(vec![
            app,
            darwin,
            linux,
            sample_statement("helper", "1.0.0"),
        ]);
        let policy = Policy::new(None, &CommonFlags::default());
        let resolver = Resolver {
            client: &fixture.client,
            key: &fixture.key,
            policy: &policy,
            locked: None,
        };
        let lock = resolver
            .resolve_portable(&BTreeMap::from([("app".into(), "^1".into())]))
            .unwrap();
        assert!(lock.roots.is_empty() && lock.packages.is_empty());
        for target in ["darwin-arm64", "darwin-x64"] {
            let packages = &lock.variants[target].packages;
            assert!(packages.contains_key("native-darwin@1.0.0"));
            assert!(!packages.contains_key("native-linux@1.0.0"));
            assert!(packages.contains_key("helper@1.0.0"));
        }
        for target in ["linux-arm64", "linux-x64"] {
            let packages = &lock.variants[target].packages;
            assert!(packages.contains_key("native-linux@1.0.0"));
            assert!(!packages.contains_key("native-darwin@1.0.0"));
            assert!(packages.contains_key("helper@1.0.0"));
        }
        let before = fixture.resolves.load(Ordering::Relaxed);
        let selected = lock.selected(&target_key().unwrap()).unwrap();
        resolver.load_lockfile(&selected).unwrap();
        assert_eq!(fixture.resolves.load(Ordering::Relaxed), before);
        let mut forged = selected;
        forged.packages.remove("helper@1.0.0");
        assert!(resolver.load_lockfile(&forged).is_err());
    }

    #[test]
    fn signed_sibling_peers_resolve_combined_range_once() {
        let mut a = sample_statement("plugin-a", "1.0.0");
        a.manifest
            .peer_dependencies
            .insert("d".into(), "^1 || ^3".into());
        let mut b = sample_statement("plugin-b", "1.0.0");
        b.manifest
            .peer_dependencies
            .insert("d".into(), "^1 || ^2".into());
        let fixture = mock_registry(vec![
            a,
            b,
            sample_statement("d", "1.0.0"),
            sample_statement("d", "2.0.0"),
            sample_statement("d", "3.0.0"),
        ]);
        let policy = Policy::new(None, &CommonFlags::default());
        let resolver = Resolver {
            client: &fixture.client,
            key: &fixture.key,
            policy: &policy,
            locked: None,
        };
        let lock = resolver
            .resolve_portable(&BTreeMap::from([
                ("plugin-a".into(), "^1".into()),
                ("plugin-b".into(), "^1".into()),
            ]))
            .unwrap();
        let selected = lock.selected(&target_key().unwrap()).unwrap();
        let a_id = &selected.roots["plugin-a"].package;
        let b_id = &selected.roots["plugin-b"].package;
        assert_eq!(
            selected.packages[a_id].peer_bindings["d"],
            selected.packages[b_id].peer_bindings["d"]
        );
        assert_eq!(
            selected.packages[&selected.packages[a_id].peer_bindings["d"]].version,
            "1.0.0"
        );
        let before = fixture.resolves.load(Ordering::Relaxed);
        resolver.load_lockfile(&selected).unwrap();
        assert_eq!(fixture.resolves.load(Ordering::Relaxed), before);
    }

    #[test]
    fn signed_frozen_policy_prunes_each_refused_release_after_context_rekey() {
        let mut p = sample_statement("p", "1.0.0");
        p.manifest
            .optional_dependencies
            .insert("z".into(), "^1".into());
        let mut z = sample_statement("z", "1.0.0");
        z.manifest
            .optional_dependencies
            .insert("a".into(), "^1".into());
        let mut a = sample_statement("a", "1.0.0");
        a.manifest.peer_dependencies.insert("d".into(), "^1".into());
        let mut d = sample_statement("d", "1.0.0");
        for statement in [&mut p, &mut d] {
            statement.provenance = Some(super::super::attestation::Provenance {
                status: "verified".into(),
                ..Default::default()
            });
        }
        let fixture = mock_registry(vec![p, z, a, d]);
        let permissive = Policy::new(None, &CommonFlags::default());
        let creator = Resolver {
            client: &fixture.client,
            key: &fixture.key,
            policy: &permissive,
            locked: None,
        };
        let lock = creator
            .resolve_portable(&BTreeMap::from([
                ("p".into(), "^1".into()),
                ("d".into(), "^1".into()),
            ]))
            .unwrap();
        let selected = lock.selected(&target_key().unwrap()).unwrap();
        let strict = Policy::new(
            None,
            &CommonFlags {
                require_provenance: true,
                ..Default::default()
            },
        );
        let loader = Resolver {
            client: &fixture.client,
            key: &fixture.key,
            policy: &strict,
            locked: Some(&lock),
        };
        let projected = loader.load_lockfile(&selected).unwrap();
        assert!(!projected
            .nodes
            .values()
            .any(|n| n.statement.name == "a" || n.statement.name == "z"));
        validate_contextual_lock_graph(&projected).unwrap();
        let mut forged = selected;
        let a_id = forged
            .packages
            .iter()
            .find(|(_, p)| p.name == "a")
            .unwrap()
            .0
            .clone();
        forged
            .packages
            .get_mut(&a_id)
            .unwrap()
            .peer_bindings
            .clear();
        assert!(loader.load_lockfile(&forged).is_err());
    }

    #[test]
    fn provider_keeps_its_declaration_context() {
        let d1 = sample_statement("d", "1.0.0");
        let d2 = sample_statement("d", "2.0.0");
        let mut q = sample_statement("q", "1.0.0");
        q.manifest.peer_dependencies.insert("d".into(), "^1".into());
        let mut p = sample_statement("p", "1.0.0");
        p.manifest.peer_dependencies.insert("q".into(), "^1".into());
        p.manifest.dependencies.insert("d".into(), "^2".into());
        let mut base = base_graph(
            &[("d", "d@1.0.0"), ("q", "q@1.0.0"), ("p", "p@1.0.0")],
            vec![d1, d2, q, p],
        );
        base.nodes
            .get_mut("q@1.0.0")
            .unwrap()
            .deps
            .insert("d".into(), "d@1.0.0".into());
        base.nodes.get_mut("p@1.0.0").unwrap().deps.extend([
            ("q".into(), "q@1.0.0".into()),
            ("d".into(), "d@2.0.0".into()),
        ]);
        let graph = contextualize(&base).unwrap();
        let q_id = &graph.roots["q"].package;
        let p_id = &graph.roots["p"].package;
        assert_eq!(graph.nodes[p_id].peer_bindings["q"], *q_id);
        assert_eq!(graph.nodes[q_id].peer_bindings["d"], "d@1.0.0");
        assert_eq!(graph.nodes[p_id].deps["d"], "d@2.0.0");
        validate_contextual_lock_graph(&graph).unwrap();
    }

    #[test]
    fn nearest_alias_provider_preserves_distinct_context_instance() {
        let d1 = sample_statement("d", "1.0.0");
        let d2 = sample_statement("d", "2.0.0");
        let mut q = sample_statement("q", "1.0.0");
        q.manifest
            .peer_dependencies
            .insert("d".into(), "^1 || ^2".into());
        let mut r = sample_statement("r", "1.0.0");
        r.manifest.peer_dependencies.insert("q".into(), "^1".into());
        let mut p = sample_statement("p", "1.0.0");
        p.manifest.dependencies.extend([
            ("d".into(), "^2".into()),
            ("local".into(), "npm:q@^1".into()),
            ("r".into(), "^1".into()),
        ]);
        let mut base = base_graph(
            &[("ancestor", "q@1.0.0"), ("d", "d@1.0.0"), ("p", "p@1.0.0")],
            vec![d1, d2, q, r, p],
        );
        base.nodes
            .get_mut("q@1.0.0")
            .unwrap()
            .deps
            .insert("d".into(), "d@1.0.0".into());
        base.nodes
            .get_mut("r@1.0.0")
            .unwrap()
            .deps
            .insert("q".into(), "q@1.0.0".into());
        base.nodes.get_mut("p@1.0.0").unwrap().deps.extend([
            ("d".into(), "d@2.0.0".into()),
            ("local".into(), "q@1.0.0".into()),
            ("r".into(), "r@1.0.0".into()),
        ]);
        let graph = contextualize(&base).unwrap();
        let p_id = &graph.roots["p"].package;
        let local_q = &graph.nodes[p_id].deps["local"];
        let root_q = &graph.roots["ancestor"].package;
        assert_ne!(local_q, root_q);
        assert_eq!(graph.nodes[local_q].peer_bindings["d"], "d@2.0.0");
        let r_id = &graph.nodes[p_id].deps["r"];
        assert_eq!(&graph.nodes[r_id].peer_bindings["q"], local_q);
    }

    #[test]
    fn ordinary_dependency_cycle_stays_finite() {
        let mut a = sample_statement("a", "1.0.0");
        let mut b = sample_statement("b", "1.0.0");
        a.manifest.dependencies.insert("b".into(), "^1".into());
        b.manifest.dependencies.insert("a".into(), "^1".into());
        let mut base = base_graph(&[("a", "a@1.0.0")], vec![a, b]);
        base.nodes
            .get_mut("a@1.0.0")
            .unwrap()
            .deps
            .insert("b".into(), "b@1.0.0".into());
        base.nodes
            .get_mut("b@1.0.0")
            .unwrap()
            .deps
            .insert("a".into(), "a@1.0.0".into());
        assert_eq!(contextualize(&base).unwrap().nodes.len(), 2);
    }

    #[test]
    fn review_same_alias_different_packages_keeps_nested_wrapper_context() {
        let mut nodes = vec![
            sample_statement("qone", "1.0.0"),
            sample_statement("qtwo", "1.0.0"),
            sample_statement("qtwo", "2.0.0"),
        ];
        let mut la = sample_statement("leaf_a", "1.0.0");
        la.manifest
            .peer_dependencies
            .insert("x".into(), "npm:qone@*".into());
        let mut lb = sample_statement("leaf_b", "1.0.0");
        lb.manifest
            .peer_dependencies
            .insert("x".into(), "npm:qtwo@*".into());
        nodes.extend([la, lb]);
        let relations: Vec<(&str, Vec<(&str, &str)>)> = vec![
            ("wa", vec![("leaf_a", "leaf_a@1.0.0")]),
            ("wb", vec![("leaf_b", "leaf_b@1.0.0")]),
            ("w", vec![("wa", "wa@1.0.0"), ("wb", "wb@1.0.0")]),
            ("fixed", vec![("qtwo", "qtwo@1.0.0"), ("w", "w@1.0.0")]),
            ("variable", vec![("w", "w@1.0.0")]),
            (
                "r",
                vec![("fixed", "fixed@1.0.0"), ("variable", "variable@1.0.0")],
            ),
            ("host1", vec![("qtwo", "qtwo@1.0.0"), ("r", "r@1.0.0")]),
            ("host2", vec![("qtwo", "qtwo@2.0.0"), ("r", "r@1.0.0")]),
        ];
        for (name, deps) in &relations {
            let mut n = sample_statement(name, "1.0.0");
            for (alias, _) in deps {
                n.manifest.dependencies.insert((*alias).into(), "*".into());
            }
            nodes.push(n);
        }
        let mut base = base_graph(
            &[
                ("qone", "qone@1.0.0"),
                ("host1", "host1@1.0.0"),
                ("host2", "host2@1.0.0"),
            ],
            nodes,
        );
        for (name, deps) in relations {
            for (alias, id) in deps {
                base.nodes
                    .get_mut(&format!("{name}@1.0.0"))
                    .unwrap()
                    .deps
                    .insert(alias.into(), id.into());
            }
        }
        base.nodes
            .get_mut("leaf_a@1.0.0")
            .unwrap()
            .deps
            .insert("x".into(), "qone@1.0.0".into());
        base.nodes
            .get_mut("leaf_b@1.0.0")
            .unwrap()
            .deps
            .insert("x".into(), "qtwo@1.0.0".into());
        let graph = contextualize(&base).unwrap();
        let h1 = &graph.roots["host1"].package;
        let h2 = &graph.roots["host2"].package;
        let r1 = &graph.nodes[h1].deps["r"];
        let r2 = &graph.nodes[h2].deps["r"];
        assert_ne!(
            r1, r2,
            "R must retain different inherited qtwo contexts for variable branch"
        );
        let mut leaf = r2;
        for alias in ["variable", "w", "wb", "leaf_b"] {
            leaf = &graph.nodes[leaf].deps[alias];
        }
        assert_eq!(graph.nodes[leaf].peer_bindings["x"], "qtwo@2.0.0");
    }

    #[test]
    fn peer_free_diamond_does_not_expand_paths() {
        let depth = 18;
        let mut statements = Vec::new();
        for layer in 0..depth {
            for side in 0..2 {
                let name = format!("n{layer}_{side}");
                let mut statement = sample_statement(&name, "1.0.0");
                if layer + 1 < depth {
                    for next in 0..2 {
                        statement
                            .manifest
                            .dependencies
                            .insert(format!("n{}_{}", layer + 1, next), "^1".into());
                    }
                }
                statements.push(statement);
            }
        }
        let mut base = base_graph(&[("n0_0", "n0_0@1.0.0")], statements);
        for layer in 0..depth - 1 {
            for side in 0..2 {
                let node = base
                    .nodes
                    .get_mut(&format!("n{layer}_{side}@1.0.0"))
                    .unwrap();
                for next in 0..2 {
                    node.deps.insert(
                        format!("n{}_{}", layer + 1, next),
                        format!("n{}_{}@1.0.0", layer + 1, next),
                    );
                }
            }
        }
        assert_eq!(
            contextualize(&base).unwrap().nodes.len(),
            1 + (depth - 1) * 2
        );
    }

    #[test]
    fn deep_dependency_chain_returns_error_before_stack_overflow() {
        let depth = MAX_CONTEXT_DEPTH + 2;
        let mut statements = Vec::new();
        for index in 0..depth {
            let mut statement = sample_statement(&format!("chain{index}"), "1.0.0");
            if index + 1 < depth {
                statement
                    .manifest
                    .dependencies
                    .insert("next".into(), format!("npm:chain{}@^1", index + 1));
            }
            statements.push(statement);
        }
        let mut base = base_graph(&[("chain0", "chain0@1.0.0")], statements);
        for index in 0..depth - 1 {
            base.nodes
                .get_mut(&format!("chain{index}@1.0.0"))
                .unwrap()
                .deps
                .insert("next".into(), format!("chain{}@1.0.0", index + 1));
        }
        let error = contextualize(&base).unwrap_err().to_string();
        assert!(error.contains("context depth exceeds"), "{error}");
    }

    #[test]
    fn peerful_diamond_reuses_shared_contexts() {
        let depth = 14;
        let mut statements = vec![sample_statement("d", "1.0.0")];
        for layer in 0..depth {
            for side in 0..2 {
                let name = format!("m{layer}_{side}");
                let mut statement = sample_statement(&name, "1.0.0");
                if layer + 1 < depth {
                    for next in 0..2 {
                        statement
                            .manifest
                            .dependencies
                            .insert(format!("m{}_{}", layer + 1, next), "^1".into());
                    }
                } else {
                    statement
                        .manifest
                        .peer_dependencies
                        .insert("d".into(), "^1".into());
                }
                statements.push(statement);
            }
        }
        let mut base = base_graph(&[("m0_0", "m0_0@1.0.0"), ("d", "d@1.0.0")], statements);
        for layer in 0..depth {
            for side in 0..2 {
                let node = base
                    .nodes
                    .get_mut(&format!("m{layer}_{side}@1.0.0"))
                    .unwrap();
                if layer + 1 < depth {
                    for next in 0..2 {
                        node.deps.insert(
                            format!("m{}_{}", layer + 1, next),
                            format!("m{}_{}@1.0.0", layer + 1, next),
                        );
                    }
                } else {
                    node.deps.insert("d".into(), "d@1.0.0".into());
                }
            }
        }
        let graph = contextualize(&base).unwrap();
        assert_eq!(graph.nodes.len(), 2 + (depth - 1) * 2);
        validate_contextual_lock_graph(&graph).unwrap();
    }

    #[test]
    fn cyclic_wrapper_inherits_peer_relevance() {
        let mut a = sample_statement("a", "1.0.0");
        let mut b = sample_statement("b", "1.0.0");
        let mut c = sample_statement("c", "1.0.0");
        a.manifest
            .dependencies
            .extend([("b".into(), "^1".into()), ("c".into(), "^1".into())]);
        b.manifest.dependencies.insert("a".into(), "^1".into());
        c.manifest.peer_dependencies.insert("d".into(), "^1".into());
        let d = sample_statement("d", "1.0.0");
        let mut base = base_graph(&[("a", "a@1.0.0"), ("d", "d@1.0.0")], vec![a, b, c, d]);
        base.nodes.get_mut("a@1.0.0").unwrap().deps.extend([
            ("b".into(), "b@1.0.0".into()),
            ("c".into(), "c@1.0.0".into()),
        ]);
        base.nodes
            .get_mut("b@1.0.0")
            .unwrap()
            .deps
            .insert("a".into(), "a@1.0.0".into());
        base.nodes
            .get_mut("c@1.0.0")
            .unwrap()
            .deps
            .insert("d".into(), "d@1.0.0".into());
        assert!(compute_peer_relevance(&base)["b@1.0.0"]);
        assert!(contextualize(&base).is_ok());
    }

    #[test]
    fn incompatible_present_peer_errors() {
        let d1 = sample_statement("d", "1.0.0");
        let d2 = sample_statement("d", "2.0.0");
        let mut p = sample_statement("p", "1.0.0");
        p.manifest.peer_dependencies.insert("d".into(), "^2".into());
        let mut base = base_graph(&[("d", "d@1.0.0"), ("p", "p@1.0.0")], vec![d1, d2, p]);
        base.nodes
            .get_mut("p@1.0.0")
            .unwrap()
            .deps
            .insert("d".into(), "d@2.0.0".into());
        assert!(contextualize(&base)
            .unwrap_err()
            .to_string()
            .contains("incompatible provider"));
    }

    #[test]
    fn forged_peer_binding_fails_context_validation() {
        let d1 = sample_statement("d", "1.0.0");
        let d2 = sample_statement("d", "2.0.0");
        let mut q = sample_statement("q", "1.0.0");
        q.manifest
            .peer_dependencies
            .insert("d".into(), "^1 || ^2".into());
        let mut base = base_graph(&[("d", "d@1.0.0"), ("q", "q@1.0.0")], vec![d1, d2, q]);
        base.nodes
            .get_mut("q@1.0.0")
            .unwrap()
            .deps
            .insert("d".into(), "d@2.0.0".into());
        let mut graph = contextualize(&base).unwrap();
        let q_id = graph.roots["q"].package.clone();
        graph
            .nodes
            .get_mut(&q_id)
            .unwrap()
            .peer_bindings
            .insert("d".into(), "d@2.0.0".into());
        assert!(validate_contextual_lock_graph(&graph).is_err());
    }

    #[test]
    fn optional_peer_is_absent_without_provider() {
        let mut q = sample_statement("q", "1.0.0");
        q.manifest.peer_dependencies.insert("d".into(), "^1".into());
        q.manifest.peer_optional.push("d".into());
        let base = base_graph(&[("q", "q@1.0.0")], vec![q]);
        let graph = contextualize(&base).unwrap();
        assert!(graph.nodes[&graph.roots["q"].package]
            .peer_bindings
            .is_empty());
    }

    #[test]
    fn optional_failure_rekeys_parent_context() {
        let mut p = sample_statement("p", "1.0.0");
        p.manifest
            .optional_dependencies
            .insert("q".into(), "^1".into());
        let mut q = sample_statement("q", "1.0.0");
        q.manifest.peer_dependencies.insert("d".into(), "^1".into());
        let d = sample_statement("d", "1.0.0");
        let mut base = base_graph(&[("p", "p@1.0.0")], vec![p, q, d]);
        base.nodes
            .get_mut("p@1.0.0")
            .unwrap()
            .deps
            .insert("q".into(), "q@1.0.0".into());
        base.nodes
            .get_mut("q@1.0.0")
            .unwrap()
            .deps
            .insert("d".into(), "d@1.0.0".into());
        let graph = contextualize(&base).unwrap();
        let old_parent = graph.roots["p"].package.clone();
        let failed = graph.nodes[&old_parent].deps["q"].clone();
        let reduced = without_failed_optional(&graph, &failed).unwrap();
        assert_eq!(reduced.roots["p"].package, "p@1.0.0");
        assert_eq!(reduced.nodes.len(), 1);
        validate_contextual_lock_graph(&reduced).unwrap();
    }

    #[test]
    fn optional_failure_removes_release_across_peer_contexts() {
        let d1 = sample_statement("d", "1.0.0");
        let d2 = sample_statement("d", "2.0.0");
        let mut q = sample_statement("q", "1.0.0");
        q.manifest
            .peer_dependencies
            .insert("d".into(), "^1 || ^2".into());
        let mut p = sample_statement("p", "1.0.0");
        p.manifest
            .optional_dependencies
            .insert("q".into(), "^1".into());
        let mut h1 = sample_statement("h1", "1.0.0");
        h1.manifest
            .dependencies
            .extend([("d".into(), "^1".into()), ("p".into(), "^1".into())]);
        let mut h2 = sample_statement("h2", "1.0.0");
        h2.manifest
            .dependencies
            .extend([("d".into(), "^2".into()), ("p".into(), "^1".into())]);
        let mut base = base_graph(
            &[("h1", "h1@1.0.0"), ("h2", "h2@1.0.0")],
            vec![d1, d2, q, p, h1, h2],
        );
        base.nodes
            .get_mut("q@1.0.0")
            .unwrap()
            .deps
            .insert("d".into(), "d@1.0.0".into());
        base.nodes
            .get_mut("p@1.0.0")
            .unwrap()
            .deps
            .insert("q".into(), "q@1.0.0".into());
        base.nodes.get_mut("h1@1.0.0").unwrap().deps.extend([
            ("d".into(), "d@1.0.0".into()),
            ("p".into(), "p@1.0.0".into()),
        ]);
        base.nodes.get_mut("h2@1.0.0").unwrap().deps.extend([
            ("d".into(), "d@2.0.0".into()),
            ("p".into(), "p@1.0.0".into()),
        ]);
        let graph = contextualize(&base).unwrap();
        let p1 = &graph.nodes[&graph.roots["h1"].package].deps["p"];
        let p2 = &graph.nodes[&graph.roots["h2"].package].deps["p"];
        assert_ne!(p1, p2);
        let reduced = without_failed_optional(&graph, &graph.nodes[p1].deps["q"]).unwrap();
        assert_eq!(
            reduced
                .nodes
                .values()
                .filter(|n| n.statement.name == "q")
                .count(),
            0
        );
        validate_contextual_lock_graph(&reduced).unwrap();
    }

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
