//! Verification of an installed node_modules tree before package code runs.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};

use super::{
    attestation::{Statement, TrustedKey},
    linker::{
        modules_dir, package_path, relative_path, validate_command, validate_entry, InstalledState,
        STATE_FILE,
    },
    policy::Policy,
    registry_client::RegistryClient,
    resolver::{package_scope, parse_spec, validate_package_name, version_satisfies},
    store::{safe_id, LocalStore},
    tree,
};

fn plain_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        bail!("installed directory was replaced: {}", path.display());
    }
    Ok(())
}

fn exact_link(link: &Path, target: &Path) -> Result<()> {
    if !fs::symlink_metadata(link)?.file_type().is_symlink() {
        bail!("dependency link was replaced: {}", link.display());
    }
    let expected = relative_path(target, link.parent().context("link has no parent")?);
    if fs::read_link(link)? != expected {
        bail!("dependency link changed: {}", link.display());
    }
    Ok(())
}

fn validate_installed_links(root: &Path, state: &InstalledState) -> Result<()> {
    let modules = modules_dir(root);
    let virtual_dir = modules.join(".rivet");
    plain_dir(&modules)?;
    plain_dir(&virtual_dir)?;
    let canonical_root = root.canonicalize()?;
    for ancestor in canonical_root.ancestors().skip(1) {
        let outside_modules = ancestor.join("node_modules");
        if outside_modules.exists() {
            bail!(
                "Node could resolve unverified ancestor modules at {}",
                outside_modules.display()
            );
        }
    }
    let expected_slots: BTreeSet<String> =
        state.lock.packages.keys().map(|id| safe_id(id)).collect();
    for entry in fs::read_dir(&virtual_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != STATE_FILE && !expected_slots.contains(&name) {
            bail!("unverified virtual-store entry {}", entry.path().display());
        }
    }
    for (id, package) in &state.lock.packages {
        validate_package_name(&package.name)?;
        let slot = virtual_dir.join(safe_id(id));
        let deps_dir = slot.join("node_modules");
        plain_dir(&slot)?;
        plain_dir(&deps_dir)?;
        let own = package_path(root, id, &package.name);
        if let Some(scope) = package_scope(&package.name) {
            plain_dir(&deps_dir.join(scope))?;
        }
        plain_dir(&own)?;
        for (alias, dep) in &package.dependencies {
            validate_package_name(alias)?;
            let target = state
                .lock
                .packages
                .get(dep)
                .with_context(|| format!("missing locked dependency {dep}"))?;
            let link = deps_dir.join(alias);
            if let Some(scope) = package_scope(alias) {
                plain_dir(&deps_dir.join(scope))?;
            }
            exact_link(&link, &package_path(root, dep, &target.name))?;
        }
        // Do not let Node resolve undeclared sibling packages.
        for entry in walkdir::WalkDir::new(&deps_dir)
            .min_depth(1)
            .max_depth(2)
            .follow_links(false)
        {
            let entry = entry?;
            let relative = entry
                .path()
                .strip_prefix(&deps_dir)?
                .to_str()
                .context("non-utf8 dependency link")?;
            if !allowed_layout_entry(relative, &package.name, package.dependencies.keys()) {
                bail!("undeclared dependency entry {}", entry.path().display());
            }
        }
    }
    for (alias, locked) in &state.lock.roots {
        validate_package_name(alias)?;
        let package = state
            .lock
            .packages
            .get(&locked.package)
            .context("root package absent")?;
        if let Some(scope) = package_scope(alias) {
            plain_dir(&modules.join(scope))?;
        }
        exact_link(
            &modules.join(alias),
            &package_path(root, &locked.package, &package.name),
        )?;
    }
    for entry in walkdir::WalkDir::new(&modules)
        .min_depth(1)
        .max_depth(2)
        .follow_links(false)
    {
        let entry = entry?;
        let relative = entry
            .path()
            .strip_prefix(&modules)?
            .to_str()
            .context("non-utf8 root module entry")?;
        if relative == ".rivet"
            || relative.starts_with(".rivet/")
            || relative == ".bin"
            || relative.starts_with(".bin/")
        {
            continue;
        }
        if !allowed_layout_entry(relative, "", state.lock.roots.keys()) {
            bail!("undeclared root module entry {}", entry.path().display());
        }
    }
    Ok(())
}

fn allowed_layout_entry<'a>(
    relative: &str,
    own: &str,
    aliases: impl Iterator<Item = &'a String>,
) -> bool {
    relative == own
        || (!own.is_empty() && relative.starts_with(&format!("{own}/")))
        || (!own.is_empty() && own.starts_with(&format!("{relative}/")))
        || aliases
            .into_iter()
            .any(|alias| alias == relative || alias.starts_with(&format!("{relative}/")))
}

/// Re-establishes trust in an installed tree before running it: the local
/// state must match the protected receipt, every link must match the signed
/// graph, every package needs a fresh (or, offline, unexpired cached) signed
/// statement, and every package directory is re-hashed. All installed
/// packages are checked, not just the command's closure, because Node can
/// resolve sibling roots through the top-level node_modules.
pub struct Verifier<'a> {
    pub store: &'a LocalStore,
    pub client: &'a RegistryClient,
    pub key: &'a TrustedKey,
    pub policy: &'a Policy,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub warnings: Vec<String>,
    pub online: bool,
    pub statements: BTreeMap<String, Statement>,
    pub timings: VerifyTimings,
}

/// Verification time in milliseconds. `other_ms` includes attestation
/// verification, cache writes, policy and graph checks, and rounding.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct VerifyTimings {
    pub total_ms: u128,
    pub layout_ms: u128,
    pub fetch_ms: u128,
    pub hash_ms: u128,
    pub other_ms: u128,
}

#[derive(Default)]
struct VerifyDurations {
    layout: Duration,
    fetch: Duration,
    hash: Duration,
}

impl VerifyDurations {
    fn record_hash(&mut self, elapsed: Duration) {
        self.hash += elapsed;
    }

    fn finish(self, total: Duration) -> VerifyTimings {
        let total_ms = total.as_millis();
        let layout_ms = self.layout.as_millis();
        let fetch_ms = self.fetch.as_millis();
        let hash_ms = self.hash.as_millis();
        VerifyTimings {
            total_ms,
            layout_ms,
            fetch_ms,
            hash_ms,
            other_ms: total_ms.saturating_sub(layout_ms + fetch_ms + hash_ms),
        }
    }
}

impl Verifier<'_> {
    pub fn verify(&self, root: &Path, state: &InstalledState) -> Result<VerifyReport> {
        let started = Instant::now();
        let receipt = self
            .store
            .read_install_receipt(root, self.key)?
            .context("installed tree has no trusted receipt; reinstall")?;
        if &receipt != state {
            bail!("installed state differs from trusted install receipt; reinstall");
        }
        validate_installed_links(root, state)?;
        let mut timings = VerifyDurations {
            layout: started.elapsed(),
            ..VerifyDurations::default()
        };
        // Node's ordinary resolution can find sibling top-level roots even
        // when the chosen bin did not declare them as dependencies.
        let ids: BTreeSet<String> = state.lock.packages.keys().cloned().collect();
        let now = time::OffsetDateTime::now_utc();
        let mut report = VerifyReport::default();
        let wanted: Vec<(String, String)> = ids
            .iter()
            .filter_map(|id| state.lock.packages.get(id))
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        let fetch_started = Instant::now();
        let fresh = match self.client.attestations(&wanted) {
            Ok(batch) => {
                report.online = true;
                Some(batch)
            }
            Err(err) => {
                report.warnings.push(format!(
                    "registry unreachable ({err:#}); using cached attestations"
                ));
                None
            }
        };
        timings.fetch = fetch_started.elapsed();
        for id in &ids {
            let locked = state
                .lock
                .packages
                .get(id)
                .with_context(|| format!("{id} is not in the installed graph"))?;
            let statement = match fresh.as_ref().and_then(|b| b.attestations.get(id)) {
                Some(envelope) => {
                    let statement = envelope.verify(self.key, now)?;
                    self.store
                        .cache_attestation(&statement, envelope, self.key)?;
                    statement
                }
                None => {
                    if let Some(err) = fresh.as_ref().and_then(|b| b.errors.get(id)) {
                        bail!("registry no longer serves {id}: {err}");
                    }
                    let (_, envelope) = self
                        .store
                        .cached_attestation(&locked.name, &locked.version, self.key)?
                        .with_context(|| {
                            format!("no cached attestation for {id}; reconnect to the registry")
                        })?;
                    envelope.verify(self.key, now)?
                }
            };
            if statement.id() != *id
                || statement.artifact.hash != locked.artifact
                || statement.artifact.tree_digest != locked.tree_digest
            {
                bail!("signed identity of {id} no longer matches what is installed; reinstall");
            }
            report.warnings.extend(self.policy.check(&statement, true)?);
            let dir = package_path(root, id, &locked.name);
            let expected = state
                .script_modified
                .get(id)
                .cloned()
                .unwrap_or_else(|| locked.tree_digest.clone());
            let hash_started = Instant::now();
            let actual = tree::tree_digest_of_dir(&dir)
                .with_context(|| format!("hash installed files of {id}"))?;
            timings.record_hash(hash_started.elapsed());
            if actual != expected {
                bail!(
                    "installed files of {id} were modified after install ({}); run `rivet install` to restore them",
                    dir.display()
                );
            }
            report.statements.insert(id.clone(), statement);
        }
        for (command, target) in &state.bins {
            if !ids.contains(&target.package) {
                continue;
            }
            validate_command(command)?;
            validate_entry(&target.entry)?;
            let statement = report
                .statements
                .get(&target.package)
                .context("bin package was not verified")?;
            let declared = statement
                .manifest
                .bin
                .get(command)
                .context("bin command absent from signed manifest")?;
            if declared.trim_start_matches("./") != target.entry {
                bail!("bin {command} does not match signed executable entry");
            }
            if !statement
                .executables
                .iter()
                .any(|e| e.command == *command && e.entry.trim_start_matches("./") == target.entry)
            {
                bail!("bin {command} is absent from signed executable metadata");
            }
        }
        for id in &ids {
            let statement = report
                .statements
                .get(id)
                .context("signed closure is incomplete")?;
            let locked = state
                .lock
                .packages
                .get(id)
                .context("locked closure is incomplete")?;
            if state.script_modified.contains_key(id)
                && statement.manifest.install_scripts.is_empty()
            {
                bail!("modified package {id} has no signed install script authorization");
            }
            for (alias, dep) in &locked.dependencies {
                let spec = statement
                    .manifest
                    .dependency_spec(alias)
                    .with_context(|| format!("installed edge {id} -> {alias} is not signed"))?;
                let (name, range) = parse_spec(alias, spec)?;
                let signed_dep = report.statements.get(dep).with_context(|| {
                    format!("installed edge {id} -> {alias} leaves verified closure")
                })?;
                if signed_dep.name != name || !version_satisfies(&range, &signed_dep.version)? {
                    bail!("installed edge {id} -> {alias} differs from signed dependency");
                }
            }
            for alias in statement.manifest.dependencies.keys() {
                if !locked.dependencies.contains_key(alias) {
                    bail!("installed graph omits signed required dependency {alias} of {id}");
                }
            }
        }
        report.timings = timings.finish(started.elapsed());
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::core::{
        attestation::tests::{sample_statement, seal},
        linker::{
            read_state, state_path,
            tests::{fixture_graph, serve_once, unsigned_node, Fixture},
        },
        lockfile::LockedRoot,
    };
    use crate::CommonFlags;

    fn verifier<'a>(fx: &'a Fixture, client: &'a RegistryClient) -> Verifier<'a> {
        Verifier {
            store: &fx.store,
            client,
            key: &fx.key,
            policy: &fx.policy,
        }
    }

    #[test]
    fn hash_timing_accumulates_submillisecond_packages_before_rounding() {
        let mut timings = VerifyDurations::default();
        for _ in 0..4 {
            timings.record_hash(Duration::from_micros(300));
        }
        let report = timings.finish(Duration::from_micros(1500));
        assert_eq!(report.hash_ms, 1);
        assert_eq!(report.other_ms, 0);
    }

    fn attestations_body(fx: &Fixture, statements: &[&Statement]) -> String {
        let attestations: serde_json::Map<String, serde_json::Value> = statements
            .iter()
            .map(|s| {
                (
                    s.id(),
                    serde_json::to_value(seal(&fx.signing, &fx.key.keyid, s)).unwrap(),
                )
            })
            .collect();
        serde_json::json!({ "attestations": attestations }).to_string()
    }

    #[test]
    fn changed_dependency_link_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("node_modules");
        fs::create_dir_all(parent.join("actual")).unwrap();
        fs::create_dir_all(parent.join("attacker")).unwrap();
        let link = parent.join("dependency");
        symlink("attacker", &link).unwrap();
        assert!(exact_link(&link, &parent.join("actual")).is_err());
    }

    #[test]
    fn rejects_state_and_link_tampering_before_execution() {
        for mutation in ["bin", "graph", "script_digest", "link"] {
            let fx = Fixture::new(CommonFlags::default());
            let client = fx.offline_client();
            fx.linker(&client, false)
                .link(
                    &fx.project,
                    &fixture_graph(&fx.store, 'a', None),
                    &fx.store.registry,
                )
                .unwrap();
            let mut state = read_state(&fx.project).unwrap().unwrap();
            let package = package_path(&fx.project, "demo@1.0.0", "demo");
            match mutation {
                "bin" => state.bins.get_mut("demo").unwrap().entry = "bin/other.js".into(),
                "graph" => {
                    state
                        .lock
                        .packages
                        .get_mut("demo@1.0.0")
                        .unwrap()
                        .dependencies
                        .insert("other".into(), "demo@1.0.0".into());
                }
                "script_digest" => {
                    fs::write(package.join("bin/demo.js"), "console.log('changed')\n").unwrap();
                    state.script_modified.insert(
                        "demo@1.0.0".into(),
                        tree::tree_digest_of_dir(&package).unwrap(),
                    );
                }
                "link" => {
                    let link = fx.project.join("node_modules/demo");
                    fs::remove_file(&link).unwrap();
                    symlink(".rivet/attacker", link).unwrap();
                }
                _ => unreachable!(),
            }
            if mutation != "link" {
                fs::write(state_path(&fx.project), serde_json::to_vec(&state).unwrap()).unwrap();
            }
            let error = verifier(&fx, &client)
                .verify(&fx.project, &state)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("receipt") || error.contains("link"),
                "{mutation}: {error}"
            );
        }
    }

    #[test]
    fn rejects_replayed_active_attestation_after_revocation() {
        for same_time in [false, true] {
            let fx = Fixture::new(CommonFlags::default());
            let graph = fixture_graph(&fx.store, 'a', None);
            let active = graph.nodes["demo@1.0.0"].statement.clone();
            let (client, server) = serve_once(attestations_body(&fx, &[&active]));
            fx.linker(&client, false)
                .link(&fx.project, &graph, &fx.store.registry)
                .unwrap();
            let mut revoked = active.clone();
            revoked.state = "revoked".into();
            if !same_time {
                revoked.issued_at = "2026-09-26T00:00:00Z".into();
            }
            fx.store
                .cache_attestation(
                    &revoked,
                    &seal(&fx.signing, &fx.key.keyid, &revoked),
                    &fx.key,
                )
                .unwrap();
            let state = read_state(&fx.project).unwrap().unwrap();
            let error = verifier(&fx, &client)
                .verify(&fx.project, &state)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("rollback") || error.contains("conflicting"),
                "{error}"
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn accepts_unchanged_installed_package_and_links() {
        let fx = Fixture::new(CommonFlags::default());
        let graph = fixture_graph(&fx.store, 'a', None);
        let (client, server) = serve_once(attestations_body(
            &fx,
            &[&graph.nodes["demo@1.0.0"].statement],
        ));
        fx.linker(&client, false)
            .link(&fx.project, &graph, &fx.store.registry)
            .unwrap();
        let state = read_state(&fx.project).unwrap().unwrap();
        let report = verifier(&fx, &client).verify(&fx.project, &state).unwrap();
        assert!(report.statements.contains_key("demo@1.0.0"));
        server.join().unwrap();
    }

    #[test]
    fn rehashes_sibling_root_outside_the_commands_closure() {
        let fx = Fixture::new(CommonFlags::default());
        let client = fx.offline_client();
        let mut graph = fixture_graph(&fx.store, 'a', None);
        let mut sibling = sample_statement("sibling", "1.0.0");
        sibling.artifact.hash = format!("sha512-{}", "b".repeat(128));
        let sibling_dir = fx.store.package_dir(&sibling.artifact.hash).unwrap();
        fs::create_dir_all(&sibling_dir).unwrap();
        fs::write(sibling_dir.join("index.js"), "module.exports = 'safe';\n").unwrap();
        sibling.artifact.tree_digest = tree::tree_digest_of_dir(&sibling_dir).unwrap();
        graph.roots.insert(
            "sibling".into(),
            LockedRoot {
                spec: "1.0.0".into(),
                package: sibling.id(),
            },
        );
        graph.nodes.insert(sibling.id(), unsigned_node(sibling));
        fx.linker(&client, false)
            .link(&fx.project, &graph, &fx.store.registry)
            .unwrap();
        for node in graph.nodes.values() {
            let signed = seal(&fx.signing, &fx.key.keyid, &node.statement);
            fx.store
                .cache_attestation(&node.statement, &signed, &fx.key)
                .unwrap();
        }
        fs::write(
            package_path(&fx.project, "sibling@1.0.0", "sibling").join("index.js"),
            "module.exports = 'tampered';\n",
        )
        .unwrap();
        let state = read_state(&fx.project).unwrap().unwrap();
        let error = verifier(&fx, &client)
            .verify(&fx.project, &state)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("sibling@1.0.0") && error.contains("modified"),
            "{error}"
        );
    }
}
