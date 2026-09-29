use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::commands::{import::describe, inspect::find_statement_with_freshness, run::locate};
use crate::core::{
    installed::Verifier,
    linker,
    manifest::Manifest,
    output::{emit_many, Event},
    policy::Policy,
    resolver::split_name_version,
    session::Session,
};
use crate::CommonFlags;

/// Re-checks a package: optionally asks the registry to re-audit it, fetches
/// a fresh signed statement, and (for installed commands) re-hashes every
/// installed file reachable from the project module resolution path.
pub fn run(target: String, reaudit: bool, flags: CommonFlags) -> Result<()> {
    let session = Session::open()?;
    let project_root = std::env::current_dir()?;
    let project_state = linker::read_state(&project_root)?;
    let is_project_bin = project_state
        .as_ref()
        .is_some_and(|state| state.bins.contains_key(&target));
    // A signed release may have several peer-context IDs. Any one matching
    // installed instance selects the release; Verifier checks all instances.
    let project_package = project_state.as_ref().and_then(|state| {
        let id = state
            .lock
            .roots
            .get(&target)
            .map(|root| &root.package)
            .or_else(|| state.lock.packages.contains_key(&target).then_some(&target))
            .or_else(|| {
                state
                    .lock
                    .packages
                    .iter()
                    .find(|(_, package)| format!("{}@{}", package.name, package.version) == target)
                    .map(|(id, _)| id)
            })?;
        state.lock.packages.get(id)
    });
    let imported_command = if is_project_bin || project_package.is_some() {
        None
    } else {
        match session.store.read_command(&target) {
            Ok(command) => Some(command),
            Err(err)
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(err) => return Err(err),
        }
    };
    let located = if is_project_bin || imported_command.is_some() {
        Some(locate(None, &target, &session)?)
    } else {
        None
    };
    let project_manifest = if project_package.is_some() && located.is_none() {
        let path = project_root.join("rivet.toml");
        if path.exists() {
            Some(Manifest::read_from(&path).with_context(|| format!("read {}", path.display()))?)
        } else {
            None
        }
    } else {
        None
    };
    if reaudit && !(flags.dry_run || flags.plan) {
        let (name, version) = located
            .as_ref()
            .and_then(|located| {
                located
                    .state
                    .lock
                    .packages
                    .get(&located.target.package)
                    .map(|p| (p.name.clone(), Some(p.version.clone())))
            })
            .or_else(|| {
                project_package.map(|package| (package.name.clone(), Some(package.version.clone())))
            })
            .unwrap_or_else(|| split_name_version(&target));
        let Some(version) = version else {
            bail!("--reaudit needs name@version or an imported command");
        };
        session.client.trigger_audit(&name, &version)?;
    }
    let lookup = located
        .as_ref()
        .and_then(|located| {
            located
                .state
                .lock
                .packages
                .get(&located.target.package)
                .map(|p| format!("{}@{}", p.name, p.version))
        })
        .or_else(|| project_package.map(|p| format!("{}@{}", p.name, p.version)))
        .unwrap_or_else(|| target.clone());
    let Some(statement) = find_statement_with_freshness(&session, &lookup, true)? else {
        bail!("{target} is not in the Rivet registry");
    };
    let mut lines = describe(&statement);
    let mut installed = json!(null);
    let installed_target = located
        .as_ref()
        .map(|located| {
            (
                located.root.as_path(),
                &located.state,
                located.manifest.as_ref(),
            )
        })
        .or_else(|| {
            project_package.map(|_| {
                (
                    project_root.as_path(),
                    project_state.as_ref().expect("project package has state"),
                    project_manifest.as_ref(),
                )
            })
        });
    if let Some((root, state, manifest)) = installed_target {
        let policy = Policy::new(manifest.and_then(|m| m.policy.as_ref()), &flags);
        let report = Verifier {
            store: &session.store,
            client: &session.client,
            key: &session.key,
            policy: &policy,
        }
        .verify(root, state)?;
        let ids: Vec<&String> = report.statements.keys().collect();
        lines.push(format!(
            "Installed files and links: {} packages verified",
            ids.len()
        ));
        for warning in &report.warnings {
            lines.push(format!("Warning: {warning}"));
        }
        installed = json!({"packages": ids, "warnings": report.warnings});
    } else {
        lines.push(
            "Verified fresh signed statement; no installed command matched this target".into(),
        );
    }
    emit_many(
        flags.output_mode(),
        "Rivet Verify",
        lines,
        vec![Event::new("audit.completed")
            .with("package", statement.id())
            .with("verdict", statement.verdict())],
        json!({"statement": statement, "installed": installed}),
    )
}
