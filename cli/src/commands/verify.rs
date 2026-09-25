use anyhow::{bail, Result};
use serde_json::json;

use crate::commands::{import::describe, inspect::find_statement_with_freshness, run::locate};
use crate::core::{
    installed::Verifier,
    linker,
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
    let project_state = linker::read_state(&std::env::current_dir()?)?;
    let imported_command = match session.store.read_command(&target) {
        Ok(command) => Some(command),
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            None
        }
        Err(err) => return Err(err),
    };
    let is_project_bin = project_state
        .as_ref()
        .is_some_and(|state| state.bins.contains_key(&target));
    let located = if is_project_bin || imported_command.is_some() {
        Some(locate(None, &target, &session)?)
    } else {
        None
    };
    if reaudit && !(flags.dry_run || flags.plan) {
        let (name, version) = located
            .as_ref()
            .map(|located| split_name_version(&located.target.package))
            .unwrap_or_else(|| split_name_version(&target));
        let Some(version) = version else {
            bail!("--reaudit needs name@version or an imported command");
        };
        session.client.trigger_audit(&name, &version)?;
    }
    let lookup = located
        .as_ref()
        .map(|located| located.target.package.as_str())
        .unwrap_or(&target);
    let Some(statement) = find_statement_with_freshness(&session, lookup, true)? else {
        bail!("{target} is not in the Rivet registry");
    };
    let mut lines = describe(&statement);
    let mut installed = json!(null);
    if let Some(located) = located {
        let policy = Policy::new(
            located.manifest.as_ref().and_then(|m| m.policy.as_ref()),
            &flags,
        );
        let report = Verifier {
            store: &session.store,
            client: &session.client,
            key: &session.key,
            policy: &policy,
        }
        .verify(&located.root, &located.state)?;
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
