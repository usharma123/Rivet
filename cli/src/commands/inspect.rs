use anyhow::{Context, Result};
use serde_json::json;
use time::OffsetDateTime;

use crate::commands::import::describe;
use crate::core::{
    attestation::Statement,
    output::{emit, Event},
    resolver::split_name_version,
    risk::namesquat,
    session::Session,
};
use crate::CommonFlags;

pub fn run(target: String, flags: CommonFlags) -> Result<()> {
    let session = Session::open()?;
    match find_statement(&session, &target)? {
        Some(statement) => {
            let mut lines = describe(&statement);
            lines.push(format!(
                "Dependencies: {}",
                statement.manifest.dependencies.len()
            ));
            for executable in &statement.executables {
                lines.push(format!(
                    "Executable: {} -> {} permissions {}",
                    executable.command,
                    executable.entry,
                    executable.permissions.clone().unwrap_or_else(|| json!({}))
                ));
            }
            emit(
                flags.output_mode(),
                "Rivet Inspect",
                lines,
                Event::new("risk.detected")
                    .with("name", statement.name.clone())
                    .with("verdict", statement.verdict()),
                json!({"found": true, "statement": statement}),
            )
        }
        None => {
            let (name, _) = split_name_version(&target);
            let squat = namesquat(&name);
            let mut lines = vec![
                format!("Package: {target}"),
                "State: not in the Rivet registry".to_string(),
            ];
            if let Some(squat) = &squat {
                lines.push(format!(
                    "Warning: possible namesquat of {}",
                    squat.confusable_with
                ));
                lines.push(
                    "Recommendation: do not install unless you meant this exact package.".into(),
                );
            }
            emit(
                flags.output_mode(),
                "Rivet Inspect",
                lines,
                Event::new("risk.detected").with("name", name.clone()),
                json!({"found": false, "package": target, "namesquat": squat}),
            )
        }
    }
}

/// Finds a verified statement for a command, "name@version" or "name".
pub fn find_statement(session: &Session, target: &str) -> Result<Option<Statement>> {
    find_statement_with_freshness(session, target, false)
}

pub fn find_statement_with_freshness(
    session: &Session,
    target: &str,
    require_fresh: bool,
) -> Result<Option<Statement>> {
    let (name, version) = match session.store.read_command(target) {
        Ok(command) => (command.package, Some(command.version)),
        Err(_) => split_name_version(target),
    };
    let version = match version {
        Some(version) => version,
        None => match latest_known(session, &name)? {
            Some(version) => version,
            None => return Ok(None),
        },
    };
    let now = OffsetDateTime::now_utc();
    match session.client.attestation(&name, &version) {
        Ok(envelope) => {
            let statement = envelope.verify(&session.key, now)?;
            if statement.name != name || statement.version != version {
                anyhow::bail!(
                    "registry answered {} for requested {name}@{version}",
                    statement.id()
                );
            }
            session
                .store
                .cache_attestation(&statement, &envelope, &session.key)?;
            Ok(Some(statement))
        }
        Err(err) => match session
            .store
            .cached_attestation(&name, &version, &session.key)?
        {
            Some((statement, envelope)) => {
                eprintln!("rivet: registry unavailable ({err:#}); showing cached statement");
                if require_fresh {
                    Ok(Some(envelope.verify(&session.key, now)?))
                } else {
                    Ok(Some(statement))
                }
            }
            None if err.to_string().contains("404") => Ok(None),
            None => Err(err).context("fetch attestation"),
        },
    }
}

fn latest_known(session: &Session, name: &str) -> Result<Option<String>> {
    let path = format!("/v1/packages/{}", urlencoding::encode(name));
    let Ok(value) = session.client.get(&path) else {
        return Ok(None);
    };
    let versions = value
        .get("versions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(versions
        .iter()
        .filter(|v| v.get("latest_verified_audit_id").is_some())
        .filter_map(|v| v.get("version").and_then(|v| v.as_str()).map(String::from))
        .next())
}
