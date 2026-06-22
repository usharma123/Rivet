use std::{path::PathBuf, process::Command};

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::core::{
    output::{emit_many, Event, OutputMode},
    risk::{combine_risk, RiskLevel},
    store::{LocalStore, StoredExecutable, StoredPackage},
};
use crate::CommonFlags;

pub fn run(command: String, args: Vec<String>, flags: CommonFlags) -> Result<()> {
    let store = LocalStore::from_env()?;
    let command_ref = store
        .read_command(&command)
        .with_context(|| format!("command not found in Rivet store: {command}"))?;
    let package = store.read_package(&command_ref.package, Some(&command_ref.version))?;
    let executable = package
        .executables
        .iter()
        .find(|candidate| candidate.command == command)
        .cloned()
        .with_context(|| format!("executable metadata missing for {command}"))?;
    enforce_policy(&package, &flags)?;

    let entry = executable_path(&package, &executable);
    emit_many(
        flags.output_mode(),
        "Rivet Run",
        vec![
            format!("Command: {command}"),
            format!("Package: {}@{}", package.name, package.version),
            format!("State: {}", package.state),
            format!("Risk: {}", package.risk_score),
            format!("Executable: {}", executable.entry),
            "Running...".to_string(),
        ],
        vec![
            Event::new("install.started")
                .with("command", command.clone())
                .with("package", package.name.clone()),
            Event::new("artifact.verified").with("artifact", package.artifact.clone()),
        ],
        json!({
            "command": command,
            "args": args,
            "package": package.name,
            "version": package.version,
            "entry": entry,
        }),
    )?;

    if flags.dry_run || flags.plan {
        return Ok(());
    }
    let status = command_for_entry(&entry, &args).status()?;
    if !status.success() {
        bail!("command exited with status {status}");
    }
    if flags.output_mode() == OutputMode::Events {
        println!(
            "{}",
            serde_json::to_string(
                &Event::new("install.completed").with("command", executable.command)
            )?
        );
    }
    Ok(())
}

fn enforce_policy(package: &StoredPackage, flags: &CommonFlags) -> Result<()> {
    match package.state.as_str() {
        "revoked" | "blocked" if !flags.unsafe_allow_revoked => {
            bail!(
                "package {}@{} is {}; use --unsafe-allow-revoked to override",
                package.name,
                package.version,
                package.state
            );
        }
        _ => {}
    }
    let risk = combine_risk(package.risk_score, &package.risk_reasons, &package.name);
    if matches!(risk.level, RiskLevel::High | RiskLevel::Critical) && !flags.unsafe_allow_risk {
        bail!(
            "package {}@{} is {:?} risk; use --unsafe-allow-risk to override",
            package.name,
            package.version,
            risk.level
        );
    }
    Ok(())
}

fn executable_path(package: &StoredPackage, executable: &StoredExecutable) -> PathBuf {
    package
        .package_dir
        .join(executable.entry.trim_start_matches("./"))
}

fn command_for_entry(entry: &PathBuf, args: &[String]) -> Command {
    let is_js = entry
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "cjs" | "mjs"));
    let mut command = if is_js {
        let mut command = Command::new("node");
        command.arg(entry);
        command
    } else {
        Command::new(entry)
    };
    command.args(args);
    command
}
