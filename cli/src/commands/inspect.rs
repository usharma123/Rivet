use anyhow::Result;
use serde_json::json;

use crate::core::{
    output::{emit, Event},
    risk::combine_risk,
    store::{LocalStore, StoredPackage},
};
use crate::CommonFlags;

pub fn run(target: String, flags: CommonFlags) -> Result<()> {
    let store = LocalStore::from_env()?;
    let package = store
        .read_package(&target, None)
        .or_else(|_| {
            let command = store.read_command(&target)?;
            store.read_package(&command.package, Some(&command.version))
        })
        .ok();

    match package {
        Some(package) => inspect_package(target, package, flags),
        None => inspect_unknown(target, flags),
    }
}

fn inspect_package(target: String, package: StoredPackage, flags: CommonFlags) -> Result<()> {
    let risk = combine_risk(package.risk_score, &package.risk_reasons, &target);
    let mut lines = vec![
        format!("Package: {}", package.name),
        format!("Version: {}", package.version),
        format!("Source: {}", package.source),
        format!("State: {}", package.state),
        format!("Artifact size: {} bytes", package.artifact_size),
        format!(
            "Publisher: {}",
            package.publisher.as_deref().unwrap_or("unverified")
        ),
        format!(
            "Last published by: {}",
            package.last_published_by.as_deref().unwrap_or("unknown")
        ),
        format!(
            "Source visibility: {}",
            if package.source_visibility.is_empty() {
                "unknown"
            } else {
                &package.source_visibility
            }
        ),
        format!("Native binaries: {}", yes_no(package.has_native_binaries)),
        format!("Install scripts: {}", yes_no(package.has_install_scripts)),
        format!("Risk: {:?} ({})", risk.level, risk.score),
    ];
    if let Some(audit) = &package.verified_audit {
        lines.push(format!("Verified audit: {}", audit.status));
        lines.push(format!("Audit verdict: {}", audit.verdict));
        lines.push(format!("Audit score: {}", audit.risk_score));
        lines.push(format!(
            "Audit signature: {}",
            if audit.signature.is_empty() {
                "missing"
            } else {
                "present"
            }
        ));
        lines.push(format!("Audit cost: {} cents", audit.cost_cents));
    } else {
        lines.push("Verified audit: none".to_string());
    }
    for executable in &package.executables {
        lines.push(format!("Executable: {}", executable.command));
        lines.push(format!("Entry: {}", executable.entry));
        lines.push(format!("Permissions: {}", executable.permissions));
    }
    if let Some(confusable) = &risk.confusable_with {
        lines.push(format!("Warning: possible namesquat with {confusable}"));
    }
    if package.executables.is_empty() {
        lines.push("Executables: none".to_string());
    }

    emit(
        flags.output_mode(),
        "Rivet Inspect",
        lines,
        Event::new("risk.detected")
            .with("name", package.name.clone())
            .with("risk", risk.score),
        json!({
            "package": package,
            "risk": risk,
        }),
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn inspect_unknown(target: String, flags: CommonFlags) -> Result<()> {
    let risk = combine_risk(20, &["unverified package".to_string()], &target);
    let mut lines = vec![
        format!("Package: {target}"),
        "State: not imported".to_string(),
        "Publisher: unverified".to_string(),
        format!("Risk: {:?} ({})", risk.level, risk.score),
    ];
    if let Some(confusable) = &risk.confusable_with {
        lines.push("Warning: possible namesquat".to_string());
        lines.push(format!("Confusable with: {confusable}"));
        lines.push(
            "Recommendation: do not install unless you intentionally meant this exact package."
                .to_string(),
        );
    }
    emit(
        flags.output_mode(),
        "Rivet Inspect",
        lines,
        Event::new("risk.detected")
            .with("name", target.clone())
            .with("risk", risk.score),
        json!({
            "package": target,
            "found": false,
            "risk": risk,
        }),
    )
}
