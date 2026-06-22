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
        format!("Risk: {:?} ({})", risk.level, risk.score),
    ];
    for executable in &package.executables {
        lines.push(format!("Executable: {}", executable.command));
        lines.push(format!("Entry: {}", executable.entry));
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
