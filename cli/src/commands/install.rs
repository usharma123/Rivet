use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::commands::import::{import_npm_package, update_lockfile};
use crate::core::{
    lockfile::Lockfile,
    manifest::Manifest,
    output::{emit_many, Event},
    paths::ProjectPaths,
};
use crate::CommonFlags;

pub fn run(flags: CommonFlags) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    if !paths.manifest.exists() {
        bail!("rivet.toml not found; run `rivet init` first");
    }
    let manifest = Manifest::read_from(&paths.manifest)
        .with_context(|| format!("read {}", paths.manifest.display()))?;
    let mut lockfile = if paths.lockfile.exists() {
        Lockfile::read_from(&paths.lockfile)?
    } else {
        Lockfile::default()
    };
    let missing: Vec<_> = manifest
        .dependencies
        .keys()
        .filter(|name| !lockfile.packages.contains_key(*name))
        .cloned()
        .collect();

    let mut imported = Vec::new();
    if !flags.dry_run && !flags.plan {
        for (name, requested) in &manifest.dependencies {
            if lockfile.packages.contains_key(name) {
                continue;
            }
            let spec = if requested == "latest" {
                format!("npm:{name}")
            } else {
                format!("npm:{name}@{requested}")
            };
            let result = import_npm_package(&spec, &flags)
                .with_context(|| format!("import dependency {name}"))?;
            update_lockfile(&paths.lockfile, &result.package)?;
            lockfile = Lockfile::read_from(&paths.lockfile)?;
            imported.push(format!(
                "{}@{}",
                result.package.name, result.package.version
            ));
        }
    }

    paths.ensure_metadata()?;
    std::fs::write(
        paths.metadata_dir.join("install-plan.json"),
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "dependencies": manifest.dependencies,
            "imported": imported,
            "locked": lockfile.packages,
        }))?,
    )?;
    std::fs::write(
        paths.metadata_dir.join("graph.json"),
        serde_json::to_string_pretty(&json!({
            "packages": lockfile.packages.keys().collect::<Vec<_>>(),
        }))?,
    )?;

    let lines = vec![
        format!("Project: {}", manifest.package.name),
        format!("Dependencies: {}", manifest.dependencies.len()),
        format!("Locked: {}", lockfile.packages.len()),
        format!("Imported: {}", imported.len()),
    ];
    let events = vec![
        Event::new("install.started").with("project", manifest.package.name.clone()),
        Event::new("manifest.read").with("path", paths.manifest.display().to_string()),
        Event::new("plan.created")
            .with("dependencies", manifest.dependencies.len())
            .with("pending_import", missing.len()),
        Event::new("install.completed").with("changed", !imported.is_empty()),
    ];

    emit_many(
        flags.output_mode(),
        "Rivet Install Plan",
        lines,
        events,
        json!({
            "project": manifest.package.name,
            "dependencies": manifest.dependencies,
            "locked": lockfile.packages,
            "pending_import": missing,
            "imported": imported,
            "changed": !imported.is_empty()
        }),
    )
}
