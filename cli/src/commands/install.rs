use anyhow::{bail, Context, Result};
use serde_json::json;

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
    let lockfile = if paths.lockfile.exists() {
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

    let lines = vec![
        format!("Project: {}", manifest.package.name),
        format!("Dependencies: {}", manifest.dependencies.len()),
        format!("Locked: {}", lockfile.packages.len()),
        format!("Pending import: {}", missing.len()),
    ];
    let events = vec![
        Event::new("install.started").with("project", manifest.package.name.clone()),
        Event::new("manifest.read").with("path", paths.manifest.display().to_string()),
        Event::new("plan.created")
            .with("dependencies", manifest.dependencies.len())
            .with("pending_import", missing.len()),
        Event::new("install.completed").with("changed", false),
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
            "changed": false
        }),
    )
}
