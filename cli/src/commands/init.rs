use anyhow::{Context, Result};
use serde_json::json;

use crate::core::{
    lockfile::Lockfile,
    manifest::{Manifest, PackageSection, PolicySection},
    output::{emit, Event},
    paths::ProjectPaths,
    registry_client::RegistryClient,
    store::LocalStore,
};
use crate::CommonFlags;

pub fn run(flags: CommonFlags) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    let name = paths
        .root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("rivet-package")
        .to_string();
    let manifest = Manifest {
        package: PackageSection {
            name: sanitize_package_name(&name),
            version: "0.1.0".to_string(),
            description: Some("A Rivet package".to_string()),
            license: Some("MIT".to_string()),
        },
        policy: Some(PolicySection::default()),
        ..Manifest::default()
    };

    if flags.dry_run || flags.plan {
        emit(
            flags.output_mode(),
            "Rivet Init Plan",
            vec![
                format!("Create {}", paths.manifest.display()),
                format!("Create {}", paths.lockfile.display()),
                format!("Create {}", paths.metadata_dir.display()),
            ],
            Event::new("plan.created").with("command", "init"),
            json!({"created": false, "package": manifest.package}),
        )?;
        return Ok(());
    }

    let store = LocalStore::open(RegistryClient::from_env()?.base_url())?;
    if !paths.manifest.exists() {
        manifest
            .write_to(&paths.manifest)
            .with_context(|| format!("write {}", paths.manifest.display()))?;
    }
    if !paths.lockfile.exists() {
        Lockfile::default()
            .write_to(&paths.lockfile)
            .with_context(|| format!("write {}", paths.lockfile.display()))?;
    }
    paths.ensure_metadata()?;
    store.ensure()?;
    let gitignore = paths.root.join(".gitignore");
    if !gitignore.exists() {
        std::fs::write(&gitignore, "node_modules/\n")?;
    }

    emit(
        flags.output_mode(),
        "Rivet Init",
        vec![
            format!("Project: {}", manifest.package.name),
            format!("Manifest: {}", paths.manifest.display()),
            format!("Lockfile: {}", paths.lockfile.display()),
            format!("Metadata: {}", paths.metadata_dir.display()),
            format!("Store: {}", store.store_dir.display()),
        ],
        Event::new("manifest.read").with("path", paths.manifest.display().to_string()),
        json!({
            "created": true,
            "package": manifest.package.name,
            "manifest": paths.manifest,
            "lockfile": paths.lockfile,
        }),
    )
}

fn sanitize_package_name(name: &str) -> String {
    name.to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}
