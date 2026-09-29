use anyhow::{Context, Result};
use serde_json::json;

use crate::core::{
    lockfile::Lockfile,
    manifest::{Manifest, PackageSection, PolicySection},
    output::{emit, Event},
    paths::ProjectPaths,
    project::{atomic_write, Project, ProjectLock},
    registry_client::RegistryClient,
    store::LocalStore,
};
use crate::CommonFlags;

pub fn run(flags: CommonFlags) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    let _guard = ProjectLock::acquire(&paths.root)?;
    if paths.root.join("package.json").exists() {
        let project = Project::read(&paths.root)?;
        let changed = !(paths.manifest.exists() || flags.plan || flags.dry_run);
        if changed {
            atomic_write(&paths.manifest, b"[policy]\nmin_release_age_hours = 72\n")?;
        }
        if !flags.plan && !flags.dry_run {
            ensure_gitignore(&paths.root)?;
        }
        return emit(
            flags.output_mode(),
            "Rivet Init",
            vec!["Use package.json for dependencies and scripts; rivet.toml holds policy.".into()],
            Event::new(if changed {
                "manifest.updated"
            } else {
                "plan.created"
            }),
            json!({"created": changed, "manifest": project.path, "policy": paths.manifest}),
        );
    }
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
    ensure_gitignore(&paths.root)?;

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

fn ensure_gitignore(root: &std::path::Path) -> Result<()> {
    let path = root.join(".gitignore");
    let mut contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).context("read .gitignore"),
    };
    let original_len = contents.len();
    for entry in ["node_modules/", ".rivet/"] {
        if !contents.lines().any(|line| line.trim() == entry) {
            if !contents.is_empty() && !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(entry);
            contents.push('\n');
        }
    }
    if contents.len() != original_len {
        atomic_write(&path, contents.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitignore_preserves_user_entries_and_adds_missing_defaults_once() {
        for initial in [None, Some("dist/"), Some("node_modules/\n# custom\n")] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join(".gitignore");
            if let Some(initial) = initial {
                std::fs::write(&path, initial).unwrap();
            }
            ensure_gitignore(root.path()).unwrap();
            let contents = std::fs::read_to_string(&path).unwrap();
            assert!(contents.starts_with(initial.unwrap_or("")));
            assert_eq!(
                contents
                    .lines()
                    .filter(|line| *line == "node_modules/")
                    .count(),
                1
            );
            assert_eq!(
                contents.lines().filter(|line| *line == ".rivet/").count(),
                1
            );
            ensure_gitignore(root.path()).unwrap();
            assert_eq!(std::fs::read_to_string(path).unwrap(), contents);
        }
    }
}
