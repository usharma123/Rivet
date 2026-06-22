use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::core::{
    manifest::Manifest,
    output::{emit, Event},
    paths::ProjectPaths,
};
use crate::CommonFlags;

pub fn run(package: String, flags: CommonFlags) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    if !paths.manifest.exists() {
        bail!("rivet.toml not found; run `rivet init` first");
    }
    let mut manifest = Manifest::read_from(&paths.manifest)
        .with_context(|| format!("read {}", paths.manifest.display()))?;
    let (name, version) = parse_dependency(&package);

    if flags.dry_run || flags.plan {
        emit(
            flags.output_mode(),
            "Rivet Add Plan",
            vec![format!("Add dependency: {name} = {version}")],
            Event::new("plan.created")
                .with("command", "add")
                .with("package", name.clone()),
            json!({"changed": false, "dependency": name, "version": version}),
        )?;
        return Ok(());
    }

    manifest.dependencies.insert(name.clone(), version.clone());
    manifest.write_to(&paths.manifest)?;

    emit(
        flags.output_mode(),
        "Rivet Add",
        vec![
            format!("Project: {}", manifest.package.name),
            format!("Added: {name}@{version}"),
            "Run `rivet install` to resolve and lock artifacts.".to_string(),
        ],
        Event::new("dependency.resolved")
            .with("name", name.clone())
            .with("version", version.clone()),
        json!({"changed": true, "dependency": name, "version": version}),
    )
}

fn parse_dependency(spec: &str) -> (String, String) {
    if let Some((name, version)) = spec.rsplit_once('@') {
        if !name.is_empty() && !version.is_empty() && !spec.starts_with('@') {
            return (name.to_string(), version.to_string());
        }
    }
    (spec.to_string(), "latest".to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_dependency;

    #[test]
    fn parses_unscoped_dependency_specs() {
        assert_eq!(
            parse_dependency("react@18.2.0"),
            ("react".into(), "18.2.0".into())
        );
        assert_eq!(parse_dependency("react"), ("react".into(), "latest".into()));
    }
}
