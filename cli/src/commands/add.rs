use anyhow::Result;
use serde_json::json;

use crate::core::{
    output::{emit, Event},
    paths::ProjectPaths,
    project::{Project, ProjectLock},
    resolver::split_name_version,
};
use crate::CommonFlags;

pub fn run(package: String, flags: CommonFlags) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    let _guard = ProjectLock::acquire(&paths.root)?;
    let mut project = Project::read(&paths.root)?;
    let (name, version) = parse_dependency(&package);
    project.add(&name, &version, false)?;
    let changed = !(flags.dry_run || flags.plan);
    if changed {
        project.save()?;
    }
    emit(
        flags.output_mode(),
        "Rivet Add",
        vec![
            format!("{name}@{version}"),
            "Run rivet install to resolve and install.".into(),
        ],
        Event::new(if changed {
            "manifest.updated"
        } else {
            "plan.created"
        })
        .with("dependency", &name),
        json!({"changed": changed, "dependency": name, "version": version}),
    )
}

pub(crate) fn parse_dependency(spec: &str) -> (String, String) {
    let spec = spec.strip_prefix("npm:").unwrap_or(spec);
    let (name, version) = split_name_version(spec);
    (name, version.unwrap_or_else(|| "latest".to_string()))
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
        assert_eq!(
            parse_dependency("@babel/core@^7.24.0"),
            ("@babel/core".into(), "^7.24.0".into())
        );
        assert_eq!(
            parse_dependency("@types/node"),
            ("@types/node".into(), "latest".into())
        );
    }
}
