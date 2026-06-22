use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::json;

use crate::core::{
    output::{emit_many, Event},
    registry_client::RegistryClient,
};
use crate::CommonFlags;

pub fn revoke(
    package: String,
    reason: String,
    replacement: Option<String>,
    flags: CommonFlags,
) -> Result<()> {
    change_state(package, "revoke", reason, replacement, flags)
}

pub fn yank(package: String, reason: String, flags: CommonFlags) -> Result<()> {
    change_state(package, "yank", reason, None, flags)
}

fn change_state(
    package: String,
    action: &'static str,
    reason: String,
    replacement: Option<String>,
    flags: CommonFlags,
) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("--reason is required");
    }
    let (name, version) = parse_package_version(&package)?;
    let request = StateChangeRequest {
        reason: reason.clone(),
        replacement_version: replacement,
    };

    let planned = json!({
            "package": name,
            "version": version,
            "action": action,
            "reason": reason,
    });
    if !flags.json || flags.dry_run || flags.plan {
        emit_many(
            flags.output_mode(),
            &format!("Rivet {}", title_case(action)),
            vec![
                format!("Package: {name}@{version}"),
                format!("Reason: {reason}"),
            ],
            vec![Event::new(release_event(action))
                .with("package", name.clone())
                .with("version", version.clone())],
            &planned,
        )?;
    }

    if flags.dry_run || flags.plan {
        return Ok(());
    }
    let registry = RegistryClient::from_env()?;
    let response = registry.package_action(&name, &version, action, &request)?;
    if flags.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "request": planned,
                "registry_response": response,
            }))?
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct StateChangeRequest {
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    replacement_version: Option<String>,
}

fn parse_package_version(spec: &str) -> Result<(String, String)> {
    if spec.starts_with('@') {
        if let Some(slash_index) = spec.find('/') {
            if let Some(relative_version_index) = spec[slash_index + 1..].rfind('@') {
                let index = slash_index + 1 + relative_version_index;
                return Ok((spec[..index].to_string(), spec[index + 1..].to_string()));
            }
        }
    } else if let Some((name, version)) = spec.rsplit_once('@') {
        if !name.is_empty() && !version.is_empty() {
            return Ok((name.to_string(), version.to_string()));
        }
    }
    bail!("package must be in name@version form")
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => value.to_string(),
    }
}

fn release_event(action: &str) -> &'static str {
    match action {
        "revoke" => "release.revoked",
        "yank" => "release.yanked",
        _ => "release.updated",
    }
}

#[cfg(test)]
mod tests {
    use super::parse_package_version;

    #[test]
    fn parses_package_version_specs() {
        assert_eq!(
            parse_package_version("demo@0.1.0").unwrap(),
            ("demo".into(), "0.1.0".into())
        );
        assert_eq!(
            parse_package_version("@scope/demo@0.1.0").unwrap(),
            ("@scope/demo".into(), "0.1.0".into())
        );
    }
}
