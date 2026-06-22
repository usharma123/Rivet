use std::io::{self, Write};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::json;

use crate::core::{
    artifact::{create_project_tgz, sha512_hex},
    manifest::Manifest,
    output::{emit_many, Event, OutputMode},
    paths::ProjectPaths,
    registry_client::RegistryClient,
};
use crate::CommonFlags;

pub fn run(flags: CommonFlags) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    let manifest = Manifest::read_from(&paths.manifest)
        .with_context(|| format!("read {}", paths.manifest.display()))?;
    let artifact = create_project_tgz(&paths.root)?;
    let artifact_hash = sha512_hex(&artifact);
    let risk = publish_risk(&manifest);
    let executables = manifest
        .executables
        .iter()
        .map(|(command, executable)| RegistryExecutable {
            command: command.clone(),
            entry: executable.entry.clone(),
            summary: executable.summary.clone(),
            permissions: serde_json::to_value(&executable.permissions)
                .unwrap_or_else(|_| json!({})),
            risk_score: risk.score as u16,
        })
        .collect::<Vec<_>>();

    let review = json!({
            "package": manifest.package.name,
            "version": manifest.package.version,
            "artifact": artifact_hash,
            "risk": risk,
            "executables": executables,
    });
    if flags.output_mode() != OutputMode::Json || flags.dry_run || flags.plan {
        emit_many(
            flags.output_mode(),
            "Release Review",
            vec![
                format!("Package: {}", manifest.package.name),
                format!("Version: {}", manifest.package.version),
                format!("Commands: {}", executables.len()),
                format!("Generated artifact: {artifact_hash}"),
                format!("Risk: {}", risk.level),
            ],
            vec![
                Event::new("publish.started")
                    .with("package", manifest.package.name.clone())
                    .with("version", manifest.package.version.clone()),
                Event::new("publish.ready").with("artifact", artifact_hash.clone()),
            ],
            &review,
        )?;
    }

    if flags.dry_run || flags.plan {
        return Ok(());
    }
    if !flags.non_interactive && flags.output_mode() == OutputMode::Human && !confirm_publish()? {
        bail!("publish cancelled");
    }

    let registry = RegistryClient::from_env()?;
    registry.put_artifact(&artifact_hash, &artifact)?;
    let request = PublishRequest {
        source: "native",
        publisher: manifest
            .publisher
            .as_ref()
            .map(|publisher| publisher.identity.clone())
            .unwrap_or_default(),
        state: "active",
        manifest: serde_json::to_value(&manifest)?,
        artifact_hash: artifact_hash.clone(),
        artifact_url: format!("/v1/artifacts/{artifact_hash}"),
        source_metadata: json!({"local": {"path": paths.root}}),
        executables,
        risk_score: risk.score as u16,
    };
    let response = registry.package_action(
        &manifest.package.name,
        &manifest.package.version,
        "publish",
        &request,
    )?;
    if flags.output_mode() == OutputMode::Events {
        println!(
            "{}",
            serde_json::to_string(
                &Event::new("release.published")
                    .with("package", manifest.package.name)
                    .with("version", manifest.package.version)
            )?
        );
    } else if flags.output_mode() == OutputMode::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "review": review,
                "registry_response": response,
            }))?
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct PublishRequest {
    source: &'static str,
    publisher: String,
    state: &'static str,
    manifest: serde_json::Value,
    artifact_hash: String,
    artifact_url: String,
    source_metadata: serde_json::Value,
    executables: Vec<RegistryExecutable>,
    risk_score: u16,
}

#[derive(Debug, Clone, Serialize)]
struct RegistryExecutable {
    command: String,
    entry: String,
    summary: Option<String>,
    permissions: serde_json::Value,
    risk_score: u16,
}

#[derive(Debug, Serialize)]
struct PublishRisk {
    score: u8,
    level: &'static str,
    reasons: Vec<String>,
}

fn publish_risk(manifest: &Manifest) -> PublishRisk {
    let mut score = 0u8;
    let mut reasons = Vec::new();
    for script in ["preinstall", "install", "postinstall"] {
        if manifest.scripts.contains_key(script) {
            score = score.saturating_add(25);
            reasons.push(format!("{script} script present"));
        }
    }
    if manifest.publisher.is_none() {
        score = score.saturating_add(20);
        reasons.push("publisher identity missing".to_string());
    }
    let level = match score {
        0..=29 => "low",
        30..=59 => "medium",
        60..=79 => "high",
        _ => "critical",
    };
    PublishRisk {
        score,
        level,
        reasons,
    }
}

fn confirm_publish() -> Result<bool> {
    print!("Publish as active? [Y/n] ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(!matches!(input.trim(), "n" | "N" | "no" | "NO"))
}

#[cfg(test)]
mod tests {
    use crate::core::manifest::{Manifest, PackageSection};

    use super::publish_risk;

    #[test]
    fn missing_publisher_increases_publish_risk() {
        let manifest = Manifest {
            package: PackageSection {
                name: "demo".into(),
                version: "0.1.0".into(),
                description: None,
                license: None,
            },
            ..Manifest::default()
        };
        let risk = publish_risk(&manifest);
        assert!(risk.score >= 20);
    }
}
