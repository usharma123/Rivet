use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::json;

use crate::core::{
    artifact::{extract_tgz, sha512_hex, verify_npm_integrity},
    lockfile::{LockedPackage, Lockfile},
    npm::{download_tarball, fetch_metadata, parse_package_json, select_version, NpmSpec},
    output::{emit_many, Event},
    paths::ProjectPaths,
    registry_client::RegistryClient,
    store::{LocalStore, StoredExecutable, StoredPackage},
};
use crate::CommonFlags;

pub fn run(spec: String, flags: CommonFlags) -> Result<()> {
    let result = import_npm_package(&spec, &flags)?;
    write_project_lock_if_present(&result)?;

    emit_many(
        flags.output_mode(),
        "Rivet Import",
        vec![
            format!(
                "Package: {}@{}",
                result.package.name, result.package.version
            ),
            format!("Source: {}", result.package.source),
            format!("Artifact: {}", result.package.artifact),
            format!("Executables: {}", result.package.executables.len()),
            format!("Registry: {}", result.package.registry),
        ],
        vec![
            Event::new("artifact.downloaded")
                .with("name", result.package.name.clone())
                .with("version", result.package.version.clone()),
            Event::new("artifact.verified").with("integrity", result.package.integrity.clone()),
            Event::new("dependency.resolved")
                .with("name", result.package.name.clone())
                .with("version", result.package.version.clone()),
        ],
        json!({
            "package": result.package,
            "registry_response": result.registry_response,
        }),
    )
}

pub fn import_npm_package(spec: &str, _flags: &CommonFlags) -> Result<ImportResult> {
    let npm_spec = NpmSpec::parse(spec)?;
    let http = Client::new();
    let metadata = fetch_metadata(&http, &npm_spec.name)?;
    let selected = select_version(&metadata, npm_spec.version.as_deref())?;
    let tarball = download_tarball(&http, selected)?;
    verify_npm_integrity(&tarball, &selected.dist.integrity)?;
    let artifact = sha512_hex(&tarball);

    let store = LocalStore::from_env()?;
    store.ensure()?;
    let artifact_dir = store.artifact_dir(&artifact);
    extract_tgz(&tarball, &artifact_dir)?;
    fs::write(artifact_dir.join("artifact.tgz"), &tarball)?;

    let package_dir = artifact_dir.join("package");
    let package_json_path = package_dir.join("package.json");
    let package_json_value: serde_json::Value = serde_json::from_slice(
        &fs::read(&package_json_path)
            .with_context(|| format!("read {}", package_json_path.display()))?,
    )?;
    let package_json = parse_package_json(package_json_value.clone(), &selected.name);
    let executables = package_json
        .bin
        .iter()
        .map(|(command, entry)| StoredExecutable {
            command: command.clone(),
            entry: entry.clone(),
            summary: selected.description.clone(),
            permissions: json!({
                "filesystem": ["read:cwd", "write:cwd"],
                "network": false,
                "env": []
            }),
        })
        .collect::<Vec<_>>();
    let (risk_score, risk_reasons) = import_risk(&package_json.scripts);
    let generated_manifest = json!({
        "name": selected.name,
        "version": selected.version,
        "source": "npm-import",
        "executables": executables,
        "risk": {
            "score": risk_score,
            "reasons": risk_reasons,
        }
    });
    fs::write(
        artifact_dir.join("rivet.manifest.json"),
        serde_json::to_vec_pretty(&generated_manifest)?,
    )?;
    fs::write(
        artifact_dir.join("sbom.json"),
        serde_json::to_vec_pretty(&json!({"dependencies": package_json.dependencies}))?,
    )?;
    fs::write(
        artifact_dir.join("eval.json"),
        serde_json::to_vec_pretty(&json!({"status": "not-run"}))?,
    )?;
    fs::write(
        artifact_dir.join("provenance.json"),
        serde_json::to_vec_pretty(&json!({"source": "npm", "tarball": selected.dist.tarball}))?,
    )?;

    let registry = RegistryClient::from_env()?;
    registry.put_artifact(&artifact, &tarball)?;
    let request = ImportRegistryRequest {
        name: selected.name.clone(),
        version: selected.version.clone(),
        source: "npm-import",
        state: "active",
        manifest: generated_manifest.clone(),
        artifact_hash: artifact.clone(),
        artifact_url: format!("/v1/artifacts/{artifact}"),
        source_metadata: json!({
            "npm": {
                "tarball": selected.dist.tarball,
                "integrity": selected.dist.integrity,
                "scripts": package_json.scripts,
                "dependencies": package_json.dependencies,
            }
        }),
        executables: executables
            .iter()
            .map(|executable| RegistryExecutable {
                command: executable.command.clone(),
                entry: executable.entry.clone(),
                summary: executable.summary.clone(),
                permissions: executable.permissions.clone(),
                risk_score: risk_score as u16,
            })
            .collect(),
        risk_score: risk_score as u16,
    };
    let registry_response = registry.import_npm(&request)?;

    let stored = StoredPackage {
        name: selected.name.clone(),
        version: selected.version.clone(),
        source: "npm-import".to_string(),
        state: "active".to_string(),
        artifact,
        integrity: selected.dist.integrity.clone(),
        registry: registry.base_url().to_string(),
        package_dir,
        manifest: generated_manifest,
        package_json: package_json.raw,
        executables,
        dependencies: package_json.dependencies,
        risk_score,
        risk_reasons,
    };
    store.write_package(&stored)?;
    let _ = store.read_package(&stored.name, Some(&stored.version))?;

    Ok(ImportResult {
        package: stored,
        registry_response,
    })
}

#[derive(Debug, Clone)]
pub struct ImportResult {
    pub package: StoredPackage,
    pub registry_response: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ImportRegistryRequest<'a> {
    name: String,
    version: String,
    source: &'a str,
    state: &'a str,
    manifest: serde_json::Value,
    artifact_hash: String,
    artifact_url: String,
    source_metadata: serde_json::Value,
    executables: Vec<RegistryExecutable>,
    risk_score: u16,
}

#[derive(Debug, Serialize)]
struct RegistryExecutable {
    command: String,
    entry: String,
    summary: Option<String>,
    permissions: serde_json::Value,
    risk_score: u16,
}

fn write_project_lock_if_present(result: &ImportResult) -> Result<()> {
    let paths = ProjectPaths::from_current_dir()?;
    if !paths.lockfile.exists() {
        return Ok(());
    }
    update_lockfile(&paths.lockfile, &result.package)
}

pub fn update_lockfile(path: &PathBuf, package: &StoredPackage) -> Result<()> {
    let mut lockfile = if path.exists() {
        Lockfile::read_from(path)?
    } else {
        Lockfile::default()
    };
    lockfile.packages.insert(
        package.name.clone(),
        LockedPackage {
            version: package.version.clone(),
            source: package.source.clone(),
            artifact: package.artifact.clone(),
            integrity: package.integrity.clone(),
            registry: package.registry.clone(),
            state: package.state.clone(),
            dependencies: package.dependencies.clone(),
        },
    );
    lockfile.write_to(path)
}

fn import_risk(scripts: &std::collections::BTreeMap<String, String>) -> (u8, Vec<String>) {
    let mut score = 8;
    let mut reasons = Vec::new();
    for script in ["preinstall", "install", "postinstall"] {
        if scripts.contains_key(script) {
            score += 25;
            reasons.push(format!("{script} script present"));
        }
    }
    (score.min(100), reasons)
}
