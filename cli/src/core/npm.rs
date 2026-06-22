use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmSpec {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NpmMetadata {
    #[serde(rename = "dist-tags")]
    pub dist_tags: BTreeMap<String, String>,
    pub versions: BTreeMap<String, NpmVersion>,
}

#[derive(Debug, Deserialize)]
pub struct NpmVersion {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    pub dist: NpmDist,
}

#[derive(Debug, Deserialize)]
pub struct NpmDist {
    pub tarball: String,
    pub integrity: String,
}

#[derive(Debug, Clone)]
pub struct NpmPackageJson {
    pub raw: Value,
    pub dependencies: BTreeMap<String, String>,
    pub bin: BTreeMap<String, String>,
    pub scripts: BTreeMap<String, String>,
}

impl NpmSpec {
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec
            .strip_prefix("npm:")
            .ok_or_else(|| anyhow::anyhow!("npm import spec must start with npm:"))?;
        if spec.is_empty() {
            bail!("npm import spec is empty");
        }
        if spec.starts_with('@') {
            if let Some(slash_index) = spec.find('/') {
                if let Some(relative_version_index) = spec[slash_index + 1..].rfind('@') {
                    let index = slash_index + 1 + relative_version_index;
                    return Ok(Self {
                        name: spec[..index].to_string(),
                        version: Some(spec[index + 1..].to_string()),
                    });
                }
            }
            return Ok(Self {
                name: spec.to_string(),
                version: None,
            });
        }
        if let Some((name, version)) = spec.rsplit_once('@') {
            if !name.is_empty() && !version.is_empty() {
                return Ok(Self {
                    name: name.to_string(),
                    version: Some(version.to_string()),
                });
            }
        }
        Ok(Self {
            name: spec.to_string(),
            version: None,
        })
    }
}

pub fn fetch_metadata(client: &Client, name: &str) -> Result<NpmMetadata> {
    let encoded = urlencoding::encode(name);
    let url = format!("https://registry.npmjs.org/{encoded}");
    let response = client
        .get(url)
        .send()
        .context("fetch npm metadata")?
        .error_for_status()
        .context("npm metadata response")?;
    Ok(response.json()?)
}

pub fn select_version<'a>(
    metadata: &'a NpmMetadata,
    requested: Option<&str>,
) -> Result<&'a NpmVersion> {
    let version = match requested {
        Some(version) => version.to_string(),
        None => metadata
            .dist_tags
            .get("latest")
            .context("npm package has no latest dist-tag")?
            .to_string(),
    };
    metadata
        .versions
        .get(&version)
        .with_context(|| format!("npm version not found: {version}"))
}

pub fn download_tarball(client: &Client, version: &NpmVersion) -> Result<Vec<u8>> {
    let response = client
        .get(&version.dist.tarball)
        .send()
        .context("download npm tarball")?
        .error_for_status()
        .context("npm tarball response")?;
    Ok(response.bytes()?.to_vec())
}

pub fn parse_package_json(raw: Value, fallback_name: &str) -> NpmPackageJson {
    let dependencies = raw
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|deps| {
            deps.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let scripts = raw
        .get("scripts")
        .and_then(Value::as_object)
        .map(|scripts| {
            scripts
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let bin = match raw.get("bin") {
        Some(Value::String(entry)) => {
            let mut map = BTreeMap::new();
            map.insert(command_name(fallback_name), entry.clone());
            map
        }
        Some(Value::Object(entries)) => entries
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
            .collect(),
        _ => BTreeMap::new(),
    };
    NpmPackageJson {
        raw,
        dependencies,
        bin,
        scripts,
    }
}

fn command_name(package_name: &str) -> String {
    package_name
        .rsplit('/')
        .next()
        .unwrap_or(package_name)
        .to_string()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{parse_package_json, NpmSpec};

    #[test]
    fn parses_npm_specs() {
        assert_eq!(
            NpmSpec::parse("npm:prettier@3.5.0").unwrap(),
            NpmSpec {
                name: "prettier".into(),
                version: Some("3.5.0".into())
            }
        );
        assert_eq!(
            NpmSpec::parse("npm:react").unwrap(),
            NpmSpec {
                name: "react".into(),
                version: None
            }
        );
    }

    #[test]
    fn detects_bin_map_from_package_json() {
        let parsed = parse_package_json(
            json!({"bin":{"prettier":"./bin/prettier.cjs"},"dependencies":{"a":"1.0.0"}}),
            "prettier",
        );
        assert_eq!(parsed.bin["prettier"], "./bin/prettier.cjs");
        assert_eq!(parsed.dependencies["a"], "1.0.0");
    }
}
