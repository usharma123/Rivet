//! Project input and cooperative locking shared by human and agent commands.
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

use super::{
    error::Failure,
    manifest::{Manifest, PackageSection, PolicySection, ScriptSection},
    resolver::parse_spec,
};

pub struct Project {
    pub root: PathBuf,
    pub path: PathBuf,
    pub manifest: Manifest,
    document: Option<Value>,
    original: Vec<u8>,
    policy_original: Option<Vec<u8>>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    policy: Option<PolicySection>,
}

impl Project {
    pub fn read(root: &Path) -> Result<Self> {
        let json_path = root.join("package.json");
        let toml_path = root.join("rivet.toml");
        if json_path.exists() {
            let original = fs::read(&json_path)?;
            let document: Value = serde_json::from_slice(&original).map_err(|e| {
                Failure::new(
                    "INVALID_MANIFEST",
                    e.to_string(),
                    "Fix package.json syntax.",
                )
            })?;
            if !document.is_object() {
                bail!(Failure::new(
                    "INVALID_MANIFEST",
                    "package.json must be an object",
                    "Use a valid npm project manifest."
                ));
            }
            // These fields change graph semantics. Refuse until implemented instead
            // of silently producing a different dependency tree from npm.
            for field in [
                "workspaces",
                "overrides",
                "optionalDependencies",
                "peerDependencies",
                "bundledDependencies",
                "bundleDependencies",
            ] {
                if document.get(field).is_some_and(|v| {
                    !v.is_null()
                        && v.as_object().is_none_or(|m| !m.is_empty())
                        && v.as_array().is_none_or(|a| !a.is_empty())
                }) {
                    bail!(Failure::new("UNSUPPORTED_PROJECT", format!("root {field} is not supported yet"), "Use a supported single-package project. Transitive optional dependencies and peers remain supported."));
                }
            }
            let mut dependencies = string_map(&document, "dependencies")?;
            for (name, spec) in string_map(&document, "devDependencies")? {
                if dependencies.get(&name).is_some_and(|s| s != &spec) {
                    bail!(Failure::new(
                        "INVALID_MANIFEST",
                        format!("conflicting dependency and devDependency for {name}"),
                        "Use one consistent spec for this dependency."
                    ));
                }
                dependencies.insert(name, spec);
            }
            for (alias, spec) in &dependencies {
                validate_spec(alias, spec)?;
            }
            let scripts = string_map(&document, "scripts")?
                .into_iter()
                .map(|(name, command)| {
                    (
                        name,
                        ScriptSection {
                            command,
                            ..Default::default()
                        },
                    )
                })
                .collect();
            let policy_original = if toml_path.exists() {
                Some(fs::read(&toml_path)?)
            } else {
                None
            };
            let policy = policy_original.as_ref().map(|bytes| -> Result<Option<PolicySection>> {
                let file: PolicyFile = toml::from_str(std::str::from_utf8(bytes)?).map_err(|e| Failure::new("AMBIGUOUS_MANIFEST", format!("with package.json, rivet.toml may contain only [policy]: {e}"), "Keep dependencies and scripts in package.json and only Rivet policy in rivet.toml."))?;
                Ok(file.policy)
            }).transpose()?.flatten();
            let manifest = Manifest {
                package: PackageSection {
                    name: text_field(&document, "name")?.unwrap_or_else(|| {
                        root.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned()
                    }),
                    version: text_field(&document, "version")?.unwrap_or_else(|| "0.0.0".into()),
                    description: text_field(&document, "description")?,
                    license: None,
                },
                dependencies,
                scripts,
                policy,
                ..Default::default()
            };
            Ok(Self {
                root: root.into(),
                path: json_path,
                manifest,
                document: Some(document),
                original,
                policy_original,
            })
        } else if toml_path.exists() {
            let original = fs::read(&toml_path)?;
            let manifest = Manifest::read_from(&toml_path)?;
            Ok(Self {
                root: root.into(),
                path: toml_path,
                manifest,
                document: None,
                original,
                policy_original: None,
            })
        } else {
            bail!(Failure::new(
                "PROJECT_NOT_FOUND",
                "package.json or rivet.toml not found",
                "Run in a project directory, or use rivet init."
            ))
        }
    }

    pub fn add(&mut self, alias: &str, spec: &str, dev: bool) -> Result<()> {
        validate_spec(alias, spec)?;
        if let Some(document) = &mut self.document {
            let existing_dev = document
                .get("devDependencies")
                .and_then(Value::as_object)
                .is_some_and(|m| m.contains_key(alias));
            let section = if dev || existing_dev {
                "devDependencies"
            } else {
                "dependencies"
            };
            for field in ["dependencies", "devDependencies"] {
                if let Some(map) = document.get_mut(field).and_then(Value::as_object_mut) {
                    map.remove(alias);
                }
            }
            if document.get(section).is_none() {
                document[section] = serde_json::json!({});
            }
            document[section]
                .as_object_mut()
                .context("dependencies must be an object")?
                .insert(alias.into(), Value::String(spec.into()));
        } else if dev {
            bail!(Failure::new(
                "UNSUPPORTED_PROJECT",
                "--save-dev requires package.json",
                "Use package.json to distinguish development dependencies."
            ));
        }
        self.manifest.dependencies.insert(alias.into(), spec.into());
        Ok(())
    }

    pub fn remove(&mut self, alias: &str) -> Result<()> {
        super::resolver::validate_package_name(alias)?;
        self.manifest.dependencies.remove(alias);
        if let Some(document) = &mut self.document {
            for field in ["dependencies", "devDependencies"] {
                if let Some(map) = document.get_mut(field).and_then(Value::as_object_mut) {
                    map.remove(alias);
                }
            }
        }
        Ok(())
    }

    pub fn encoded(&self) -> Result<Vec<u8>> {
        if let Some(document) = &self.document {
            Ok((serde_json::to_string_pretty(document)? + "\n").into_bytes())
        } else {
            Ok(toml::to_string_pretty(&self.manifest)?.into_bytes())
        }
    }

    pub fn assert_unchanged(&self) -> Result<()> {
        let policy = self.root.join("rivet.toml");
        let current_policy = if self.document.is_some() && policy.exists() {
            Some(fs::read(policy)?)
        } else {
            None
        };
        if fs::read(&self.path)? != self.original
            || current_policy != self.policy_original
            || (self.document.is_none() && self.root.join("package.json").exists())
        {
            bail!(Failure::new(
                "PROJECT_CHANGED",
                "project manifest or policy changed during the operation",
                "Review concurrent edits and run the command again."
            ));
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        self.assert_unchanged()?;
        atomic_write(&self.path, &self.encoded()?)
    }
}

fn text_field(document: &Value, field: &str) -> Result<Option<String>> {
    document
        .get(field)
        .map(|v| {
            v.as_str().map(String::from).ok_or_else(|| {
                Failure::new(
                    "INVALID_MANIFEST",
                    format!("{field} must be a string"),
                    "Fix package.json.",
                )
                .into()
            })
        })
        .transpose()
}

fn string_map(document: &Value, field: &str) -> Result<BTreeMap<String, String>> {
    document
        .get(field)
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|e| {
                Failure::new(
                    "INVALID_MANIFEST",
                    format!("invalid {field}: {e}"),
                    "Use an object with string values in package.json.",
                )
                .into()
            })
        })
        .unwrap_or_else(|| Ok(BTreeMap::new()))
}

pub fn validate_spec(alias: &str, spec: &str) -> Result<()> {
    let (_, range) = parse_spec(alias, spec)?;
    if range.contains([':', '/', '\\']) {
        bail!(Failure::new(
            "UNSUPPORTED_DEPENDENCY",
            format!("unsupported dependency {alias}: {spec}"),
            "Use a registry version, semver range, dist-tag, or npm: alias."
        ));
    }
    Ok(())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut staging =
        tempfile::NamedTempFile::new_in(path.parent().context("file needs a parent directory")?)?;
    if let Ok(metadata) = fs::metadata(path) {
        staging.as_file().set_permissions(metadata.permissions())?;
    }
    staging.write_all(bytes)?;
    staging.as_file().sync_all()?;
    staging.persist(path)?;
    Ok(())
}

/// Nonblocking advisory lock: agents receive a retryable error rather than
/// silently waiting or overwriting another Rivet process's project changes.
pub struct ProjectLock {
    _file: File,
}
impl ProjectLock {
    pub fn acquire(root: &Path) -> Result<Self> {
        let directory = root.join(".rivet");
        fs::create_dir_all(&directory)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("project.lock"))?;
        // SAFETY: flock borrows a live descriptor for this call. Dropping the
        // owned file releases the lock, including when the process crashes.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                bail!(Failure::new(
                    "PROJECT_BUSY",
                    "another Rivet operation is using this project",
                    "Retry with backoff after the other operation finishes."
                )
                .retry());
            }
            return Err(error.into());
        }
        Ok(Self { _file: file })
    }
}
