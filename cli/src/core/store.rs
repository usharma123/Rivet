use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::paths::rivet_home;

#[derive(Debug, Clone)]
pub struct LocalStore {
    pub home: PathBuf,
    pub store_dir: PathBuf,
    pub bin_dir: PathBuf,
    pub index_dir: PathBuf,
}

impl LocalStore {
    pub fn from_env() -> Result<Self> {
        let home = rivet_home()?;
        Ok(Self {
            store_dir: home.join("store"),
            bin_dir: home.join("bin"),
            index_dir: home.join("index"),
            home,
        })
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.home)?;
        fs::create_dir_all(&self.store_dir)?;
        fs::create_dir_all(&self.bin_dir)?;
        fs::create_dir_all(&self.index_dir)?;
        fs::create_dir_all(self.index_dir.join("packages"))?;
        fs::create_dir_all(self.index_dir.join("commands"))?;
        Ok(())
    }

    pub fn artifact_dir(&self, artifact_hash: &str) -> PathBuf {
        self.store_dir.join(artifact_hash)
    }

    pub fn package_json_path(&self, name: &str, version: &str) -> PathBuf {
        self.index_dir
            .join("packages")
            .join(format!("{}@{}.json", safe_id(name), version))
    }

    pub fn latest_package_json_path(&self, name: &str) -> PathBuf {
        self.index_dir
            .join("packages")
            .join(format!("{}.json", safe_id(name)))
    }

    pub fn command_json_path(&self, command: &str) -> PathBuf {
        self.index_dir
            .join("commands")
            .join(format!("{}.json", safe_id(command)))
    }

    pub fn write_package(&self, package: &StoredPackage) -> Result<()> {
        self.ensure()?;
        write_json(
            &self.package_json_path(&package.name, &package.version),
            package,
        )?;
        write_json(&self.latest_package_json_path(&package.name), package)?;
        for executable in &package.executables {
            let command = StoredCommand {
                command: executable.command.clone(),
                package: package.name.clone(),
                version: package.version.clone(),
            };
            write_json(&self.command_json_path(&executable.command), &command)?;
        }
        Ok(())
    }

    pub fn read_package(&self, name: &str, version: Option<&str>) -> Result<StoredPackage> {
        let path = match version {
            Some(version) => self.package_json_path(name, version),
            None => self.latest_package_json_path(name),
        };
        let data = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn read_command(&self, command: &str) -> Result<StoredCommand> {
        let data = fs::read_to_string(self.command_json_path(command))?;
        Ok(serde_json::from_str(&data)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredPackage {
    pub name: String,
    pub version: String,
    pub source: String,
    pub state: String,
    pub artifact: String,
    pub integrity: String,
    pub registry: String,
    pub package_dir: PathBuf,
    pub manifest: serde_json::Value,
    pub package_json: serde_json::Value,
    pub executables: Vec<StoredExecutable>,
    pub dependencies: std::collections::BTreeMap<String, String>,
    pub risk_score: u8,
    pub risk_reasons: Vec<String>,
    #[serde(default)]
    pub artifact_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_published_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,
    #[serde(default)]
    pub source_visibility: String,
    #[serde(default)]
    pub has_native_binaries: bool,
    #[serde(default)]
    pub has_install_scripts: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_audit: Option<StoredAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredExecutable {
    pub command: String,
    pub entry: String,
    pub summary: Option<String>,
    pub permissions: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCommand {
    pub command: String,
    pub package: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAudit {
    pub id: Option<String>,
    pub status: String,
    pub sandbox_runtime: String,
    pub agent_image: String,
    pub verdict: String,
    pub risk_score: u16,
    pub reasons: Vec<String>,
    pub suggested_actions: Vec<String>,
    pub signature: String,
    pub cost_cents: u16,
    pub release_state_applied: Option<String>,
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::safe_id;

    #[test]
    fn safe_id_removes_path_separators() {
        assert_eq!(safe_id("@scope/pkg"), "_scope_pkg");
    }
}
