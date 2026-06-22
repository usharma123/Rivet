use std::{collections::BTreeMap, fs, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lockfile {
    pub version: u8,
    #[serde(default)]
    pub packages: BTreeMap<String, LockedPackage>,
}

impl Default for Lockfile {
    fn default() -> Self {
        Self {
            version: 1,
            packages: BTreeMap::new(),
        }
    }
}

impl Lockfile {
    pub fn read_from(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedPackage {
    pub version: String,
    pub source: String,
    pub artifact: String,
    pub integrity: String,
    pub registry: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::{LockedPackage, Lockfile};
    use std::collections::BTreeMap;

    #[test]
    fn lockfile_serializes_expected_shape() {
        let mut lock = Lockfile::default();
        lock.packages.insert(
            "prettier".into(),
            LockedPackage {
                version: "3.5.0".into(),
                source: "npm-import".into(),
                artifact: "sha512-test".into(),
                integrity: "sha512-test".into(),
                registry: "https://registry.rivet.dev".into(),
                state: "active".into(),
                dependencies: BTreeMap::new(),
            },
        );
        let json = serde_json::to_string(&lock).unwrap();
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("\"prettier\""));
    }
}
