use std::{collections::BTreeMap, fs, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub package: PackageSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<PublisherSection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub executables: BTreeMap<String, ExecutableSection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scripts: BTreeMap<String, ScriptSection>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            package: PackageSection {
                name: "rivet-package".to_string(),
                version: "0.1.0".to_string(),
                description: None,
                license: None,
            },
            publisher: None,
            dependencies: BTreeMap::new(),
            executables: BTreeMap::new(),
            scripts: BTreeMap::new(),
        }
    }
}

impl Manifest {
    pub fn read_from(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        Ok(toml::from_str(&data)?)
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let data = toml::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageSection {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublisherSection {
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutableSection {
    pub entry: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default)]
    pub permissions: Permissions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ScriptSection {
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystem: Vec<String>,
    #[serde(default)]
    pub network: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Permissions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystem: Vec<String>,
    #[serde(default)]
    pub network: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            filesystem: vec![],
            network: false,
            env: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Manifest, PackageSection};

    #[test]
    fn manifest_round_trips_toml() {
        let manifest = Manifest {
            package: PackageSection {
                name: "demo".into(),
                version: "0.1.0".into(),
                description: Some("Demo".into()),
                license: Some("MIT".into()),
            },
            ..Manifest::default()
        };
        let toml = toml::to_string_pretty(&manifest).unwrap();
        let parsed: Manifest = toml::from_str(&toml).unwrap();
        assert_eq!(parsed, manifest);
    }
}
