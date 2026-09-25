//! rivet.lock v2: the fully resolved dependency graph, pinned to artifact
//! hashes and tree digests signed by one registry key.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const LOCKFILE_VERSION: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lockfile {
    pub version: u8,
    #[serde(default)]
    pub registry: String,
    #[serde(default)]
    pub registry_key: String,
    #[serde(default)]
    pub roots: BTreeMap<String, LockedRoot>,
    #[serde(default)]
    pub packages: BTreeMap<String, LockedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedRoot {
    pub spec: String,
    pub package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub artifact: String,
    pub tree_digest: String,
    pub state: String,
    pub verdict: String,
    pub provenance: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub install_scripts: Vec<String>,
}

impl Default for Lockfile {
    fn default() -> Self {
        Self {
            version: LOCKFILE_VERSION,
            registry: String::new(),
            registry_key: String::new(),
            roots: BTreeMap::new(),
            packages: BTreeMap::new(),
        }
    }
}

impl Lockfile {
    /// Reads a lockfile. Returns None for missing or pre-v2 lockfiles, which
    /// carry no signed identities and must be re-resolved.
    pub fn read_current(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        let value: serde_json::Value =
            serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
        if value.get("version").and_then(serde_json::Value::as_u64) != Some(LOCKFILE_VERSION as u64)
        {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(value)?))
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data + "\n")?;
        Ok(())
    }

    /// Drops packages no root can reach and returns their ids.
    pub fn retain_reachable(&mut self) -> Vec<String> {
        let mut reachable = std::collections::BTreeSet::new();
        let mut stack: Vec<String> = self.roots.values().map(|r| r.package.clone()).collect();
        while let Some(id) = stack.pop() {
            if reachable.insert(id.clone()) {
                if let Some(package) = self.packages.get(&id) {
                    stack.extend(package.dependencies.values().cloned());
                }
            }
        }
        let orphans: Vec<String> = self
            .packages
            .keys()
            .filter(|id| !reachable.contains(*id))
            .cloned()
            .collect();
        for id in &orphans {
            self.packages.remove(id);
        }
        orphans
    }

    /// True when every manifest dependency is locked with the same spec.
    pub fn satisfies(&self, dependencies: &BTreeMap<String, String>) -> bool {
        dependencies.len() == self.roots.len()
            && dependencies.iter().all(|(alias, spec)| {
                self.roots.get(alias).is_some_and(|root| {
                    &root.spec == spec && self.packages.contains_key(&root.package)
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_round_trips_and_detects_staleness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rivet.lock");
        let mut lock = Lockfile::default();
        lock.roots.insert(
            "prettier".into(),
            LockedRoot {
                spec: "^3.0.0".into(),
                package: "prettier@3.5.0".into(),
            },
        );
        lock.packages.insert(
            "prettier@3.5.0".into(),
            LockedPackage {
                name: "prettier".into(),
                version: "3.5.0".into(),
                artifact: "sha512-x".into(),
                tree_digest: "rivet-tree-v1:sha256:y".into(),
                state: "active".into(),
                verdict: "low".into(),
                provenance: "absent".into(),
                dependencies: BTreeMap::new(),
                optional: false,
                install_scripts: vec![],
            },
        );
        lock.write_to(&path).unwrap();
        let read = Lockfile::read_current(&path).unwrap().unwrap();
        assert_eq!(read, lock);
        let mut deps = BTreeMap::from([("prettier".to_string(), "^3.0.0".to_string())]);
        assert!(read.satisfies(&deps));
        deps.insert("react".into(), "^19".into());
        assert!(!read.satisfies(&deps));
    }

    #[test]
    fn v1_lockfiles_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rivet.lock");
        fs::write(&path, r#"{"version":1,"packages":{"a":{"version":"1"}}}"#).unwrap();
        assert!(Lockfile::read_current(&path).unwrap().is_none());
    }
}
