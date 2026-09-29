//! rivet.lock v3: pinned graphs for the supported runtime targets.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const LOCKFILE_VERSION: u8 = 3;

pub const TARGETS: [&str; 4] = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct LockVariant {
    pub roots: BTreeMap<String, LockedRoot>,
    pub packages: BTreeMap<String, LockedPackage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Complete target-specific graphs. Empty only in an installed receipt.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variants: BTreeMap<String, LockVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LockedRoot {
    pub spec: String,
    pub package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Peer alias to contextual provider instance, separate from signed release id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_bindings: BTreeMap<String, String>,
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
            variants: BTreeMap::new(),
        }
    }
}

impl Lockfile {
    /// Reads a lockfile. Version 2 is returned for explicit migration handling.
    pub fn read_current(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        let value: serde_json::Value =
            serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
        let version = value.get("version").and_then(serde_json::Value::as_u64);
        if !matches!(version, Some(2 | 3)) {
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
        if self.version != LOCKFILE_VERSION
            || self.variants.len() != TARGETS.len()
            || self.registry.is_empty()
            || self.registry_key.is_empty()
            || !self.roots.is_empty()
            || !self.packages.is_empty()
        {
            return false;
        }
        TARGETS.iter().all(|target| {
            self.variants.get(*target).is_some_and(|variant| {
                (variant.unsupported.is_none()
                    || (variant.roots.is_empty() && variant.packages.is_empty()))
                    && (variant.unsupported.is_some() || variant.roots.len() == dependencies.len())
                    && dependencies.iter().all(|(alias, spec)| {
                        variant.unsupported.is_some()
                            || variant.roots.get(alias).is_some_and(|root| {
                                &root.spec == spec && variant.packages.contains_key(&root.package)
                            })
                    })
            })
        })
    }

    pub fn selected(&self, target: &str) -> Result<Self> {
        if self.version != LOCKFILE_VERSION {
            anyhow::bail!("rivet.lock v2 has no portable target pins; run `rivet install` to regenerate v3 before using --frozen");
        }
        if self.registry.is_empty() || self.registry_key.is_empty() {
            anyhow::bail!("portable rivet.lock must pin its registry and signing key");
        }
        if self.variants.len() != TARGETS.len()
            || TARGETS
                .iter()
                .any(|target| !self.variants.contains_key(*target))
        {
            anyhow::bail!("portable rivet.lock is missing a supported target graph");
        }
        if !self.roots.is_empty() || !self.packages.is_empty() {
            anyhow::bail!("portable rivet.lock contains host-specific top-level graph data");
        }
        let variant = self.variants.get(target).with_context(|| {
            format!("rivet.lock has no pinned graph for {target}; run `rivet install` on a supported target")
        })?;
        if let Some(reason) = &variant.unsupported {
            anyhow::bail!("rivet.lock marks {target} unsupported: {reason}");
        }
        Ok(Self {
            version: self.version,
            registry: self.registry.clone(),
            registry_key: self.registry_key.clone(),
            roots: variant.roots.clone(),
            packages: variant.packages.clone(),
            variants: BTreeMap::new(),
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
        let mut lock = Lockfile {
            registry: "https://registry.example.test".into(),
            registry_key: "test-key".into(),
            ..Lockfile::default()
        };
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
                peer_bindings: BTreeMap::new(),
                optional: false,
                install_scripts: vec![],
            },
        );
        for target in TARGETS {
            lock.variants.insert(
                target.into(),
                LockVariant {
                    roots: lock.roots.clone(),
                    packages: lock.packages.clone(),
                    unsupported: None,
                },
            );
        }
        lock.roots.clear();
        lock.packages.clear();
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
