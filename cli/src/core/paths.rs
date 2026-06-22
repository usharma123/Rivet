use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde_json::json;

pub struct ProjectPaths {
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub lockfile: PathBuf,
    pub metadata_dir: PathBuf,
}

impl ProjectPaths {
    pub fn from_current_dir() -> Result<Self> {
        let root = env::current_dir()?;
        Ok(Self::from_root(root))
    }

    pub fn from_root(root: PathBuf) -> Self {
        Self {
            manifest: root.join("rivet.toml"),
            lockfile: root.join("rivet.lock"),
            metadata_dir: root.join(".rivet"),
            root,
        }
    }

    pub fn ensure_metadata(&self) -> Result<()> {
        fs::create_dir_all(&self.metadata_dir)?;
        write_json_if_missing(
            &self.metadata_dir.join("graph.json"),
            &json!({"packages": []}),
        )?;
        write_json_if_missing(
            &self.metadata_dir.join("install-plan.json"),
            &json!({"version": 1, "steps": []}),
        )?;
        Ok(())
    }
}

pub fn rivet_home() -> Result<PathBuf> {
    if let Ok(value) = env::var("RIVET_HOME") {
        return Ok(PathBuf::from(value));
    }
    dirs::home_dir()
        .map(|home| home.join(".rivet"))
        .context("could not determine home directory")
}

fn write_json_if_missing(path: &Path, value: &serde_json::Value) -> Result<()> {
    if !path.exists() {
        fs::write(path, serde_json::to_string_pretty(value)?)?;
    }
    Ok(())
}
