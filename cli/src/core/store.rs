use std::{fs, path::PathBuf};

use anyhow::Result;

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
}
