use std::{collections::BTreeMap, fs, path::PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::paths::rivet_home;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ByokConfig {
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider: String,
    pub key_env: String,
    pub endpoint: String,
}

impl ByokConfig {
    pub fn read() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn write(&self) -> Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

pub fn default_provider(provider: &str) -> ProviderConfig {
    let upper = provider.to_ascii_uppercase().replace('-', "_");
    ProviderConfig {
        provider: provider.to_string(),
        key_env: format!("{upper}_API_KEY"),
        endpoint: match provider {
            "openai" => "https://api.openai.com/v1".to_string(),
            "anthropic" => "https://api.anthropic.com".to_string(),
            _ => "local".to_string(),
        },
    }
}

fn config_path() -> Result<PathBuf> {
    Ok(rivet_home()?.join("config.json"))
}
