use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct RegistryClient {
    base_url: String,
    token: String,
    client: Client,
}

impl RegistryClient {
    pub fn from_env() -> Result<Self> {
        let base_url = std::env::var("RIVET_REGISTRY_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());
        let token = std::env::var("RIVET_REGISTRY_TOKEN")
            .context("RIVET_REGISTRY_TOKEN is required for registry writes")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client: Client::new(),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn put_artifact(&self, hash: &str, bytes: &[u8]) -> Result<()> {
        let url = format!("{}/v1/artifacts/{}", self.base_url, hash);
        self.client
            .put(url)
            .bearer_auth(&self.token)
            .body(bytes.to_vec())
            .send()
            .context("upload artifact")?
            .error_for_status()
            .context("artifact upload response")?;
        Ok(())
    }

    pub fn import_npm<T: Serialize>(&self, request: &T) -> Result<serde_json::Value> {
        self.post("/v1/import/npm", request)
    }

    pub fn post<T: Serialize>(&self, path: &str, request: &T) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .json(request)
            .send()
            .context("registry request")?;
        let status = response.status();
        let value: serde_json::Value = response.json().unwrap_or_else(|_| serde_json::json!({}));
        if !status.is_success() {
            bail!("registry request failed ({status}): {value}");
        }
        Ok(value)
    }
}
