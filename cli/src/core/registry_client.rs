use std::{collections::BTreeMap, io::Read, time::Duration};

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};

use super::attestation::{Envelope, TrustedKey};

const MAX_ARTIFACT_BYTES: u64 = 256 << 20;

#[derive(Debug, Clone)]
pub struct RegistryClient {
    base_url: String,
    token: Option<String>,
    client: Client,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionResponse {
    pub attestation: Envelope,
    #[serde(default)]
    pub skipped: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchResponse {
    #[serde(default)]
    pub attestations: BTreeMap<String, Envelope>,
    #[serde(default)]
    pub errors: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct ResolveRequest<'a> {
    name: &'a str,
    spec: &'a str,
    min_age_hours: f64,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    prefer: &'a [String],
}

impl RegistryClient {
    pub fn from_env() -> Result<Self> {
        let base_url = std::env::var("RIVET_REGISTRY_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());
        let token = std::env::var("RIVET_REGISTRY_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        Self::new(&base_url, token)
    }

    pub fn new(base_url: &str, token: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client,
        })
    }

    pub fn require_token(&self) -> Result<()> {
        if self.token.is_none() {
            bail!("RIVET_REGISTRY_TOKEN is required for this registry operation");
        }
        Ok(())
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    pub fn keys(&self) -> Result<Vec<TrustedKey>> {
        #[derive(Deserialize)]
        struct Keys {
            keys: Vec<TrustedKey>,
        }
        let keys: Keys = serde_json::from_value(self.get("/v1/keys")?)?;
        Ok(keys.keys)
    }

    pub fn resolve(
        &self,
        name: &str,
        spec: &str,
        min_age_hours: f64,
        prefer: &[String],
    ) -> Result<VersionResponse> {
        let value = self.post(
            "/v1/npm/resolve",
            &ResolveRequest {
                name,
                spec,
                min_age_hours,
                prefer,
            },
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn attestation(&self, name: &str, version: &str) -> Result<Envelope> {
        let value = self.get(&format!(
            "/v1/packages/{}/{}/attestation",
            urlencoding::encode(name),
            urlencoding::encode(version)
        ))?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn attestations(&self, packages: &[(String, String)]) -> Result<BatchResponse> {
        let body = serde_json::json!({
            "packages": packages
                .iter()
                .map(|(name, version)| serde_json::json!({"name": name, "version": version}))
                .collect::<Vec<_>>(),
        });
        Ok(serde_json::from_value(
            self.post("/v1/attestations", &body)?,
        )?)
    }

    pub fn download_artifact(&self, hash: &str) -> Result<Vec<u8>> {
        let url = format!("{}/v1/artifacts/{}", self.base_url, hash);
        let response = self
            .client
            .get(url)
            .send()
            .context("download artifact")?
            .error_for_status()
            .context("artifact download response")?;
        let mut bytes = Vec::new();
        response
            .take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            bail!("artifact {hash} exceeds size limit");
        }
        Ok(bytes)
    }

    pub fn put_artifact(&self, hash: &str, bytes: &[u8]) -> Result<()> {
        self.require_token()?;
        let url = format!("{}/v1/artifacts/{}", self.base_url, hash);
        let response = self
            .auth(self.client.put(url))
            .body(bytes.to_vec())
            .send()
            .context("upload artifact")?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            bail!("artifact upload failed ({status}): {body}");
        }
        Ok(())
    }

    pub fn trigger_audit(&self, package: &str, version: &str) -> Result<serde_json::Value> {
        self.require_token()?;
        let package = urlencoding::encode(package);
        let version = urlencoding::encode(version);
        self.post(
            &format!("/v1/packages/{package}/{version}/audits"),
            &serde_json::json!({}),
        )
    }

    pub fn package_action<T: Serialize>(
        &self,
        package: &str,
        version: &str,
        action: &str,
        request: &T,
    ) -> Result<serde_json::Value> {
        self.require_token()?;
        let package = urlencoding::encode(package);
        let version = urlencoding::encode(version);
        self.post(
            &format!("/v1/packages/{package}/{version}/{action}"),
            request,
        )
    }

    pub fn post<T: Serialize>(&self, path: &str, request: &T) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .auth(self.client.post(url))
            .json(request)
            .send()
            .with_context(|| format!("registry request to {}", self.base_url))?;
        let status = response.status();
        let value: serde_json::Value = response.json().unwrap_or_else(|_| serde_json::json!({}));
        if !status.is_success() {
            let message = value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| value.to_string());
            bail!("registry request failed ({status}): {message}");
        }
        Ok(value)
    }

    pub fn get(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(url)
            .send()
            .with_context(|| format!("registry request to {}", self.base_url))?;
        let status = response.status();
        let value: serde_json::Value = response.json().unwrap_or_else(|_| serde_json::json!({}));
        if !status.is_success() {
            let message = value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| value.to_string());
            bail!("registry request failed ({status}): {message}");
        }
        Ok(value)
    }
}
