//! Registry key pinning. The first time the CLI talks to a registry it pins
//! the registry's signing key (trust on first use) unless RIVET_REGISTRY_PUBKEY
//! pins it explicitly. A later key change is a hard failure until the user
//! runs `rivet trust reset`.

use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    attestation::{key_id, TrustedKey},
    paths::rivet_home,
    registry_client::RegistryClient,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedRegistry {
    pub registry: String,
    pub keyid: String,
    pub public_key: String,
    pub pinned_by: String,
}

pub fn pin_path(registry: &str) -> Result<PathBuf> {
    let digest = hex::encode(Sha256::digest(registry.as_bytes()));
    Ok(rivet_home()?
        .join("trust")
        .join(format!("{}.json", &digest[..24])))
}

pub fn read_pin(registry: &str) -> Result<Option<PinnedRegistry>> {
    let path = pin_path(registry)?;
    if !path.exists() {
        return Ok(None);
    }
    let pin: PinnedRegistry = serde_json::from_str(&fs::read_to_string(&path)?)
        .with_context(|| format!("read {}", path.display()))?;
    if pin.registry != registry {
        bail!("trust pin {} belongs to {}", path.display(), pin.registry);
    }
    Ok(Some(pin))
}

pub fn reset_pin(registry: &str) -> Result<bool> {
    let path = pin_path(registry)?;
    if path.exists() {
        fs::remove_file(path)?;
        return Ok(true);
    }
    Ok(false)
}

/// Returns the key every attestation from `client` must be signed with.
pub fn trusted_key(client: &RegistryClient) -> Result<TrustedKey> {
    let registry = client.base_url().to_string();
    let explicit = std::env::var("RIVET_REGISTRY_PUBKEY")
        .ok()
        .filter(|v| !v.is_empty());
    if let Some(public_key) = explicit {
        let keyid =
            key_id(&public_key).context("RIVET_REGISTRY_PUBKEY must be a base64 ed25519 key")?;
        if let Some(pin) = read_pin(&registry)? {
            if pin.keyid != keyid || pin.public_key != public_key {
                bail!(
                    "RIVET_REGISTRY_PUBKEY differs from the pinned registry key {} for {registry}; run `rivet trust reset` before intentionally changing keys",
                    pin.keyid
                );
            }
        }
        return Ok(TrustedKey { keyid, public_key });
    }
    if let Some(pin) = read_pin(&registry)? {
        return Ok(TrustedKey {
            keyid: pin.keyid,
            public_key: pin.public_key,
        });
    }
    let keys = client.keys().context("fetch registry signing key")?;
    let Some(key) = keys.into_iter().next() else {
        bail!("registry {registry} publishes no signing keys");
    };
    if key_id(&key.public_key)? != key.keyid {
        bail!(
            "registry key id {} does not match its public key",
            key.keyid
        );
    }
    let pin = PinnedRegistry {
        registry: registry.clone(),
        keyid: key.keyid.clone(),
        public_key: key.public_key.clone(),
        pinned_by: "trust-on-first-use".into(),
    };
    let path = pin_path(&registry)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_string_pretty(&pin)?)?;
    eprintln!(
        "rivet: pinned signing key {} for {registry} (trust on first use; set RIVET_REGISTRY_PUBKEY to pin explicitly)",
        key.keyid
    );
    Ok(key)
}
