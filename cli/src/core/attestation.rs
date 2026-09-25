//! Signed release statements from the registry. Mirrors
//! registry/internal/attest. Every install and every run verifies these with
//! the pinned registry key; nothing the CLI enforces comes from unsigned data.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const PAYLOAD_TYPE: &str = "application/vnd.rivet.release+json";
pub const STATEMENT_TYPE: &str = "https://rivet.dev/attestation/release/v1";
const PAYLOAD_DOMAIN: &[u8] = b"rivet-attestation-v1\n";
/// Tolerated clock skew between client and registry.
const CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub payload_type: String,
    pub payload: String,
    pub keyid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedKey {
    pub keyid: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub kind: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub state: String,
    pub artifact: ArtifactRef,
    pub manifest: PackageManifest,
    #[serde(default)]
    pub executables: Vec<Executable>,
    #[serde(default)]
    pub publisher: String,
    pub published_at: String,
    #[serde(default)]
    pub upstream: Option<Upstream>,
    #[serde(default)]
    pub provenance: Option<Provenance>,
    #[serde(default)]
    pub audit: Option<AuditSummary>,
    #[serde(default)]
    pub revoke_reason: String,
    #[serde(default)]
    pub replacement_version: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRef {
    pub hash: String,
    pub size: u64,
    pub tree_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_optional: Vec<String>,
    #[serde(default)]
    pub bin: BTreeMap<String, String>,
    #[serde(default)]
    pub os: Vec<String>,
    #[serde(default)]
    pub cpu: Vec<String>,
    #[serde(default)]
    pub install_scripts: BTreeMap<String, String>,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub repository: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Executable {
    pub command: String,
    pub entry: String,
    #[serde(default)]
    pub permissions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Upstream {
    #[serde(default)]
    pub registry: String,
    #[serde(default)]
    pub tarball: String,
    #[serde(default)]
    pub integrity: String,
    #[serde(default)]
    pub integrity_algorithm: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub published_at: String,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub manifest_mismatch: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Provenance {
    pub status: String,
    #[serde(default)]
    pub source_repo: String,
    #[serde(default)]
    pub source_commit: String,
    #[serde(default)]
    pub source_ref: String,
    #[serde(default)]
    pub build_signer: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub declared_repo: String,
    #[serde(default)]
    pub repo_matches: Option<bool>,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditSummary {
    pub id: String,
    pub status: String,
    pub verdict: String,
    pub risk_score: u16,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub sandbox_runtime: String,
    #[serde(default)]
    pub agent_image: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub diff: Option<AuditDiff>,
    #[serde(default)]
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditDiff {
    pub previous_version: String,
    #[serde(default)]
    pub new_capabilities: Vec<String>,
    #[serde(default)]
    pub new_install_scripts: Vec<String>,
    #[serde(default)]
    pub added_dependencies: Vec<String>,
    #[serde(default)]
    pub removed_dependencies: Vec<String>,
    #[serde(default)]
    pub publisher_changed: bool,
    #[serde(default)]
    pub provenance_regressed: bool,
}

impl PackageManifest {
    /// The declared spec for a dependency alias of any kind.
    pub fn dependency_spec(&self, alias: &str) -> Option<&String> {
        self.dependencies
            .get(alias)
            .or_else(|| self.optional_dependencies.get(alias))
            .or_else(|| self.peer_dependencies.get(alias))
    }
}

impl Statement {
    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    pub fn issued_at(&self) -> Result<OffsetDateTime> {
        OffsetDateTime::parse(&self.issued_at, &Rfc3339).context("parse issued_at")
    }

    pub fn expires_at(&self) -> Result<OffsetDateTime> {
        OffsetDateTime::parse(&self.expires_at, &Rfc3339).context("parse expires_at")
    }

    pub fn verdict(&self) -> &str {
        self.audit
            .as_ref()
            .map(|a| a.verdict.as_str())
            .unwrap_or("unaudited")
    }

    pub fn provenance_status(&self) -> &str {
        self.provenance
            .as_ref()
            .map(|p| p.status.as_str())
            .unwrap_or("absent")
    }
}

impl Envelope {
    /// Verifies the signature and freshness, returning the statement.
    pub fn verify(&self, key: &TrustedKey, now: OffsetDateTime) -> Result<Statement> {
        let statement = self.verify_signature(key)?;
        let issued = statement.issued_at()?;
        let expires = statement.expires_at()?;
        let skew = time::Duration::seconds(CLOCK_SKEW_SECONDS);
        if now + skew < issued {
            bail!(
                "attestation for {} is issued in the future ({}); check the system clock",
                statement.id(),
                statement.issued_at
            );
        }
        if now - skew > expires {
            bail!(
                "attestation for {} expired at {}; reconnect to the registry to refresh it",
                statement.id(),
                statement.expires_at
            );
        }
        Ok(statement)
    }

    /// Verifies only the signature. Used when reading cached statements whose
    /// expiry is checked separately.
    pub fn verify_signature(&self, key: &TrustedKey) -> Result<Statement> {
        if self.payload_type != PAYLOAD_TYPE {
            bail!("unexpected attestation payload type {}", self.payload_type);
        }
        if self.keyid != key.keyid {
            bail!(
                "attestation signed by key {} but the pinned registry key is {}; run `rivet trust show`",
                self.keyid,
                key.keyid
            );
        }
        let public = STANDARD
            .decode(&key.public_key)
            .context("decode pinned public key")?;
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| anyhow::anyhow!("pinned public key has the wrong length"))?;
        let verifying = VerifyingKey::from_bytes(&public).context("invalid pinned public key")?;
        let payload = STANDARD.decode(&self.payload).context("decode payload")?;
        let signature = STANDARD
            .decode(&self.signature)
            .context("decode signature")?;
        let signature =
            Signature::from_slice(&signature).context("attestation signature is malformed")?;
        let mut message = PAYLOAD_DOMAIN.to_vec();
        message.extend_from_slice(&payload);
        verifying
            .verify(&message, &signature)
            .context("attestation signature is invalid")?;
        let statement: Statement =
            serde_json::from_slice(&payload).context("decode attestation statement")?;
        if statement.kind != STATEMENT_TYPE {
            bail!("unexpected statement type {}", statement.kind);
        }
        Ok(statement)
    }
}

/// Computes the key id the registry uses: "ed25519:" + first 32 hex chars of
/// sha256(public key).
pub fn key_id(public_key_b64: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    let raw = STANDARD.decode(public_key_b64)?;
    Ok(format!(
        "ed25519:{}",
        &hex::encode(Sha256::digest(raw))[..32]
    ))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn test_key() -> (SigningKey, TrustedKey) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = STANDARD.encode(signing.verifying_key().to_bytes());
        let keyid = key_id(&public).unwrap();
        (
            signing,
            TrustedKey {
                keyid,
                public_key: public,
            },
        )
    }

    pub fn sample_statement(name: &str, version: &str) -> Statement {
        Statement {
            kind: STATEMENT_TYPE.into(),
            name: name.into(),
            version: version.into(),
            source: "npm".into(),
            state: "active".into(),
            artifact: ArtifactRef {
                hash: "sha512-abc".into(),
                size: 10,
                tree_digest: "rivet-tree-v1:sha256:abc".into(),
            },
            manifest: PackageManifest {
                name: name.into(),
                version: version.into(),
                ..Default::default()
            },
            executables: vec![],
            publisher: "npm:someone".into(),
            published_at: "2026-01-01T00:00:00Z".into(),
            upstream: None,
            provenance: None,
            audit: Some(AuditSummary {
                id: "audit-1".into(),
                status: "passed".into(),
                verdict: "low".into(),
                risk_score: 5,
                sandbox_runtime: "none/static-analysis".into(),
                ..Default::default()
            }),
            revoke_reason: String::new(),
            replacement_version: String::new(),
            issued_at: "2026-09-25T00:00:00Z".into(),
            expires_at: "2026-10-02T00:00:00Z".into(),
        }
    }

    pub fn seal(signing: &SigningKey, keyid: &str, statement: &Statement) -> Envelope {
        let payload = serde_json::to_vec(statement).unwrap();
        let mut message = PAYLOAD_DOMAIN.to_vec();
        message.extend_from_slice(&payload);
        Envelope {
            payload_type: PAYLOAD_TYPE.into(),
            payload: STANDARD.encode(&payload),
            keyid: keyid.into(),
            signature: STANDARD.encode(signing.sign(&message).to_bytes()),
        }
    }

    fn at(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &Rfc3339).unwrap()
    }

    #[test]
    fn verifies_signed_statement() {
        let (signing, key) = test_key();
        let envelope = seal(&signing, &key.keyid, &sample_statement("demo", "1.0.0"));
        let statement = envelope.verify(&key, at("2026-09-26T00:00:00Z")).unwrap();
        assert_eq!(statement.id(), "demo@1.0.0");
    }

    #[test]
    fn rejects_tampered_payload() {
        let (signing, key) = test_key();
        let mut envelope = seal(&signing, &key.keyid, &sample_statement("demo", "1.0.0"));
        let mut statement = sample_statement("demo", "1.0.0");
        statement.state = "active".into();
        statement.artifact.hash = "sha512-evil".into();
        envelope.payload = STANDARD.encode(serde_json::to_vec(&statement).unwrap());
        assert!(envelope.verify(&key, at("2026-09-26T00:00:00Z")).is_err());
    }

    #[test]
    fn rejects_other_keys_and_expired_statements() {
        let (signing, key) = test_key();
        let envelope = seal(&signing, &key.keyid, &sample_statement("demo", "1.0.0"));
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let other_key = TrustedKey {
            keyid: key.keyid.clone(),
            public_key: STANDARD.encode(other.verifying_key().to_bytes()),
        };
        assert!(envelope
            .verify(&other_key, at("2026-09-26T00:00:00Z"))
            .is_err());
        let err = envelope
            .verify(&key, at("2026-10-05T00:00:00Z"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn key_id_matches_registry_format() {
        // Same seed as the registry's signing tests: bytes.Repeat([]byte{7}, 32).
        let (_, key) = test_key();
        assert!(key.keyid.starts_with("ed25519:"));
        assert_eq!(key.keyid.len(), "ed25519:".len() + 32);
    }
}
