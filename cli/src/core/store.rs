//! Local content-addressed store. Packages live under their artifact hash,
//! are written read-only, and are only ever populated from bytes whose sha512
//! and tree digest match a verified registry statement.

use std::{
    fs::{self, OpenOptions},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    artifact::sha512_hex,
    attestation::{Envelope, Statement, TrustedKey},
    linker::InstalledState,
    paths::rivet_home,
    registry_client::RegistryClient,
    tree,
};

#[derive(Debug, Clone)]
pub struct LocalStore {
    pub registry: String,
    pub home: PathBuf,
    pub store_dir: PathBuf,
    pub attestation_dir: PathBuf,
    pub tools_dir: PathBuf,
    pub index_dir: PathBuf,
}

/// Where a globally imported command lives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCommand {
    pub command: String,
    pub package: String,
    pub version: String,
    pub tool_dir: PathBuf,
}

impl LocalStore {
    /// The store under RIVET_HOME, namespaced for `registry`.
    pub fn open(registry: &str) -> Result<Self> {
        let home = rivet_home()?;
        Ok(Self {
            registry: registry.to_string(),
            store_dir: home.join("store").join("v2"),
            attestation_dir: home.join("attestations"),
            tools_dir: home.join("tools"),
            index_dir: home.join("index"),
            home,
        })
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [
            &self.home,
            &self.store_dir,
            &self.attestation_dir,
            &self.tools_dir,
            &self.index_dir.join("commands"),
        ] {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn package_dir(&self, artifact_hash: &str) -> Result<PathBuf> {
        let hex = artifact_hash
            .strip_prefix("sha512-")
            .filter(|h| h.len() == 128 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .with_context(|| format!("invalid artifact hash {artifact_hash}"))?;
        Ok(self.store_dir.join(&hex[..2]).join(hex).join("package"))
    }

    /// Makes sure the verified package is in the store and returns its
    /// directory. Existing entries are re-hashed; corrupt ones are replaced.
    pub fn ensure_package(
        &self,
        client: &RegistryClient,
        statement: &Statement,
    ) -> Result<PathBuf> {
        let dir = self.package_dir(&statement.artifact.hash)?;
        if dir.exists() {
            if tree::tree_digest_of_dir(&dir).ok().as_deref()
                == Some(statement.artifact.tree_digest.as_str())
            {
                return Ok(dir);
            }
            eprintln!(
                "rivet: store entry for {} is corrupt; re-downloading",
                statement.id()
            );
            remove_tree(dir.parent().unwrap_or(&dir))?;
        }
        let bytes = client
            .download_artifact(&statement.artifact.hash)
            .with_context(|| format!("download {}", statement.id()))?;
        if sha512_hex(&bytes) != statement.artifact.hash {
            bail!(
                "artifact for {} does not match its signed hash; refusing to install",
                statement.id()
            );
        }
        let package = tree::read_tarball(&bytes)?;
        if package.tree_digest != statement.artifact.tree_digest {
            bail!(
                "contents of {} do not match the signed tree digest; refusing to install",
                statement.id()
            );
        }
        let parent = dir.parent().context("store path has no parent")?;
        fs::create_dir_all(parent.parent().unwrap_or(parent))?;
        let staging = parent.with_extension(format!("tmp-{}", std::process::id()));
        if staging.exists() {
            remove_tree(&staging)?;
        }
        tree::write_package(&package, &staging.join("package"))?;
        match fs::rename(&staging, parent) {
            Ok(()) => {}
            Err(_) if dir.exists() => remove_tree(&staging)?,
            Err(err) => return Err(err).context("move package into store"),
        }
        Ok(dir)
    }

    /// Short, stable directory name for this store's registry, so caches and
    /// command indexes from different registries never mix.
    fn registry_scope(&self) -> String {
        hex::encode(Sha256::digest(self.registry.as_bytes()))[..24].to_string()
    }

    fn attestation_path(&self, name: &str, version: &str, key: &TrustedKey) -> PathBuf {
        let scope = hex::encode(Sha256::digest(
            format!("{}\0{}\0{}", self.registry, key.keyid, key.public_key).as_bytes(),
        ));
        self.attestation_dir.join(scope).join(format!(
            "{}@{}.json",
            safe_id(name),
            safe_id(version)
        ))
    }

    /// Caches a verified envelope. A cached statement is never replaced by an
    /// older one, which prevents replaying a stale "active" statement after a
    /// release was revoked.
    pub fn cache_attestation(
        &self,
        statement: &Statement,
        envelope: &Envelope,
        key: &TrustedKey,
    ) -> Result<()> {
        let path = self.attestation_path(&statement.name, &statement.version, key);
        let parent = path.parent().context("attestation path has no parent")?;
        fs::create_dir_all(parent)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("lock attestation cache");
        }
        if let Some((existing, _)) =
            self.cached_attestation(&statement.name, &statement.version, key)?
        {
            if existing.issued_at()? > statement.issued_at()? {
                bail!(
                    "attestation rollback for {}: a newer statement is cached",
                    statement.id()
                );
            }
            if existing.issued_at()? == statement.issued_at()? && existing != *statement {
                bail!(
                    "conflicting attestations share issued_at for {}",
                    statement.id()
                );
            }
            if existing.artifact != statement.artifact {
                bail!(
                    "registry changed the artifact for {} (was {}, now {}); refusing",
                    statement.id(),
                    existing.artifact.hash,
                    statement.artifact.hash
                );
            }
        }
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(&mut temp, envelope)?;
        temp.persist(&path)
            .map_err(|err| err.error)
            .context("replace attestation cache")?;
        Ok(())
    }

    /// Returns a cached statement whose signature verifies (expiry unchecked).
    pub fn cached_attestation(
        &self,
        name: &str,
        version: &str,
        key: &TrustedKey,
    ) -> Result<Option<(Statement, Envelope)>> {
        let path = self.attestation_path(name, version, key);
        if !path.exists() {
            return Ok(None);
        }
        let envelope: Envelope = serde_json::from_str(&fs::read_to_string(&path)?)?;
        let statement = envelope.verify_signature(key).with_context(|| {
            format!(
                "cached attestation {} is not validly signed",
                path.display()
            )
        })?;
        if statement.name != name || statement.version != version {
            bail!(
                "cached attestation {} names {}",
                path.display(),
                statement.id()
            );
        }
        Ok(Some((statement, envelope)))
    }

    pub fn tool_dir(&self, name: &str, version: &str) -> PathBuf {
        self.tools_dir.join(self.registry_scope()).join(format!(
            "{}@{}",
            safe_id(name),
            safe_id(version)
        ))
    }

    fn receipt_path(&self, root: &Path, key: &TrustedKey) -> Result<PathBuf> {
        let root = root.canonicalize().context("canonicalize install root")?;
        let identity = format!("{}\0{}\0{}", self.registry, key.keyid, root.display());
        let digest = hex::encode(Sha256::digest(identity.as_bytes()));
        Ok(self.home.join("receipts").join(format!("{digest}.json")))
    }

    pub fn write_install_receipt(
        &self,
        root: &Path,
        key: &TrustedKey,
        state: &InstalledState,
    ) -> Result<()> {
        let path = self.receipt_path(root, key)?;
        let parent = path.parent().context("receipt has no parent")?;
        fs::create_dir_all(parent)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(&mut temp, state)?;
        temp.persist(&path)
            .map_err(|err| err.error)
            .context("activate install receipt")?;
        Ok(())
    }

    pub fn read_install_receipt(
        &self,
        root: &Path,
        key: &TrustedKey,
    ) -> Result<Option<InstalledState>> {
        let path = self.receipt_path(root, key)?;
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }

    fn command_path(&self, command: &str) -> PathBuf {
        self.index_dir
            .join("commands")
            .join(self.registry_scope())
            .join(format!("{}.json", safe_id(command)))
    }

    pub fn write_command(&self, command: &StoredCommand) -> Result<()> {
        let path = self.command_path(&command.command);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(command)?)?;
        Ok(())
    }

    pub fn read_command(&self, command: &str) -> Result<StoredCommand> {
        let data = fs::read_to_string(self.command_path(command))?;
        Ok(serde_json::from_str(&data)?)
    }
}

/// Removes a directory tree that may contain read-only files and dirs.
pub fn remove_tree(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if !path.exists() && fs::symlink_metadata(path).is_err() {
        return Ok(());
    }
    for entry in walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if entry.file_type().is_dir() {
            let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o755));
        }
    }
    if fs::symlink_metadata(path)?.is_dir() {
        fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))
    } else {
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))
    }
}

/// Injective file-system encoding for package identities.
pub fn safe_id(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::attestation::tests::{sample_statement, seal, test_key};

    fn store(dir: &Path) -> LocalStore {
        LocalStore {
            registry: "http://registry.test".into(),
            home: dir.to_path_buf(),
            store_dir: dir.join("store"),
            attestation_dir: dir.join("att"),
            tools_dir: dir.join("tools"),
            index_dir: dir.join("index"),
        }
    }

    #[test]
    fn safe_id_keeps_scopes_readable() {
        assert_eq!(safe_id("@babel/core@7.0.0"), "@babel%2Fcore@7.0.0");
        assert_eq!(safe_id("../../etc"), "..%2F..%2Fetc");
        assert_ne!(safe_id("a!b"), safe_id("a_b"));
    }

    #[test]
    fn attestation_cache_refuses_rollback_and_artifact_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let (signing, key) = test_key();
        let mut newer = sample_statement("demo", "1.0.0");
        newer.state = "revoked".into();
        newer.issued_at = "2026-09-26T00:00:00Z".into();
        store
            .cache_attestation(&newer, &seal(&signing, &key.keyid, &newer), &key)
            .unwrap();
        let older = sample_statement("demo", "1.0.0");
        assert!(store
            .cache_attestation(&older, &seal(&signing, &key.keyid, &older), &key)
            .is_err());
        let (cached, _) = store
            .cached_attestation("demo", "1.0.0", &key)
            .unwrap()
            .unwrap();
        assert_eq!(
            cached.state, "revoked",
            "older active statement must not replace revoked one"
        );

        let mut swapped = sample_statement("demo", "1.0.0");
        swapped.issued_at = "2026-09-27T00:00:00Z".into();
        swapped.artifact.hash = "sha512-other".into();
        assert!(store
            .cache_attestation(&swapped, &seal(&signing, &key.keyid, &swapped), &key)
            .is_err());
    }

    #[test]
    fn rejects_malformed_artifact_hashes() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store(dir.path()).package_dir("sha512-../../x").is_err());
    }

    #[test]
    fn equal_time_revocation_conflict_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let (signing, key) = test_key();
        let active = sample_statement("demo", "1.0.0");
        store
            .cache_attestation(&active, &seal(&signing, &key.keyid, &active), &key)
            .unwrap();
        let mut revoked = active.clone();
        revoked.state = "revoked".into();
        assert!(store
            .cache_attestation(&revoked, &seal(&signing, &key.keyid, &revoked), &key)
            .is_err());
    }

    #[test]
    fn attestation_cache_is_scoped_to_registry_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let first = store(dir.path());
        let (signing, key) = test_key();
        let statement = sample_statement("demo", "1.0.0");
        first
            .cache_attestation(&statement, &seal(&signing, &key.keyid, &statement), &key)
            .unwrap();
        let mut second = store(dir.path());
        second.registry = "http://other-registry.test".into();
        assert!(second
            .cached_attestation("demo", "1.0.0", &key)
            .unwrap()
            .is_none());
        assert_ne!(
            first.tool_dir("demo", "1.0.0"),
            second.tool_dir("demo", "1.0.0")
        );
    }

    #[test]
    fn concurrent_attestation_writes_keep_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let (signing, key) = test_key();
        let active = sample_statement("demo", "1.0.0");
        let mut revoked = active.clone();
        revoked.state = "revoked".into();
        revoked.issued_at = "2026-09-26T00:00:00Z".into();
        let older_envelope = seal(&signing, &key.keyid, &active);
        let newer_envelope = seal(&signing, &key.keyid, &revoked);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let _ = store.cache_attestation(&active, &older_envelope, &key);
            });
            scope.spawn(|| {
                store
                    .cache_attestation(&revoked, &newer_envelope, &key)
                    .unwrap();
            });
        });
        assert_eq!(
            store
                .cached_attestation("demo", "1.0.0", &key)
                .unwrap()
                .unwrap()
                .0
                .state,
            "revoked"
        );
    }
}
