//! Canonical package tarball handling. Mirrors registry/internal/canon: the
//! registry signs a tree digest computed with these exact rules, and the CLI
//! recomputes it before installing and before every run.

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::{Archive, EntryType};
use walkdir::WalkDir;

pub const MAX_UNPACKED_BYTES: u64 = 512 << 20;
pub const MAX_FILE_BYTES: u64 = 256 << 20;
pub const MAX_ENTRIES: usize = 100_000;
pub const TREE_DIGEST_PREFIX: &str = "rivet-tree-v1:sha256:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonFile {
    pub executable: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CanonPackage {
    pub files: BTreeMap<String, CanonFile>,
    pub tree_digest: String,
}

pub fn read_tarball(bytes: &[u8]) -> Result<CanonPackage> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder.take(MAX_UNPACKED_BYTES * 2));
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for (index, entry) in archive.entries().context("read tarball")?.enumerate() {
        if index >= MAX_ENTRIES {
            bail!("unsafe package archive: too many entries");
        }
        let mut entry = entry.context("read tarball entry")?;
        let header_type = entry.header().entry_type();
        let raw_path = String::from_utf8(entry.path_bytes().into_owned())
            .context("unsafe package archive: non-utf8 path")?;
        if header_type != EntryType::Regular || raw_path.ends_with('/') {
            continue;
        }
        let Some(path) = normalize_path(&raw_path)? else {
            continue;
        };
        let size = entry.header().size()?;
        if size > MAX_FILE_BYTES {
            bail!("unsafe package archive: {path} exceeds file size limit");
        }
        total += size;
        if total > MAX_UNPACKED_BYTES {
            bail!("unsafe package archive: unpacked size limit exceeded");
        }
        let executable = entry.header().mode()? & 0o111 != 0;
        let mut data = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut data)?;
        files.insert(path, CanonFile { executable, data });
    }
    let tree_digest = tree_digest(
        files
            .iter()
            .map(|(p, f)| (p.as_str(), f.executable, f.data.as_slice())),
    );
    Ok(CanonPackage { files, tree_digest })
}

/// Strips the first path component and validates the rest. Returns None for
/// entries with nothing left after stripping.
pub fn normalize_path(name: &str) -> Result<Option<String>> {
    if name.contains('\0') || name.contains('\\') || name.starts_with('/') {
        bail!("unsafe package archive: invalid path {name:?}");
    }
    let mut parts = name.split('/');
    parts.next();
    let mut out = Vec::new();
    for part in parts {
        match part {
            "" | "." => continue,
            ".." => bail!("unsafe package archive: path traversal in {name:?}"),
            other => out.push(other),
        }
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(out.join("/")))
}

pub fn tree_digest<'a>(files: impl Iterator<Item = (&'a str, bool, &'a [u8])>) -> String {
    let mut entries: Vec<(&str, bool, &[u8])> = files.collect();
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut hasher = Sha256::new();
    for (path, executable, data) in entries {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(if executable { b"x" } else { b"-" });
        hasher.update([0]);
        hasher.update(hex::encode(Sha256::digest(data)).as_bytes());
        hasher.update(b"\n");
    }
    format!("{TREE_DIGEST_PREFIX}{}", hex::encode(hasher.finalize()))
}

/// Recomputes the tree digest of an extracted package directory. Symlinks or
/// special files inside a package directory are treated as tampering.
pub fn tree_digest_of_dir(root: &Path) -> Result<String> {
    // Keep only per-file digests in memory. A package can contain files close
    // to the archive limit, and verification runs before every command.
    let mut files: Vec<(String, bool, [u8; 32])> = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let file_type = entry.file_type();
        if file_type.is_dir() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_str()
            .context("non-utf8 path in package")?
            .to_string();
        if !file_type.is_file() {
            bail!(
                "unexpected non-regular file {relative} in {}",
                root.display()
            );
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            // O_NONBLOCK prevents a swapped-in FIFO from hanging verification.
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(entry.path())?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!(
                "unexpected non-regular file {relative} in {}",
                root.display()
            );
        }
        let mut hasher = Sha256::new();
        loop {
            let count = match file.read(&mut buffer) {
                Ok(count) => count,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            };
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        files.push((
            relative,
            metadata.permissions().mode() & 0o111 != 0,
            hasher.finalize().into(),
        ));
    }
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut hasher = Sha256::new();
    for (path, executable, digest) in files {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(if executable { b"x" } else { b"-" });
        hasher.update([0]);
        hasher.update(hex::encode(digest).as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!(
        "{TREE_DIGEST_PREFIX}{}",
        hex::encode(hasher.finalize())
    ))
}

/// Writes a canonical package to `dest` with read-only files, so installed
/// packages cannot silently modify the shared store.
pub fn write_package(package: &CanonPackage, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    for (path, file) in &package.files {
        let target = dest.join(path);
        if !target.starts_with(dest) {
            bail!("refusing to write outside package directory: {path}");
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &file.data)?;
        let mode = if file.executable { 0o555 } else { 0o444 };
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    const VECTOR: &[u8] = include_bytes!("../../../fixtures/tarballs/tree-vector.tgz");
    const VECTOR_DIGEST: &str = include_str!("../../../fixtures/tarballs/tree-vector.digest");

    #[test]
    fn matches_shared_tree_vector() {
        let package = read_tarball(VECTOR).unwrap();
        let paths: Vec<_> = package.files.keys().cloned().collect();
        assert_eq!(
            paths,
            vec![
                "README.md",
                "bin/tv.js",
                "lib/a.js",
                "lib/b.js",
                "package.json"
            ]
        );
        assert_eq!(package.files["lib/a.js"].data, b"module.exports = 2\n");
        assert!(package.files["bin/tv.js"].executable);
        assert!(!package.files["lib/a.js"].executable);
        assert_eq!(package.tree_digest, VECTOR_DIGEST.trim());
    }

    #[test]
    fn extracted_directory_hashes_identically() {
        let package = read_tarball(VECTOR).unwrap();
        let dir = tempfile::tempdir().unwrap();
        write_package(&package, dir.path()).unwrap();
        assert_eq!(
            tree_digest_of_dir(dir.path()).unwrap(),
            VECTOR_DIGEST.trim()
        );
        // Adding a file is detected.
        let extra = dir.path().join("extra.js");
        fs::write(&extra, "evil").unwrap();
        assert_ne!(
            tree_digest_of_dir(dir.path()).unwrap(),
            VECTOR_DIGEST.trim()
        );
        fs::remove_file(extra).unwrap();
        fs::remove_file(dir.path().join("lib/a.js")).unwrap();
        assert_ne!(
            tree_digest_of_dir(dir.path()).unwrap(),
            VECTOR_DIGEST.trim()
        );
    }

    #[test]
    fn empty_directory_has_empty_canonical_digest() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            tree_digest_of_dir(dir.path()).unwrap(),
            tree_digest(std::iter::empty())
        );
    }

    #[test]
    fn streams_large_file_with_canonical_digest_and_detects_tail_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let data = vec![0x5a; 32 * 1024 * 1024];
        fs::write(&path, &data).unwrap();
        let expected = tree_digest(std::iter::once(("large.bin", false, data.as_slice())));
        assert_eq!(tree_digest_of_dir(dir.path()).unwrap(), expected);

        let mut changed = data;
        *changed.last_mut().unwrap() = 0x5b;
        fs::write(&path, changed).unwrap();
        assert_ne!(tree_digest_of_dir(dir.path()).unwrap(), expected);
    }

    #[test]
    fn streams_empty_and_multiple_files_with_executable_modes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("empty"), []).unwrap();
        fs::write(dir.path().join("script"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(dir.path().join("script"), fs::Permissions::from_mode(0o755)).unwrap();
        let expected = tree_digest(
            [
                ("script", true, b"#!/bin/sh\n".as_slice()),
                ("empty", false, b"".as_slice()),
            ]
            .into_iter(),
        );
        assert_eq!(tree_digest_of_dir(dir.path()).unwrap(), expected);

        fs::set_permissions(dir.path().join("script"), fs::Permissions::from_mode(0o644)).unwrap();
        assert_ne!(tree_digest_of_dir(dir.path()).unwrap(), expected);
    }

    #[test]
    fn rejects_symlinks_and_special_files_in_extracted_tree() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        symlink("missing", &link).unwrap();
        assert!(tree_digest_of_dir(dir.path()).is_err());
        fs::remove_file(link).unwrap();

        let fifo = dir.path().join("pipe");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(tree_digest_of_dir(dir.path()).is_err());
    }

    #[test]
    fn rejects_traversal() {
        assert!(normalize_path("package/../../etc/passwd").is_err());
        assert!(normalize_path("/package/x").is_err());
        assert!(normalize_path("package\\x").is_err());
        assert_eq!(
            normalize_path("package/./a//b.js").unwrap().unwrap(),
            "a/b.js"
        );
        assert_eq!(normalize_path("package").unwrap(), None);
    }
}
