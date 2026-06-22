use std::{
    io::{Cursor, Write},
    path::Path,
};

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use sha2::{Digest, Sha512};
use tar::Archive;
use walkdir::WalkDir;

pub fn sha512_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    format!("sha512-{}", hex::encode(hasher.finalize()))
}

pub fn verify_npm_integrity(bytes: &[u8], integrity: &str) -> Result<()> {
    let Some(encoded) = integrity.strip_prefix("sha512-") else {
        return Ok(());
    };
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let actual = STANDARD.encode(digest);
    if actual != encoded {
        bail!("npm tarball integrity mismatch");
    }
    Ok(())
}

pub fn extract_tgz(bytes: &[u8], destination: &std::path::Path) -> Result<()> {
    if destination.exists() {
        std::fs::remove_dir_all(destination)?;
    }
    std::fs::create_dir_all(destination)?;
    let cursor = Cursor::new(bytes);
    let decoder = GzDecoder::new(cursor);
    let mut archive = Archive::new(decoder);
    archive.unpack(destination)?;
    Ok(())
}

pub fn create_project_tgz(root: &Path) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut encoder);
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            let path = entry.path();
            if path == root || should_skip(path, root) || entry.file_type().is_dir() {
                continue;
            }
            let relative = path.strip_prefix(root)?;
            builder.append_path_with_name(path, relative)?;
        }
        builder.finish()?;
    }
    encoder.flush()?;
    Ok(encoder.finish()?)
}

fn should_skip(path: &Path, root: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return true;
    };
    relative.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        matches!(
            value.as_ref(),
            ".git" | ".rivet" | "target" | "node_modules" | "registry/artifacts"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::sha512_hex;

    #[test]
    fn sha512_hash_uses_rivet_prefix() {
        let hash = sha512_hex(b"hello");
        assert!(hash.starts_with("sha512-"));
        assert_eq!(hash.len(), "sha512-".len() + 128);
    }
}
