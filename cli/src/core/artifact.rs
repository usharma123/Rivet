use std::{io::Write, path::Path};

use anyhow::Result;
use flate2::{write::GzEncoder, Compression};
use sha2::{Digest, Sha512};
use walkdir::WalkDir;

/// Rivet artifact hash: "sha512-" + hex digest of the tarball bytes.
pub fn sha512_hex(bytes: &[u8]) -> String {
    format!("sha512-{}", hex::encode(Sha512::digest(bytes)))
}

/// Builds a reproducible npm-style tarball ("package/" prefix, sorted
/// entries, zeroed timestamps and owners) from a project directory.
pub fn create_project_tgz(root: &Path) -> Result<Vec<u8>> {
    let mut entries: Vec<_> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file() && !should_skip(entry.path(), root))
        .map(|entry| entry.into_path())
        .collect();
    entries.sort();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut encoder);
        builder.mode(tar::HeaderMode::Deterministic);
        for path in entries {
            let relative = path.strip_prefix(root)?;
            let name = Path::new("package").join(relative);
            builder.append_path_with_name(&path, name)?;
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
            ".git" | ".rivet" | "target" | "node_modules" | ".env" | ".npmrc" | "rivet.lock"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tree;

    #[test]
    fn sha512_hash_uses_rivet_prefix() {
        let hash = sha512_hex(b"hello");
        assert!(hash.starts_with("sha512-"));
        assert_eq!(hash.len(), "sha512-".len() + 128);
    }

    #[test]
    fn project_tarballs_are_canonical_and_reproducible() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules/x")).unwrap();
        std::fs::write(dir.path().join("bin/a.js"), "a").unwrap();
        std::fs::write(dir.path().join("rivet.toml"), "x").unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::write(dir.path().join("node_modules/x/i.js"), "x").unwrap();
        let first = create_project_tgz(dir.path()).unwrap();
        let second = create_project_tgz(dir.path()).unwrap();
        assert_eq!(first, second, "tarball must be reproducible");
        let package = tree::read_tarball(&first).unwrap();
        let paths: Vec<_> = package.files.keys().cloned().collect();
        assert_eq!(paths, vec!["bin/a.js", "rivet.toml"]);
    }
}
