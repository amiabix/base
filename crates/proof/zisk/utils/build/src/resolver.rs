//! Helpers for resolving and hash-checking ELF files inside a build script.

use std::{
    fmt::{self, Write as _},
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::manifest::ElfEntry;

/// Failure modes for [`resolve_elf`].
#[derive(Debug)]
pub enum ResolveError {
    /// The expected file could not be read from disk.
    Missing {
        /// Expected ELF path.
        path: PathBuf,
        /// Manifest entry name.
        name: String,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The file existed but its sha256 did not match the manifest entry.
    HashMismatch {
        /// Existing ELF path.
        path: PathBuf,
        /// Manifest entry name.
        name: String,
        /// Expected sha256 from the manifest.
        expected: String,
        /// Actual sha256 computed from the file.
        actual: String,
    },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { path, name, source } => {
                write!(f, "ELF `{name}` not found at {path} ({source})", path = path.display(),)
            }
            Self::HashMismatch { path, name, expected, actual } => write!(
                f,
                "ELF `{name}` sha256 mismatch at {path} (expected {expected}, actual {actual})",
                path = path.display(),
            ),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Missing { source, .. } => Some(source),
            Self::HashMismatch { .. } => None,
        }
    }
}

/// Resolve a manifest entry against an on-disk cache directory.
pub fn resolve_elf(cache_dir: &Path, entry: &ElfEntry) -> Result<PathBuf, ResolveError> {
    let path = cache_dir.join(&entry.name);
    let bytes = fs::read(&path).map_err(|err| ResolveError::Missing {
        path: path.clone(),
        name: entry.name.clone(),
        source: err,
    })?;
    let actual = hex_sha256(&bytes);
    if actual != entry.sha256 {
        return Err(ResolveError::HashMismatch {
            path,
            name: entry.name.clone(),
            expected: entry.sha256.clone(),
            actual,
        });
    }
    Ok(path)
}

/// Hex-encoded sha256 of the supplied bytes.
pub fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Derive the `cargo:rustc-env` variable name a build script exposes for the
/// given ELF name. Example: `range-elf-embedded` → `RANGE_ELF_EMBEDDED_PATH`.
pub fn elf_env_var(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for ch in name.chars() {
        out.push(match ch {
            'a'..='z' => ch.to_ascii_uppercase(),
            '-' | '.' => '_',
            _ => ch,
        });
    }
    out.push_str("_PATH");
    out
}
