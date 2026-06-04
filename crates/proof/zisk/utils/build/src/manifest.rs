//! TOML schema for the `ZisK` ELF manifest.

use serde::Deserialize;

/// Top-level manifest containing a list of ELF entries.
#[derive(Debug, Deserialize)]
pub struct ElfManifest {
    /// Individual ELF entries (one per pinned guest binary).
    pub elfs: Vec<ElfEntry>,
}

/// A single manifest entry pinning one ELF file to its sha256.
#[derive(Debug, Deserialize)]
pub struct ElfEntry {
    /// File name within the cache directory.
    pub name: String,
    /// Lowercase hex-encoded sha256 of the file's contents.
    pub sha256: String,
}
