#![doc = include_str!("../README.md")]

mod manifest;
pub use manifest::{ElfEntry, ElfManifest};

mod resolver;
pub use resolver::{ResolveError, elf_env_var, hex_sha256, resolve_elf};
