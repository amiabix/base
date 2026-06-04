# base-proof-zisk-build-utils

Build-script helpers shared by the `ZisK` ELF-embedding crate and any future
crates that need to resolve a `ZisK` guest artifact against a `manifest.toml`
sha256-pinned cache.

Public surface:

- `ElfManifest` - TOML schema for `[[elfs]]` entries.
- `resolve_elf` - hash-checks a cached ELF file against an expected sha256.
- `hex_sha256` - convenience helper for build scripts.
- `elf_env_var` - derives the `cargo:rustc-env` variable name a build script
  exposes for each manifest entry.
