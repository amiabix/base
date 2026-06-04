# base-proof-zisk-elfs

Embeds the `ZisK` guest ELFs (`range-elf-embedded`, `aggregation-elf`) as
`&'static [u8]` constants for downstream use by the backend service.

The actual binaries live out of tree under `crates/proof/zisk/elf/` and are
NOT committed to git. `build.rs` resolves them against the pinned sha256s in
`crates/proof/zisk/elf/manifest.toml` and exposes their absolute paths via
`cargo:rustc-env` so the constants below can embed them at compile time.

## Environment variables

- **`BASE_ZISK_ELF_CACHE_DIR`:** overrides the default cache directory
  (`crates/proof/zisk/elf`).

If an ELF is missing or its sha256 does not match `manifest.toml`, the build
fails. Rebuild the guest artifacts with `just zisk build-elfs`, then update the
manifest with `just zisk write-manifest` when guest code changes.
