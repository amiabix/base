//! Build script for `base-proof-zisk-elfs`.
//!
//! Reads `crates/proof/zisk/elf/manifest.toml`, verifies each pinned ELF's
//! sha256 against the on-disk cache, and exposes the resolved absolute path
//! via `cargo:rustc-env=<NAME>_PATH=...` so `src/lib.rs` can embed the bytes
//! via `include_bytes!(env!(...))`.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

use base_proof_zisk_build_utils::{ElfEntry, ElfManifest, elf_env_var, resolve_elf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    // crate is at crates/proof/zisk/utils/elfs; ELF cache lives at crates/proof/zisk/elf.
    let cache_dir = env::var_os("BASE_ZISK_ELF_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("../../elf"));
    let manifest_path = cache_dir.join("manifest.toml");

    println!("cargo:rerun-if-env-changed=BASE_ZISK_ELF_CACHE_DIR");
    println!("cargo:rerun-if-changed={}", manifest_path.display());

    let manifest = load_manifest(&manifest_path);

    for entry in &manifest.elfs {
        let env_name = elf_env_var(&entry.name);
        let expected_path = cache_dir.join(&entry.name);
        println!("cargo:rerun-if-changed={}", expected_path.display());

        let resolved = resolve_elf(&cache_dir, entry)
            .unwrap_or_else(|err| fail(&format!("{err}\nRun `just zisk build-elfs` and retry.")));
        println!("cargo:rustc-env={}={}", env_name, resolved.display());
    }
}

fn load_manifest(path: &Path) -> ElfManifest {
    let contents = fs::read_to_string(path).unwrap_or_else(|err| {
        fail(&format!("failed to read ELF manifest at {}: {err}", path.display()))
    });
    toml::from_str(&contents)
        .unwrap_or_else(|err| fail(&format!("failed to parse {}: {err}", path.display())))
}

fn warn(msg: &str) {
    for line in msg.lines() {
        println!("cargo:warning={line}");
    }
}

fn fail(msg: &str) -> ! {
    warn(msg);
    eprintln!("{msg}");
    process::exit(1);
}

// Touch the `ElfEntry` type so the build-utils import is exercised.
const _: fn(&ElfEntry) = |_| {};
