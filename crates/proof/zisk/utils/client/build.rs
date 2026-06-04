//! Teach rustc that `target_vendor = "zisk"` is a valid cfg value.
//!
//! The ZisK guest target (`riscv64ima-zisk-zkvm-elf`) sets
//! `target_vendor = "zisk"`. That value is not in rustc's built-in well-known
//! set, so `#[cfg(target_vendor = "zisk")]` would trigger the `unexpected_cfgs`
//! lint without this declaration. Scoped to this crate via build.rs so the
//! check-cfg extension does not leak into host crates.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(target_vendor, values(\"zisk\"))");
}
