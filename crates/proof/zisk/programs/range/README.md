# range

ZisK zkVM guest binary that proves a window of Base L2 block state-transition
function execution against a checkpointed L1 head.

Built via the ZisK toolchain into a `riscv64ima-zisk-zkvm-elf` ELF that is
embedded by `base-proof-zisk-elfs::RANGE_ELF_EMBEDDED`. The embedded ELF's
sha256 is pinned in `crates/proof/zisk/elf/manifest.toml`.

The guest commits a `BootInfoStruct` packed via `ziskos::io::commit_slice`,
which becomes the proof's public values. The aggregation guest recursively
verifies a sequence of range proofs and reads the embedded public values to
build the final `AggregationOutputs`.
