# aggregation

ZisK zkVM guest binary that recursively verifies a sequence of `range` proofs
and emits the aggregated `AggregationOutputs` digest as its public values.

Built via the ZisK toolchain into a `riscv64ima-zisk-zkvm-elf` ELF that is
embedded by `base-proof-zisk-elfs::AGGREGATION_ELF`.

## Public-value binding (security-critical)

Host-supplied data is untrusted. The guest enforces binding as follows:

1. Each range proof is verified inside the guest via
   `ziskos::zisklib::verify_zisk_proof_c`.
2. The host submits the `BootInfoStruct` recovered while building the same
   witness. The aggregation guest computes its commitment and requires it to
   equal the 32-byte digest committed by the verified range proof.
3. The aggregation guest only uses a `BootInfoStruct` after that digest check
   succeeds.

This guarantees the recursive aggregation cannot bind to attacker-controlled
boot info even if the host conspires.
