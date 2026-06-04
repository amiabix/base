# Base ZisK Smoke Harness

Runs a single-range ZisK proving smoke test outside the gRPC service. The
binary builds or loads the range witness, proves the embedded range guest, and
prints phase timings plus the raw verifier receipt size.

`RECEIPT_OUTPUT_PATH` writes the raw `Proof::get_proof_bytes()` receipt used by
the aggregation guest and verifier precompile. It is not the structured
`Proof::save()` container expected by `cargo-zisk verify -p`.

Useful runtime controls:

- `BASE_ZISK_EXECUTOR=emulator` uses the Rust emulator executor. This is the default.
- `BASE_ZISK_EXECUTOR=assembly` uses the ZisK assembly executor.
- `BASE_ZISK_GPU=1` enables GPU proving.
- `BASE_ZISK_MAX_STREAMS=1` limits parallel GPU streams.
- `BASE_ZISK_WITNESS_THREADS=1` limits witness worker pools.
- `BASE_ZISK_MAX_WITNESS_STORED=1` limits queued GPU witness storage.
