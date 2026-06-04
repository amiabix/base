# base-proof-zisk-client-utils

`ZisK` zkVM client utilities for Base proof generation. Shared by the range and
aggregation guests plus the host-side witness builder.

Modules:

- `boot` - `BootInfoStruct`, its compact range-proof commitment, and the
  rollup-config hashing helper.
- `types` - `AggregationInputs` / `AggregationOutputs` for the aggregation
  guest.
- `witness` - `DefaultWitnessData` (rkyv-archivable), `PreimageStore`,
  `WitnessExecutor` trait, and `EthDAWitnessExecutor`.
- `executor` - re-export shortcut for `EthDAWitnessExecutor`.

This crate is the single source of truth for cross-crate proof primitives;
the host fetcher, the guest binaries, and the backend service all import the
same types from here.
