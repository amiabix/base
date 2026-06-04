# base-proof-zisk-range-utils

Host- and guest-shared helpers for the ZisK range program. Splitting the helper
logic into a normal Cargo crate (compiled with the normal toolchain) lets the
guest binary stay minimal while still depending on rich logic via the
`workspace.path` import.

Public surface:

- `run_range_program(executor, oracle, beacon)` - runs the derivation +
  execution pipeline inside the guest and commits the resulting
  `BootInfoStruct` digest to the ZisK public-values channel.
- `setup_tracing()` (feature `tracing-subscriber`) - wires up
  `tracing_subscriber::fmt` for local debug runs.
