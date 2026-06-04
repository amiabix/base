# base-proof-zisk-proof-utils

Serialization helpers for `ZisK` proof blobs (range STARK + aggregation Plonk),
plus host-side stdin builders shared by the backend service and the CLI
binaries.

Public surface:

- `ZiskProofBlob` - sealed wrapper around the raw bytes a `ZisK` verifier accepts,
  with accessors for the proof bytes.
- `decode_boot_info_commitment_from_proof` - parses the verified range proof's
  public values as the committed `BootInfoStruct` digest.
- `get_agg_proof_stdin` - host-side builder that packs a list of verified
  range proofs and their host-derived boot info into the aggregation guest's
  `stdin` blob.
- `RangeWitnessCache` - disk cache for range guest `ZiskStdin` blobs and the
  matching `BootInfoStruct` sidecar, used to avoid repeated live RPC witness
  generation for the same block range.
