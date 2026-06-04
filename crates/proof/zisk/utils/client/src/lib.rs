#![doc = include_str!("../README.md")]

mod boot;
pub use boot::{
    BootInfoStruct, boot_info_commitment, decode_boot_info, encode_boot_info, hash_rollup_config,
};

mod executor;
pub use executor::ETHDAWitnessExecutor;

mod oracle;
pub use oracle::{BlobKzgVerifier, BlobStore};

mod precompiles;
pub use precompiles::{
    BaseZkvmPrecompiles, CustomCrypto, ZiskCycleObserver, ZkvmBaseEvmFactory, cycle_tracker,
};

mod types;
pub use types::{
    AggregationInputs, AggregationOutputs, PROGRAM_VK_WORDS, VADCOP_PUBLIC_WORDS, VADCOP_VK_WORDS,
    VadcopProofPublics, ZISK_PUBLIC_VALUE_BYTES, ZISK_PUBLIC_WORDS,
};

mod witness;
pub use witness::{
    BYTES_PER_BLOB, BlobData, DefaultWitnessData, KzgBlob, KzgBytes48, PreimageStore, WitnessData,
    check_preimage,
};
pub use witness::{
    PipelineInputs, WitnessExecutor, ensure_derived_block_matches_claim, get_inputs_for_pipeline,
};

mod client;
pub use client::{DEFAULT_INTERMEDIATE_ROOT_INTERVAL, advance_to_target, fetch_safe_head_hash};
