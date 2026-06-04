//! Host-side builder for the aggregation guest's stdin blob.

use alloy_primitives::{Address, B256};
use anyhow::Result;
use base_proof_zisk_client_utils::{AggregationInputs, BootInfoStruct};

use crate::blob::ZiskProofBlob;

/// Pack range proof receipts into the aggregation guest's stdin blob. The
/// aggregation guest verifies each proof before trusting its public values. The
/// caller is responsible for the L1 header chain (passed separately via
/// `ziskos::io::read_input_slice` on the guest side).
///
/// Returns the serialized `AggregationInputs` value plus the raw verifier
/// bytes per range proof; the backend layer wraps these into the concrete
/// `ZiskStdin` representation used by the prover client.
pub fn get_agg_proof_stdin(
    range_proofs: Vec<ZiskProofBlob>,
    range_boot_infos: Vec<BootInfoStruct>,
    latest_l1_checkpoint_head: B256,
    prover_address: Address,
    zisk_range_program_vk: B256,
) -> Result<AggregationInputs> {
    let range_proof_bytes = range_proofs.into_iter().map(|blob| blob.proof_bytes).collect();

    Ok(AggregationInputs {
        range_proofs: range_proof_bytes,
        range_boot_infos,
        latest_l1_checkpoint_head,
        prover_address,
        zisk_range_program_vk,
    })
}
