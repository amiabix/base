//! `ZiskProofBlob` - verifier-shaped bytes with verifier-bound public digests.

use alloy_primitives::B256;
use anyhow::{Result, anyhow};
use base_proof_zisk_client_utils::VadcopProofPublics;
use serde::{Deserialize, Serialize};

/// Verifier-shaped `ZisK` proof bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZiskProofBlob {
    /// Bytes consumed by the on-chain / off-chain verifier.
    pub proof_bytes: Vec<u8>,
}

impl ZiskProofBlob {
    /// Construct from raw verifier bytes.
    pub const fn new(proof_bytes: Vec<u8>) -> Self {
        Self { proof_bytes }
    }

    /// Return a view of the verifier-shaped bytes.
    pub fn proof(&self) -> &[u8] {
        &self.proof_bytes
    }
}

/// Decode the 32-byte range-output commitment from the public-values segment.
///
/// Callers MUST verify the proof before trusting the decoded commitment.
pub fn decode_boot_info_commitment_from_proof(blob: &ZiskProofBlob) -> Result<B256> {
    let publics = VadcopProofPublics::parse(&blob.proof_bytes)
        .ok_or_else(|| anyhow!("invalid ZisK VADCOP proof public layout"))?;
    publics
        .committed_digest()
        .ok_or_else(|| anyhow!("range proof public values are not a single digest"))
}
