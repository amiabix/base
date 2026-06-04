//! Shared types for the `ZisK` range and aggregation guests.

use alloy_primitives::{Address, B256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

use crate::BootInfoStruct;

/// Number of u64 words in a `ZisK` program verification key.
pub const PROGRAM_VK_WORDS: usize = 4;
/// Number of u64 public-output words in a `ZisK` proof.
pub const ZISK_PUBLIC_WORDS: usize = 64;
/// Number of bytes recoverable from `ZisK` public-output words.
pub const ZISK_PUBLIC_VALUE_BYTES: usize = ZISK_PUBLIC_WORDS * 4;
/// Number of u64 words in the VADCOP verification key suffix.
pub const VADCOP_VK_WORDS: usize = 4;
/// Expected public count in verifier-ready VADCOP blobs: program VK plus zkVM publics.
pub const VADCOP_PUBLIC_WORDS: usize = PROGRAM_VK_WORDS + ZISK_PUBLIC_WORDS;

/// Inputs to the `ZisK` aggregation program.
///
/// `range_proofs` carries the serialized `ZisK` proof blobs (verifier-ready
/// bytes); the aggregation guest verifies each blob via
/// `ziskos::zisklib::verify_zisk_proof_c`, then checks that each host-supplied
/// [`BootInfoStruct`] hashes to the digest committed by the corresponding
/// verified range proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationInputs {
    /// Serialized `ZisK` range-proof blobs (each blob verified inside the guest).
    pub range_proofs: Vec<Vec<u8>>,
    /// Host-supplied range outputs, bound to `range_proofs` by their public
    /// `boot_info_commitment` digest.
    pub range_boot_infos: Vec<BootInfoStruct>,
    /// L1 block hash anchoring all ranges; matched to the header chain walked
    /// against `headers` (provided separately via `ziskos::io::read_input_slice`).
    pub latest_l1_checkpoint_head: B256,
    /// On-chain prover address bound into the aggregation public values.
    pub prover_address: Address,
    /// Committed verification key of the range program. Becomes
    /// [`AggregationOutputs::imageHash`].
    pub zisk_range_program_vk: B256,
}

sol! {
    /// Aggregation public values committed by the `ZisK` aggregation guest.
    ///
    /// The packed layout matches the on-chain `AggregateVerifier`'s expected
    /// keccak digest format so the contract dispatches by proof-type byte
    /// without any extra encoding step.
    #[derive(Debug, Serialize, Deserialize)]
    struct AggregationOutputs {
        address proverAddress;
        bytes32 l1Head;
        bytes32 l2PreRoot;
        uint64 startingL2SequenceNumber;
        bytes32 l2PostRoot;
        uint64 endingL2SequenceNumber;
        bytes intermediateRoots;
        bytes32 rollupConfigHash;
        bytes32 imageHash;
    }
}

/// Public values parsed from a verifier-shaped VADCOP proof blob.
///
/// VADCOP blobs start with the public-word count. The first four public words
/// are the program VK, followed by the fixed ZisK public-output words. The
/// verifier key is a four-word suffix after the proof body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VadcopProofPublics {
    program_vk: [u64; PROGRAM_VK_WORDS],
    public_values: Vec<u8>,
}

impl VadcopProofPublics {
    /// Parse the public region from a `ZisK` VADCOP proof byte blob.
    pub fn parse(proof_blob: &[u8]) -> Option<Self> {
        if proof_blob.len() < (1 + VADCOP_PUBLIC_WORDS + VADCOP_VK_WORDS) * 8
            || !proof_blob.len().is_multiple_of(8)
        {
            return None;
        }

        let words = proof_blob
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes")))
            .collect::<Vec<_>>();

        let n_publics = usize::try_from(words[0]).ok()?;
        if n_publics != VADCOP_PUBLIC_WORDS || words.len() < 1 + n_publics + VADCOP_VK_WORDS {
            return None;
        }

        let mut program_vk = [0u64; PROGRAM_VK_WORDS];
        program_vk.copy_from_slice(&words[1..1 + PROGRAM_VK_WORDS]);

        let public_words = &words[1 + PROGRAM_VK_WORDS..1 + n_publics];
        let mut public_values = Vec::with_capacity(ZISK_PUBLIC_VALUE_BYTES);
        for &word in public_words {
            public_values.extend_from_slice(&(word as u32).to_le_bytes());
        }

        Some(Self { program_vk, public_values })
    }

    /// Program verification key words committed by the proved range program.
    pub const fn program_vk(&self) -> [u64; PROGRAM_VK_WORDS] {
        self.program_vk
    }

    /// Program verification key encoded as the on-chain `bytes32` image hash.
    pub fn program_vk_b256(&self) -> B256 {
        let mut bytes = [0u8; 32];
        for (i, word) in self.program_vk.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        B256::from(bytes)
    }

    /// Raw committed public-value bytes, padded to the `ZisK` public-output width.
    pub fn public_values(&self) -> &[u8] {
        &self.public_values
    }

    /// Interpret the public values as one 32-byte digest followed by zero padding.
    pub fn committed_digest(&self) -> Option<B256> {
        if self.public_values.len() != ZISK_PUBLIC_VALUE_BYTES {
            return None;
        }
        if self.public_values[32..].iter().any(|&byte| byte != 0) {
            return None;
        }

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&self.public_values[..32]);
        Some(B256::from(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof_blob_with_publics(public_values: &[u8; ZISK_PUBLIC_VALUE_BYTES]) -> Vec<u8> {
        let mut words = Vec::new();
        words.push(VADCOP_PUBLIC_WORDS as u64);
        words.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        for chunk in public_values.chunks_exact(4) {
            words.push(u32::from_le_bytes(chunk.try_into().expect("four bytes")) as u64);
        }
        words.extend_from_slice(&[0xaa, 0xbb]);
        words.extend_from_slice(&[0x55, 0x66, 0x77, 0x88]);

        words.into_iter().flat_map(u64::to_le_bytes).collect()
    }

    #[test]
    fn parse_reads_vadcop_blob_publics() {
        let mut public_values = [0u8; ZISK_PUBLIC_VALUE_BYTES];
        public_values[..32].copy_from_slice(B256::repeat_byte(0xab).as_slice());

        let parsed = VadcopProofPublics::parse(&proof_blob_with_publics(&public_values))
            .expect("valid proof layout");

        assert_eq!(parsed.program_vk(), [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(parsed.committed_digest(), Some(B256::repeat_byte(0xab)));
    }

    #[test]
    fn parse_rejects_wrong_public_count() {
        let mut blob = proof_blob_with_publics(&[0u8; ZISK_PUBLIC_VALUE_BYTES]);
        blob[..8].copy_from_slice(&(VADCOP_PUBLIC_WORDS as u64 - 1).to_le_bytes());

        assert!(VadcopProofPublics::parse(&blob).is_none());
    }

    #[test]
    fn committed_digest_rejects_extra_public_data() {
        let mut public_values = [0u8; ZISK_PUBLIC_VALUE_BYTES];
        public_values[..32].copy_from_slice(B256::repeat_byte(0xab).as_slice());
        public_values[32] = 1;
        let parsed = VadcopProofPublics::parse(&proof_blob_with_publics(&public_values))
            .expect("valid proof layout");

        assert_eq!(parsed.committed_digest(), None);
    }
}
