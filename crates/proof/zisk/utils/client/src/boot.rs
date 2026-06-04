//! Boot information committed by the range guest as `ZisK` public values.

use alloy_primitives::{B256, Bytes, keccak256};
use alloy_sol_types::sol;
use anyhow::{Context, Result};
use base_common_genesis::RollupConfig;
use base_proof::BootInfo;
use base_proof_primitives::PerChainConfig;
use serde::{Deserialize, Serialize};

/// Hash the rollup config using the canonical [`PerChainConfig`] binary encoding and keccak256.
///
/// Stable across hardfork additions: only the core chain identity fields are hashed,
/// so adding a new fork timestamp to [`RollupConfig`] does not change the hash.
pub fn hash_rollup_config(config: &RollupConfig) -> B256 {
    let mut per_chain =
        PerChainConfig::from_rollup_config(config).expect("rollup config missing system_config");
    per_chain.force_defaults();
    per_chain.hash()
}

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct BootInfoStruct {
        bytes32 l1Head;
        bytes32 l2PreRoot;
        bytes32 l2PostRoot;
        uint64 l2PreBlockNumber;
        uint64 l2BlockNumber;
        bytes32 rollupConfigHash;
        bytes intermediateRoots;
    }
}

/// Serialize boot info with the range/aggregation commitment codec.
pub fn encode_boot_info(boot_info: &BootInfoStruct) -> Vec<u8> {
    bincode::serialize(boot_info).expect("bincode serialize BootInfoStruct")
}

/// Deserialize boot info with the range/aggregation commitment codec.
pub fn decode_boot_info(input: &[u8]) -> Result<BootInfoStruct> {
    bincode::deserialize(input).context("bincode deserialize BootInfoStruct")
}

/// Compute the compact public value committed by the ZisK range guest.
pub fn boot_info_commitment(boot_info: &BootInfoStruct) -> B256 {
    keccak256(encode_boot_info(boot_info))
}

impl BootInfoStruct {
    /// Create from a [`BootInfo`], the derived L2 block number, and intermediate state roots.
    pub fn new(
        boot_info: BootInfo,
        l2_pre_block_number: u64,
        l2_block_number: u64,
        intermediate_roots: Vec<B256>,
    ) -> Self {
        assert_eq!(
            l2_block_number, boot_info.claimed_l2_block_number,
            "derived L2 block number must match claimed L2 block number"
        );

        Self {
            l1Head: boot_info.l1_head,
            l2PreRoot: boot_info.agreed_l2_output_root,
            l2PostRoot: boot_info.claimed_l2_output_root,
            l2PreBlockNumber: l2_pre_block_number,
            l2BlockNumber: l2_block_number,
            rollupConfigHash: hash_rollup_config(&boot_info.rollup_config),
            intermediateRoots: Bytes::from(
                intermediate_roots
                    .iter()
                    .flat_map(|root| root.as_slice())
                    .copied()
                    .collect::<Vec<u8>>(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, b256};
    use base_common_chains::ChainConfig;

    use super::*;

    fn sample_boot_info(claimed_l2_block_number: u64) -> BootInfo {
        let rollup_config = base_common_chains::rollup_config!(ChainConfig::MAINNET);
        let l1_config = base_common_chains::L1_CONFIGS
            .get(&rollup_config.l1_chain_id)
            .expect("Base mainnet L1 config should exist")
            .clone();

        BootInfo {
            l1_head: B256::repeat_byte(0x11),
            agreed_l2_output_root: B256::repeat_byte(0x22),
            claimed_l2_output_root: B256::repeat_byte(0x33),
            claimed_l2_block_number,
            chain_id: rollup_config.l2_chain_id.id(),
            activation_admin_address: ChainConfig::MAINNET.activation_admin_address,
            rollup_config,
            l1_config,
            proposer: Address::ZERO,
            intermediate_block_interval: 0,
            l1_head_number: 0,
        }
    }

    fn sample_boot_info_struct() -> BootInfoStruct {
        BootInfoStruct::new(sample_boot_info(20), 10, 20, vec![B256::repeat_byte(0x44)])
    }

    #[test]
    fn boot_info_struct_uses_derived_l2_block_number() {
        let boot_info_struct = sample_boot_info_struct();
        assert_eq!(boot_info_struct.l2PreBlockNumber, 10);
        assert_eq!(boot_info_struct.l2BlockNumber, 20);
        assert_eq!(
            boot_info_struct.intermediateRoots,
            Bytes::from(B256::repeat_byte(0x44).to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "derived L2 block number must match claimed L2 block number")]
    fn boot_info_struct_rejects_mismatched_derived_l2_block_number() {
        let boot = sample_boot_info(20);
        let _ = BootInfoStruct::new(boot, 10, 19, Vec::new());
    }

    /// `hash_rollup_config` must match the nitro-enclave `CONFIG_HASH_*` constants
    /// hardcoded in `base-proof-tee-nitro-enclave/src/server.rs`. If this drifts,
    /// the on-chain rollup binding diverges from TEE attestations.
    #[test]
    fn test_config_hash_matches_nitro_enclave() {
        let cases: &[(u64, B256)] = &[
            (8453, b256!("1607709d90d40904f790574404e2ad614eac858f6162faa0ec34c6bf5e5f3c57")),
            (84532, b256!("12e9c45f19f9817c6d4385fad29e7a70c355502cf0883e76a9a7e478a85d1360")),
        ];

        for &(chain_id, expected) in cases {
            let rollup = base_common_chains::rollup_config!(chain_id)
                .unwrap_or_else(|| panic!("missing rollup config for chain {chain_id}"));
            let got = hash_rollup_config(&rollup);
            assert_eq!(got, expected, "config hash mismatch for chain {chain_id}");
        }
    }

    #[test]
    fn encode_decode_round_trip_preserves_boot_info() {
        let original = sample_boot_info_struct();
        let bytes = encode_boot_info(&original);
        let decoded = decode_boot_info(&bytes).expect("decode succeeds");

        assert_eq!(decoded.l1Head, original.l1Head);
        assert_eq!(decoded.l2PreRoot, original.l2PreRoot);
        assert_eq!(decoded.l2PostRoot, original.l2PostRoot);
        assert_eq!(decoded.l2PreBlockNumber, original.l2PreBlockNumber);
        assert_eq!(decoded.l2BlockNumber, original.l2BlockNumber);
        assert_eq!(decoded.rollupConfigHash, original.rollupConfigHash);
        assert_eq!(decoded.intermediateRoots, original.intermediateRoots);
    }

    #[test]
    fn boot_info_commitment_is_keccak_of_encoded_bytes() {
        let boot = sample_boot_info_struct();
        let commit = boot_info_commitment(&boot);
        assert_eq!(commit, keccak256(encode_boot_info(&boot)));
    }

    #[test]
    fn boot_info_commitment_changes_when_post_root_changes() {
        let mut a = sample_boot_info_struct();
        let b = sample_boot_info_struct();
        a.l2PostRoot = B256::repeat_byte(0x99);
        assert_ne!(boot_info_commitment(&a), boot_info_commitment(&b));
    }
}
