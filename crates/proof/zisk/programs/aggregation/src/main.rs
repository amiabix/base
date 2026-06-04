//! ZisK aggregation guest.
//!
//! Recursively verifies a sequence of range proofs and emits the final
//! `AggregationOutputs` digest. See `README.md` for the binding model.

#![cfg_attr(target_os = "zkvm", no_main)]
#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

use std::collections::HashMap;

use alloy_consensus::Header;
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_sol_types::SolValue;
use base_proof_zisk_client_utils::{
    AggregationInputs, AggregationOutputs, boot_info_commitment, VadcopProofPublics,
};

/// Aggregation program entry point.
pub fn main() {
    let agg_inputs: AggregationInputs = ziskos::io::read();
    let headers_bytes = ziskos::io::read_input_slice();
    let headers: Vec<Header> =
        serde_cbor::from_slice(&headers_bytes).expect("invalid aggregation header input");
    assert!(!agg_inputs.range_proofs.is_empty(), "no range proofs supplied");
    assert_eq!(
        agg_inputs.range_proofs.len(),
        agg_inputs.range_boot_infos.len(),
        "range proofs and boot infos length mismatch"
    );

    let mut boot_infos = Vec::with_capacity(agg_inputs.range_boot_infos.len());
    for (i, (proof_blob, boot_info)) in agg_inputs
        .range_proofs
        .iter()
        .zip(agg_inputs.range_boot_infos.iter())
        .enumerate()
    {
        let ok = unsafe {
            ziskos::zisklib::verify_zisk_proof_c(proof_blob.as_ptr(), proof_blob.len())
        };
        assert!(ok, "range proof {i} verify failed");

        let publics = VadcopProofPublics::parse(proof_blob)
            .expect("missing public values in verified proof blob");
        assert_eq!(
            publics.program_vk_b256(),
            agg_inputs.zisk_range_program_vk,
            "range program verification key mismatch"
        );
        assert_eq!(
            publics.committed_digest().expect("range proof must commit exactly one digest"),
            boot_info_commitment(boot_info),
            "range proof public digest mismatch"
        );
        boot_infos.push(boot_info.clone());
    }

    // Ranges must join exactly at their claimed roots and block numbers.
    boot_infos.windows(2).for_each(|pair| {
        let (prev, cur) = (&pair[0], &pair[1]);
        assert_eq!(prev.l2PostRoot, cur.l2PreRoot, "non-sequential output roots");
        assert_eq!(prev.l2BlockNumber, cur.l2PreBlockNumber, "non-sequential block numbers");
        assert_eq!(prev.rollupConfigHash, cur.rollupConfigHash, "rollup config mismatch");
    });

    // Walk the supplied L1 headers backwards from the checkpoint head.
    let mut l1_heads_map: HashMap<B256, bool> =
        boot_infos.iter().map(|bi| (bi.l1Head, false)).collect();
    let mut current_hash = agg_inputs.latest_l1_checkpoint_head;
    for header in headers.iter().rev() {
        assert_eq!(current_hash, header.hash_slow());
        if let Some(found) = l1_heads_map.get_mut(&current_hash) {
            *found = true;
        }
        current_hash = header.parent_hash;
    }
    for (l1_head, found) in &l1_heads_map {
        assert!(*found, "l1 head {l1_head:?} not in header chain");
    }

    let first = &boot_infos[0];
    let last = &boot_infos[boot_infos.len() - 1];

    let intermediate_roots: Bytes = boot_infos
        .iter()
        .flat_map(|bi| bi.intermediateRoots.iter().copied())
        .collect::<Vec<u8>>()
        .into();

    let agg_outputs = AggregationOutputs {
        proverAddress: agg_inputs.prover_address,
        l1Head: agg_inputs.latest_l1_checkpoint_head,
        l2PreRoot: first.l2PreRoot,
        startingL2SequenceNumber: first.l2PreBlockNumber,
        l2PostRoot: last.l2PostRoot,
        endingL2SequenceNumber: last.l2BlockNumber,
        intermediateRoots: intermediate_roots,
        rollupConfigHash: last.rollupConfigHash,
        imageHash: agg_inputs.zisk_range_program_vk,
    };

    // The contract checks this packed-output digest for PLONK aggregate proofs.
    let packed = agg_outputs.abi_encode_packed();
    let digest = keccak256(&packed);
    ziskos::io::commit_slice(digest.as_ref());
}
