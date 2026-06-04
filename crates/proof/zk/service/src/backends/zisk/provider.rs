//! Witness generation for the `ZisK` embedded prover.
//!
//! The L1/L2/beacon/consensus RPC layer is zkVM-neutral, so this provider
//! fetches data with the existing Base host layer and converts the result into
//! the ZisK-native rkyv layout consumed by the range guest.

use std::{fmt, sync::Arc};

use alloy_primitives::B256;
use anyhow::Result;
use base_proof_succinct_ethereum_host_utils::host::SingleChainOPSuccinctHost;
use base_proof_succinct_host_utils::{fetcher::OPSuccinctDataFetcher, host::OPSuccinctHost};
use base_proof_zisk_client_utils::{
    BlobData as ZiskBlobData, BootInfoStruct, DefaultWitnessData as ZiskDefaultWitnessData,
    KzgBlob, KzgBytes48, PreimageStore as ZiskPreimageStore,
};
use rkyv::to_bytes;
use tracing::info;

use crate::backends::utils::L1HeadCalculator;

/// Inputs to [`ZiskProvider::generate_witness`].
#[derive(Debug, Clone, Copy)]
pub struct WitnessParams<'a> {
    /// First L2 block in the range (inclusive).
    pub start_block: u64,
    /// Block past the last L2 block in the range (exclusive).
    pub end_block: u64,
    /// Sequence-window size used when `l1_head` is not pinned by the caller.
    pub sequence_window: u64,
    /// L1 execution-layer RPC URL.
    pub l1_node_url: &'a str,
    /// Base consensus-layer RPC URL.
    pub base_consensus_url: &'a str,
    /// Caller-pinned L1 head hash. When `None`, the fetcher computes one.
    pub l1_head: Option<B256>,
    /// Number of L2 blocks between sampled intermediate output roots.
    pub intermediate_root_interval: u64,
}

/// Provider that turns a block range into the rkyv-encoded witness bytes
/// the `ZisK` range guest reads from `ziskos::io::read_input_slice`.
#[derive(Clone)]
pub struct ZiskProvider {
    host: Arc<SingleChainOPSuccinctHost>,
}

impl fmt::Debug for ZiskProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZiskProvider").finish_non_exhaustive()
    }
}

impl ZiskProvider {
    /// Construct a provider from a shared data fetcher.
    pub fn new(fetcher: Arc<OPSuccinctDataFetcher>) -> Self {
        info!("initializing ZisK provider");
        let host = Arc::new(SingleChainOPSuccinctHost::new(fetcher));
        Self { host }
    }

    /// Borrow the underlying data fetcher (used by the aggregation phase to
    /// fetch L1 header preimages for the chain-walk check).
    pub fn fetcher(&self) -> &Arc<OPSuccinctDataFetcher> {
        &self.host.fetcher
    }

    /// Produce the rkyv witness blob the range guest expects.
    pub async fn generate_witness(
        &self,
        params: WitnessParams<'_>,
    ) -> Result<(Vec<u8>, BootInfoStruct)> {
        let WitnessParams {
            start_block,
            end_block,
            sequence_window,
            l1_node_url,
            base_consensus_url,
            l1_head,
            intermediate_root_interval,
        } = params;

        info!(
            start_block,
            end_block,
            sequence_window,
            intermediate_root_interval,
            l1_head = ?l1_head,
            "generating ZisK witness"
        );

        let host_args = match l1_head {
            Some(hash) => {
                info!(hash = %hash, "using caller-provided l1_head");
                self.host
                    .fetch(start_block, end_block, Some(hash), intermediate_root_interval, false)
                    .await?
            }
            None => match self
                .host
                .fetch(start_block, end_block, None, intermediate_root_interval, false)
                .await
            {
                Ok(args) => {
                    info!("l1 head calculated via SafeDB");
                    args
                }
                Err(safe_db_err) => {
                    info!(
                        error = %safe_db_err,
                        sequence_window,
                        "SafeDB unavailable, falling back to sequence_window"
                    );
                    let (_l1_head_block_num, l1_head_hash) = L1HeadCalculator::calculate_l1_head(
                        l1_node_url,
                        base_consensus_url,
                        end_block,
                        sequence_window,
                    )
                    .await?;
                    self.host
                        .fetch(
                            start_block,
                            end_block,
                            Some(l1_head_hash),
                            intermediate_root_interval,
                            false,
                        )
                        .await?
                }
            },
        };

        let witness = self.host.run(&host_args).await?;
        let zisk_witness = ZiskDefaultWitnessData {
            preimage_store: ZiskPreimageStore { preimage_map: witness.preimage_store.preimage_map },
            blob_data: ZiskBlobData {
                blobs: witness.blob_data.blobs.into_iter().map(|blob| KzgBlob(blob.0)).collect(),
                commitments: witness
                    .blob_data
                    .commitments
                    .into_iter()
                    .map(|commitment| KzgBytes48(commitment.0))
                    .collect(),
                proofs: witness
                    .blob_data
                    .proofs
                    .into_iter()
                    .map(|proof| KzgBytes48(proof.0))
                    .collect(),
            },
        };
        let boot_info = zisk_witness.derive_boot_info().await?;
        let bytes = to_bytes::<rkyv::rancor::Error>(&zisk_witness)?;
        Ok((bytes.to_vec(), boot_info))
    }
}
