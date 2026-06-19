use std::{env, path::PathBuf};

use anyhow::{Context, Result};
use base_proof_succinct_host_utils::fetcher::RPCConfig;
use url::Url;

/// Environment-driven configuration for the `ZisK` smoke harness.
#[derive(Debug, Clone)]
pub struct SmokeConfig {
    /// Optional RPC configuration used on witness cache misses.
    pub rpc_config: Option<RPCConfig>,
    /// First L2 block in the proved range.
    pub start_block: u64,
    /// Number of L2 blocks to prove.
    pub num_blocks: u64,
    /// Sequence-window size used when no L1 head is pinned.
    pub sequence_window: u64,
    /// Number of L2 blocks between sampled intermediate output roots.
    pub intermediate_root_interval: u64,
    /// Optional witness cache directory.
    pub witness_cache_dir: Option<PathBuf>,
    /// Whether to ignore any cached witness and fetch a fresh one.
    pub refresh_witness_cache: bool,
    /// Optional path for writing raw verifier receipt bytes.
    pub receipt_output_path: Option<PathBuf>,
}

impl SmokeConfig {
    /// Load configuration from process environment variables.
    pub fn from_env() -> Result<Self> {
        let start_block: u64 =
            env::var("START_BLOCK").context("START_BLOCK must be set")?.parse()?;
        let num_blocks: u64 = env::var("NUM_BLOCKS").unwrap_or_else(|_| "1".into()).parse()?;
        let sequence_window: u64 =
            env::var("SEQUENCE_WINDOW").unwrap_or_else(|_| "100".into()).parse()?;
        let intermediate_root_interval: u64 =
            env::var("INTERMEDIATE_ROOT_INTERVAL").unwrap_or_else(|_| "10".into()).parse()?;
        let witness_cache_dir =
            env::var("ZISK_WITNESS_CACHE_DIR").ok().filter(|s| !s.is_empty()).map(PathBuf::from);
        let refresh_witness_cache = env::var("ZISK_WITNESS_CACHE_REFRESH")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let receipt_output_path =
            env::var("RECEIPT_OUTPUT_PATH").ok().filter(|s| !s.is_empty()).map(PathBuf::from);

        let rpc_config = match (env::var("L1_RPC"), env::var("L2_RPC"), env::var("L2_NODE_RPC")) {
            (Ok(l1), Ok(l2), Ok(l2_node)) => {
                let l1_beacon = env::var("L1_BEACON_RPC").ok();
                Some(RPCConfig {
                    l1_rpc: Url::parse(&l1).context("L1_RPC must be a valid URL")?,
                    l1_beacon_rpc: l1_beacon.map(|s| Url::parse(&s)).transpose()?,
                    l2_rpc: Url::parse(&l2).context("L2_RPC must be a valid URL")?,
                    l2_node_rpc: Url::parse(&l2_node).context("L2_NODE_RPC must be a valid URL")?,
                })
            }
            _ => None,
        };

        Ok(Self {
            rpc_config,
            start_block,
            num_blocks,
            sequence_window,
            intermediate_root_interval,
            witness_cache_dir,
            refresh_witness_cache,
            receipt_output_path,
        })
    }
}
