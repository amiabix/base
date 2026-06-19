use std::{sync::Arc, time::Instant};

use anyhow::{Context, Result};
use base_proof_succinct_host_utils::fetcher::OPSuccinctDataFetcher;
use base_proof_zisk_elfs::RANGE_ELF_EMBEDDED;
use base_proof_zisk_proof_utils::RangeWitnessCache;
use base_zk_service::{ZiskEmbeddedBackend, ZiskProvider, ZiskWitnessParams};
use tracing::info;
use zisk_sdk::{GuestProgram, ProofKind, ZiskStdin};

use crate::SmokeConfig;

/// Timings and receipt metadata emitted by one smoke run.
#[derive(Debug, Clone, Copy)]
pub struct SmokeRunOutput {
    /// Witness-generation or cache-load duration in milliseconds.
    pub witness_ms: f64,
    /// Program setup duration in milliseconds.
    pub setup_ms: f64,
    /// Proving duration in milliseconds.
    pub prove_ms: f64,
    /// End-to-end wall time in milliseconds.
    pub total_ms: f64,
    /// Raw verifier receipt byte length.
    pub receipt_bytes: usize,
}

/// Runner for the `ZisK` smoke harness.
#[derive(Debug, Clone, Copy)]
pub struct SmokeRunner;

impl SmokeRunner {
    /// Execute one range proof and optionally write the raw verifier receipt.
    pub async fn run(cfg: SmokeConfig) -> Result<SmokeRunOutput> {
        info!(
            start_block = cfg.start_block,
            num_blocks = cfg.num_blocks,
            sequence_window = cfg.sequence_window,
            intermediate_root_interval = cfg.intermediate_root_interval,
            witness_cache_dir = ?cfg.witness_cache_dir,
            refresh_witness_cache = cfg.refresh_witness_cache,
            receipt_output_path = ?cfg.receipt_output_path,
            "starting ZisK smoke test"
        );

        let t_total = Instant::now();
        let t_witness = Instant::now();
        let end_block = cfg.start_block + cfg.num_blocks;
        let cached_stdin = match (&cfg.witness_cache_dir, cfg.refresh_witness_cache) {
            (Some(cache_dir), false) => {
                RangeWitnessCache::load_stdin_from_cache(cache_dir, cfg.start_block, end_block)?
            }
            _ => None,
        };

        let (stdin, boot_info, witness_source) = match cached_stdin {
            Some(cached) => {
                info!(
                    path = %cached.stdin_path.display(),
                    boot_info_path = %cached.boot_info_path.display(),
                    boot_info_available = cached.boot_info.is_some(),
                    "loaded witness stdin from cache"
                );
                (cached.stdin, cached.boot_info, "cache")
            }
            None => {
                let rpc_config = cfg.rpc_config.as_ref().context(
                    "witness cache miss and L1_RPC/L2_RPC/L2_NODE_RPC are not all configured",
                )?;
                let fetcher = Arc::new(
                    OPSuccinctDataFetcher::from_rpc_config_with_rollup_config(rpc_config.clone())
                        .await?,
                );
                info!("data fetcher ready");

                let provider = ZiskProvider::new(Arc::clone(&fetcher));
                let (witness_bytes, boot_info) = provider
                    .generate_witness(ZiskWitnessParams {
                        start_block: cfg.start_block,
                        end_block,
                        sequence_window: cfg.sequence_window,
                        l1_node_url: rpc_config.l1_rpc.as_str(),
                        base_consensus_url: rpc_config.l2_node_rpc.as_str(),
                        l1_head: None,
                        intermediate_root_interval: cfg.intermediate_root_interval,
                    })
                    .await
                    .context("generate_witness failed")?;
                let stdin = ZiskStdin::from_bytes(witness_bytes);
                if let Some(cache_dir) = &cfg.witness_cache_dir {
                    let path = RangeWitnessCache::save_stdin_to_cache(
                        cache_dir,
                        cfg.start_block,
                        end_block,
                        &stdin,
                        &boot_info,
                    )?;
                    info!(path = %path.display(), "saved witness stdin to cache");
                }
                (stdin, Some(boot_info), "rpc")
            }
        };
        let witness_ms = t_witness.elapsed().as_secs_f64() * 1000.0;
        info!(
            witness_ms,
            source = witness_source,
            boot_info_available = boot_info.is_some(),
            "witness stdin ready"
        );
        if let Some(boot_info) = &boot_info {
            info!(
                l1_head = %boot_info.l1Head,
                l2_pre_block = boot_info.l2PreBlockNumber,
                l2_post_block = boot_info.l2BlockNumber,
                "witness boot info ready"
            );
        }

        let client = ZiskEmbeddedBackend::build_client(false)?;
        info!("embedded client built");

        let range_program =
            GuestProgram::from_bytes("range-elf-embedded", RANGE_ELF_EMBEDDED.to_vec());
        let t_setup = Instant::now();
        client.setup(&range_program).run()?.await?;
        let setup_ms = t_setup.elapsed().as_secs_f64() * 1000.0;
        info!(setup_ms, "range program setup complete");

        let t_prove = Instant::now();
        let prove_result =
            client.prove(&range_program, stdin).wrap(ProofKind::VadcopFinal).run()?.await?;
        let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

        let receipt = prove_result.get_proof_bytes()?;
        let total_ms = t_total.elapsed().as_secs_f64() * 1000.0;
        let output = SmokeRunOutput {
            witness_ms,
            setup_ms,
            prove_ms,
            total_ms,
            receipt_bytes: receipt.len(),
        };

        info!(
            witness_ms,
            setup_ms,
            prove_ms,
            total_ms,
            receipt_bytes = output.receipt_bytes,
            "range VadcopFinal proof complete"
        );

        if let Some(path) = &cfg.receipt_output_path {
            std::fs::write(path, &receipt).with_context(|| format!("write {}", path.display()))?;
            info!(path = %path.display(), "raw verifier receipt written");
        }

        Ok(output)
    }
}
