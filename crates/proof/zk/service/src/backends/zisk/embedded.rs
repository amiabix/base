//! Embedded ZisK proving backend.
//!
//! Submits range VADCOP proofs in-process and queues the aggregation/PLONK
//! stage after a PLONK request has a completed range proof.

use std::{collections::HashMap, env, sync::Arc, time::Duration};

use alloy_eips::BlockId;
use async_trait::async_trait;
use base_proof_zisk_client_utils::{
    BootInfoStruct, DEFAULT_INTERMEDIATE_ROOT_INTERVAL, VadcopProofPublics, boot_info_commitment,
};
use base_proof_zisk_elfs::{AGGREGATION_ELF, RANGE_ELF_EMBEDDED};
use base_proof_zisk_proof_utils::{
    ZiskProofBlob, decode_boot_info_commitment_from_proof, get_agg_proof_stdin,
};
use base_zk_client::ProveBlockRequest;
use base_zk_db::{
    CreateProofSession, ProofRequest, ProofRequestRepo, ProofSession, ProofStatus, ProofType,
    SessionStatus as DbSessionStatus, SessionType,
};
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;
use zisk_sdk::{EmbeddedClient, EmbeddedOpts, GuestProgram, ProofKind, ProverClient, ZiskStdin};

use super::provider::{WitnessParams, ZiskProvider};
use crate::backends::traits::{
    BackendConfig, BackendType, ProofProcessingResult, ProveResult, ProvingBackend, SessionStatus,
};

/// Embedded `ZisK` backend.
pub struct EmbeddedBackend {
    provider: ZiskProvider,
    config: BackendConfig,
    client: EmbeddedClient,
    range_program: GuestProgram,
    aggregation_program: GuestProgram,
    /// In-flight prover jobs keyed by backend session id.
    jobs: Arc<Mutex<HashMap<Uuid, JobOutcome>>>,
}

/// Result captured after an embedded prover task returns.
#[derive(Debug, Clone)]
enum JobOutcome {
    Running,
    Completed { receipt: Vec<u8>, boot_info: Option<BootInfoStruct> },
    Failed { reason: String },
}

impl std::fmt::Debug for EmbeddedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZiskEmbeddedBackend").finish_non_exhaustive()
    }
}

impl EmbeddedBackend {
    /// Construct an embedded backend.
    ///
    /// `ProverClient::embedded()` is process-global in the v0.18 SDK, so callers
    /// must serialize backend construction.
    pub fn new(provider: ZiskProvider, config: BackendConfig) -> anyhow::Result<Self> {
        let plonk_enabled = match &config {
            BackendConfig::Zisk { plonk_enabled, .. } => *plonk_enabled,
            _ => return Err(anyhow::anyhow!("ZiskEmbeddedBackend requires BackendConfig::Zisk")),
        };

        let client = Self::build_client(plonk_enabled)?;
        let range_program =
            GuestProgram::from_bytes("range-elf-embedded", RANGE_ELF_EMBEDDED.to_vec());
        let aggregation_program =
            GuestProgram::from_bytes("aggregation-elf", AGGREGATION_ELF.to_vec());

        Ok(Self {
            provider,
            config,
            client,
            range_program,
            aggregation_program,
            jobs: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Build the embedded client from env-controlled execution/proving settings.
    ///
    /// The default path is minimal-memory emulator proving. Set
    /// `BASE_ZISK_EXECUTOR=assembly` for ASM execution and `BASE_ZISK_GPU=1` for
    /// GPU proving.
    pub fn build_client(plonk_enabled: bool) -> anyhow::Result<EmbeddedClient> {
        let mut opts = EmbeddedOpts::default().minimal_memory();
        if let Ok(value) = env::var("BASE_ZISK_MAX_STREAMS") {
            let max_streams = value.parse::<usize>().map_err(|err| {
                anyhow::anyhow!("BASE_ZISK_MAX_STREAMS must be a positive integer: {err}")
            })?;
            if max_streams == 0 {
                return Err(anyhow::anyhow!("BASE_ZISK_MAX_STREAMS must be greater than zero"));
            }
            info!(max_streams, "limiting ZisK GPU streams");
            opts = opts.max_streams(max_streams);
        }
        if let Ok(value) = env::var("BASE_ZISK_WITNESS_THREADS") {
            let witness_threads = value.parse::<usize>().map_err(|err| {
                anyhow::anyhow!("BASE_ZISK_WITNESS_THREADS must be a positive integer: {err}")
            })?;
            if witness_threads == 0 {
                return Err(anyhow::anyhow!("BASE_ZISK_WITNESS_THREADS must be greater than zero"));
            }
            info!(witness_threads, "limiting ZisK witness worker threads");
            opts = opts.number_threads_witness(witness_threads);
        }
        if let Ok(value) = env::var("BASE_ZISK_MAX_WITNESS_STORED") {
            let max_witness_stored = value.parse::<usize>().map_err(|err| {
                anyhow::anyhow!("BASE_ZISK_MAX_WITNESS_STORED must be a positive integer: {err}")
            })?;
            if max_witness_stored == 0 {
                return Err(anyhow::anyhow!(
                    "BASE_ZISK_MAX_WITNESS_STORED must be greater than zero"
                ));
            }
            info!(max_witness_stored, "limiting ZisK queued GPU witnesses");
            opts = opts.max_witness_stored(max_witness_stored);
        }
        let mut builder = ProverClient::embedded().with_embedded_opts(opts);

        if env::var("BASE_ZISK_EXECUTOR").as_deref() == Ok("assembly") {
            builder = builder.assembly();
        }
        if env::var("BASE_ZISK_GPU").as_deref() == Ok("1") {
            builder = builder.gpu();
        }
        if plonk_enabled {
            builder = builder.plonk();
        }

        builder.build()
    }

    /// Compute the proof-request status from the attached session set.
    fn determine_status(proof_type: ProofType, sessions: &[ProofSession]) -> ProofProcessingResult {
        if sessions.is_empty() {
            return ProofProcessingResult { status: ProofStatus::Pending, error_message: None };
        }
        for s in sessions {
            if s.status == DbSessionStatus::Failed {
                return ProofProcessingResult {
                    status: ProofStatus::Failed,
                    error_message: s.error_message.clone(),
                };
            }
        }
        match proof_type {
            ProofType::ZiskVadcop => {
                let done = sessions.iter().all(|s| s.status == DbSessionStatus::Completed);
                if done {
                    ProofProcessingResult { status: ProofStatus::Succeeded, error_message: None }
                } else {
                    ProofProcessingResult { status: ProofStatus::Running, error_message: None }
                }
            }
            ProofType::ZiskPlonk => {
                let stark = sessions.iter().any(|s| {
                    s.session_type == SessionType::Stark && s.status == DbSessionStatus::Completed
                });
                let snark = sessions.iter().any(|s| {
                    s.session_type == SessionType::Snark && s.status == DbSessionStatus::Completed
                });
                if stark && snark {
                    ProofProcessingResult { status: ProofStatus::Succeeded, error_message: None }
                } else {
                    ProofProcessingResult { status: ProofStatus::Running, error_message: None }
                }
            }
            other => ProofProcessingResult {
                status: ProofStatus::Failed,
                error_message: Some(format!(
                    "ZiskEmbeddedBackend invoked with non-ZisK proof type: {other:?}",
                )),
            },
        }
    }
}

#[async_trait]
impl ProvingBackend for EmbeddedBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Zisk
    }

    async fn prove(&self, request: &ProveBlockRequest) -> anyhow::Result<ProveResult> {
        let BackendConfig::Zisk {
            default_sequence_window,
            l1_node_url,
            base_consensus_url,
            plonk_enabled,
            timeout_hours,
            ..
        } = &self.config
        else {
            unreachable!("validated in constructor");
        };
        let proof_type = ProofType::try_from(request.proof_type).map_err(anyhow::Error::msg)?;
        if proof_type == ProofType::ZiskPlonk && !plonk_enabled {
            return Err(anyhow::anyhow!(
                "ZisK PLONK requests require BackendConfig::Zisk.plonk_enabled=true"
            ));
        }

        let start = request.start_block_number;
        let end = start + request.number_of_blocks_to_prove;
        let sw = request.sequence_window.unwrap_or(*default_sequence_window);
        let l1_head = request
            .l1_head
            .as_ref()
            .map(|h| h.parse::<alloy_primitives::B256>())
            .transpose()
            .map_err(|e| anyhow::anyhow!("invalid l1_head: {e}"))?;
        let iri = request.intermediate_root_interval.unwrap_or(DEFAULT_INTERMEDIATE_ROOT_INTERVAL);

        // Keep witness generation outside the prover task so request metadata
        // includes timing and boot info.
        let witness_start = std::time::Instant::now();
        let (witness_bytes, boot_info) = self
            .provider
            .generate_witness(WitnessParams {
                start_block: start,
                end_block: end,
                sequence_window: sw,
                l1_node_url,
                base_consensus_url,
                l1_head,
                intermediate_root_interval: iri,
            })
            .await?;
        let wgen_ms = witness_start.elapsed().as_secs_f64() * 1000.0;

        info!(
            start,
            end,
            wgen_ms,
            witness_bytes = witness_bytes.len(),
            "ZisK witness generated, queuing embedded prove"
        );

        // The normal status path polls this map and persists completed receipts.
        let session_id = Uuid::new_v4();
        self.jobs.lock().await.insert(session_id, JobOutcome::Running);

        self.spawn_range_prove(session_id, witness_bytes, boot_info.clone(), *timeout_hours).await;

        Ok(ProveResult {
            session_id: Some(session_id.to_string()),
            metadata: Some(json!({
                "stage": "range",
                "witness_gen_ms": wgen_ms,
                "boot_info": boot_info,
            })),
            witness_gen_duration_ms: Some(wgen_ms),
        })
    }

    async fn process_proof_request(
        &self,
        proof_request: &ProofRequest,
        repo: &ProofRequestRepo,
    ) -> anyhow::Result<ProofProcessingResult> {
        let sessions = repo.get_sessions_for_request(proof_request.id).await?;

        // Fold completed prover tasks back into the DB before deriving status.
        for s in &sessions {
            if s.status == DbSessionStatus::Running
                && let Err(err) = self.sync_session(proof_request.id, s, repo).await
            {
                warn!(
                    proof_request_id = %proof_request.id,
                    session_id = %s.backend_session_id,
                    error = %err,
                    "failed to sync ZisK session - will retry on next poll"
                );
            }
        }
        let refreshed = repo.get_sessions_for_request(proof_request.id).await?;

        // PLONK requests start the aggregation job once the range receipt lands.
        if proof_request.proof_type == ProofType::ZiskPlonk {
            let stark_done = refreshed.iter().any(|s| {
                s.session_type == SessionType::Stark && s.status == DbSessionStatus::Completed
            });
            let has_snark = refreshed.iter().any(|s| s.session_type == SessionType::Snark);
            if stark_done && !has_snark {
                info!(
                    proof_request_id = %proof_request.id,
                    "range VADCOP complete, queuing aggregation+plonk wrap"
                );
                self.queue_aggregation_plonk(proof_request, repo).await?;
            }
        }

        Ok(Self::determine_status(proof_request.proof_type, &refreshed))
    }

    async fn get_session_status(&self, session: &ProofSession) -> anyhow::Result<SessionStatus> {
        let id: Uuid = session
            .backend_session_id
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid ZisK session id: {e}"))?;
        match self.jobs.lock().await.get(&id) {
            Some(JobOutcome::Running) => Ok(SessionStatus::Running),
            Some(JobOutcome::Completed { .. }) => Ok(SessionStatus::Completed),
            Some(JobOutcome::Failed { reason }) => Ok(SessionStatus::Failed(reason.clone())),
            None => Ok(SessionStatus::NotFound),
        }
    }

    fn name(&self) -> &'static str {
        "ZisK (embedded)"
    }
}

impl EmbeddedBackend {
    /// Queue a range VADCOP proof job.
    pub async fn spawn_range_prove(
        &self,
        session_id: Uuid,
        witness_bytes: Vec<u8>,
        boot_info: BootInfoStruct,
        timeout_hours: u64,
    ) {
        let jobs = Arc::clone(&self.jobs);
        let client = self.client.clone();
        let program = self.range_program.clone();
        let timeout = proof_timeout(timeout_hours);

        tokio::spawn(async move {
            let outcome = match run_range_prove(client, program, witness_bytes, timeout).await {
                Ok(receipt) => JobOutcome::Completed { receipt, boot_info: Some(boot_info) },
                Err(error) => JobOutcome::Failed { reason: error.to_string() },
            };
            jobs.lock().await.insert(session_id, outcome);
        });
    }

    /// Queue an aggregation proof followed by a PLONK wrap.
    pub async fn spawn_aggregation_plonk(
        &self,
        session_id: Uuid,
        stdin: ZiskStdin,
        timeout_hours: u64,
    ) {
        let jobs = Arc::clone(&self.jobs);
        let client = self.client.clone();
        let program = self.aggregation_program.clone();
        let timeout = proof_timeout(timeout_hours);

        tokio::spawn(async move {
            let outcome = match run_aggregation_plonk(client, program, stdin, timeout).await {
                Ok(receipt) => JobOutcome::Completed { receipt, boot_info: None },
                Err(error) => JobOutcome::Failed { reason: error.to_string() },
            };
            jobs.lock().await.insert(session_id, outcome);
        });
    }

    /// Reserve and activate the aggregation/PLONK session, then queue the job.
    pub async fn queue_aggregation_plonk(
        &self,
        proof_request: &ProofRequest,
        repo: &ProofRequestRepo,
    ) -> anyhow::Result<()> {
        let BackendConfig::Zisk { timeout_hours, .. } = &self.config else {
            unreachable!("validated in constructor");
        };

        let reservation_id =
            match repo.reserve_proof_session(proof_request.id, SessionType::Snark).await? {
                Some(id) => id,
                None => return Ok(()),
            };

        let result = self.prepare_aggregation_stdin(proof_request, repo).await;
        let stdin = match result {
            Ok(stdin) => stdin,
            Err(error) => {
                repo.fail_reserved_proof_session(
                    proof_request.id,
                    SessionType::Snark,
                    &reservation_id,
                    &error.to_string(),
                )
                .await?;
                return Err(error);
            }
        };

        let session_id = Uuid::new_v4();
        let create = CreateProofSession {
            proof_request_id: proof_request.id,
            session_type: SessionType::Snark,
            backend_session_id: session_id.to_string(),
            metadata: Some(json!({"stage": "aggregation_plonk"})),
        };
        let activated = repo.activate_reserved_proof_session(&reservation_id, create).await?;
        if !activated {
            warn!(
                proof_request_id = %proof_request.id,
                reservation_id,
                "ZisK aggregation reservation was no longer active"
            );
            return Ok(());
        }

        self.jobs.lock().await.insert(session_id, JobOutcome::Running);
        self.spawn_aggregation_plonk(session_id, stdin, *timeout_hours).await;
        Ok(())
    }

    /// Build the aggregation guest stdin from the stored range proof receipt.
    ///
    /// This performs a cheap public-digest precheck against the stored
    /// `boot_info`; the aggregation guest performs the cryptographic range
    /// proof verification before trusting those public values.
    pub async fn prepare_aggregation_stdin(
        &self,
        proof_request: &ProofRequest,
        repo: &ProofRequestRepo,
    ) -> anyhow::Result<ZiskStdin> {
        let stark_receipt = proof_request
            .stark_receipt
            .clone()
            .ok_or_else(|| anyhow::anyhow!("ZisK range receipt missing for aggregation"))?;
        let proof_blob = ZiskProofBlob::new(stark_receipt.clone());
        let boot_info = self.range_boot_info_from_metadata(proof_request, repo).await?;
        let proof_commitment = decode_boot_info_commitment_from_proof(&proof_blob)?;
        let expected_commitment = boot_info_commitment(&boot_info);
        if proof_commitment != expected_commitment {
            return Err(anyhow::anyhow!(
                "ZisK range proof public digest does not match stored boot_info"
            ));
        }
        let parsed_publics = VadcopProofPublics::parse(&stark_receipt)
            .ok_or_else(|| anyhow::anyhow!("invalid ZisK range proof public layout"))?;
        let prover_address = proof_request
            .prover_address
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("ZisK PLONK aggregation requires prover_address"))?
            .parse()?;

        let latest_l1_checkpoint_head = boot_info.l1Head;
        let header = self
            .provider
            .fetcher()
            .get_l1_header(BlockId::Hash(latest_l1_checkpoint_head.into()))
            .await?;
        let headers_bytes = serde_cbor::to_vec(&vec![header])?;
        let agg_inputs = get_agg_proof_stdin(
            vec![proof_blob],
            vec![boot_info],
            latest_l1_checkpoint_head,
            prover_address,
            parsed_publics.program_vk_b256(),
        )?;

        let stdin = ZiskStdin::new();
        stdin.write(&agg_inputs);
        stdin.write_slice(&headers_bytes);
        Ok(stdin)
    }

    /// Load the BootInfoStruct produced during range witness generation.
    async fn range_boot_info_from_metadata(
        &self,
        proof_request: &ProofRequest,
        repo: &ProofRequestRepo,
    ) -> anyhow::Result<BootInfoStruct> {
        let sessions = repo.get_sessions_for_request(proof_request.id).await?;
        let stark_session = sessions
            .iter()
            .find(|session| {
                session.session_type == SessionType::Stark
                    && session.status == DbSessionStatus::Completed
            })
            .ok_or_else(|| anyhow::anyhow!("completed ZisK range session not found"))?;
        let metadata = stark_session
            .metadata
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ZisK range session metadata missing"))?;
        let boot_info = metadata
            .get("boot_info")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("ZisK range session boot_info metadata missing"))?;
        serde_json::from_value(boot_info)
            .map_err(|e| anyhow::anyhow!("invalid ZisK range session boot_info metadata: {e}"))
    }

    /// Sync a single Running session: if the in-memory job has terminated,
    /// reflect that into the DB row. Errors here are transient and surfaced
    /// to the caller for retry.
    async fn sync_session(
        &self,
        proof_request_id: Uuid,
        session: &ProofSession,
        repo: &ProofRequestRepo,
    ) -> anyhow::Result<()> {
        let id: Uuid = session
            .backend_session_id
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid ZisK session id: {e}"))?;

        let outcome = {
            let jobs = self.jobs.lock().await;
            jobs.get(&id).cloned().unwrap_or(JobOutcome::Running)
        };

        match outcome {
            JobOutcome::Running => Ok(()),
            JobOutcome::Completed { receipt, boot_info } => {
                let metadata = if let Some(boot_info) = boot_info {
                    let mut metadata = session.metadata.clone().unwrap_or_else(|| json!({}));
                    if let Some(object) = metadata.as_object_mut() {
                        object.insert("boot_info".to_string(), serde_json::to_value(boot_info)?);
                    }
                    Some(metadata)
                } else {
                    session.metadata.clone()
                };
                let update = base_zk_db::UpdateReceipt {
                    id: proof_request_id,
                    stark_receipt: match session.session_type {
                        SessionType::Stark => Some(receipt.clone()),
                        SessionType::Snark => None,
                    },
                    snark_receipt: match session.session_type {
                        SessionType::Snark => Some(receipt),
                        SessionType::Stark => None,
                    },
                    status: ProofStatus::Running,
                    error_message: None,
                };
                repo.update_receipt_if_running(update).await?;
                let session_update = base_zk_db::UpdateProofSession {
                    backend_session_id: session.backend_session_id.clone(),
                    status: DbSessionStatus::Completed,
                    error_message: None,
                    metadata,
                };
                repo.update_proof_session(session_update).await?;
                Ok(())
            }
            JobOutcome::Failed { reason } => {
                let session_update = base_zk_db::UpdateProofSession {
                    backend_session_id: session.backend_session_id.clone(),
                    status: DbSessionStatus::Failed,
                    error_message: Some(reason),
                    metadata: session.metadata.clone(),
                };
                repo.update_proof_session(session_update).await?;
                Ok(())
            }
        }
    }
}

/// Convert a timeout-hour setting into an optional duration.
const fn proof_timeout(timeout_hours: u64) -> Option<Duration> {
    if timeout_hours == 0 { None } else { Some(Duration::from_secs(timeout_hours * 3600)) }
}

/// Run a range proof and return verifier-shaped VADCOP bytes.
async fn run_range_prove(
    client: EmbeddedClient,
    program: GuestProgram,
    witness_bytes: Vec<u8>,
    timeout: Option<Duration>,
) -> anyhow::Result<Vec<u8>> {
    let mut setup = client.setup(&program);
    if let Some(timeout) = timeout {
        setup = setup.timeout(timeout);
    }
    setup.run()?.await?;

    let stdin = ZiskStdin::from_bytes(witness_bytes);
    let mut prove = client.prove(&program, stdin).wrap(ProofKind::VadcopFinal);
    if let Some(timeout) = timeout {
        prove = prove.timeout(timeout);
    }
    let result = prove.run()?.await?;
    result.get_proof_bytes()
}

/// Run the aggregation guest and wrap the result to a PLONK proof.
async fn run_aggregation_plonk(
    client: EmbeddedClient,
    program: GuestProgram,
    stdin: ZiskStdin,
    timeout: Option<Duration>,
) -> anyhow::Result<Vec<u8>> {
    let mut setup = client.setup(&program);
    if let Some(timeout) = timeout {
        setup = setup.timeout(timeout);
    }
    setup.run()?.await?;

    let mut prove = client.prove(&program, stdin).wrap(ProofKind::Plonk);
    if let Some(timeout) = timeout {
        prove = prove.timeout(timeout);
    }
    let result = prove.run()?.await?;
    bincode::serde::encode_to_vec(result.get_proof(), bincode::config::standard())
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn make_session(session_type: SessionType, status: DbSessionStatus) -> ProofSession {
        ProofSession {
            id: 1,
            proof_request_id: Uuid::new_v4(),
            session_type,
            backend_session_id: Uuid::new_v4().to_string(),
            status,
            error_message: None,
            metadata: None,
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    #[test]
    fn determine_status_vadcop_running_until_completed() {
        let sessions = vec![make_session(SessionType::Stark, DbSessionStatus::Running)];
        let result = EmbeddedBackend::determine_status(ProofType::ZiskVadcop, &sessions);
        assert_eq!(result.status, ProofStatus::Running);
    }

    #[test]
    fn determine_status_vadcop_completed_succeeds() {
        let sessions = vec![make_session(SessionType::Stark, DbSessionStatus::Completed)];
        let result = EmbeddedBackend::determine_status(ProofType::ZiskVadcop, &sessions);
        assert_eq!(result.status, ProofStatus::Succeeded);
    }

    #[test]
    fn determine_status_plonk_requires_both_sessions_completed() {
        let only_stark = vec![make_session(SessionType::Stark, DbSessionStatus::Completed)];
        let result = EmbeddedBackend::determine_status(ProofType::ZiskPlonk, &only_stark);
        assert_eq!(result.status, ProofStatus::Running);

        let both = vec![
            make_session(SessionType::Stark, DbSessionStatus::Completed),
            make_session(SessionType::Snark, DbSessionStatus::Completed),
        ];
        let result = EmbeddedBackend::determine_status(ProofType::ZiskPlonk, &both);
        assert_eq!(result.status, ProofStatus::Succeeded);
    }

    #[test]
    fn determine_status_failure_short_circuits() {
        let mut failed = make_session(SessionType::Snark, DbSessionStatus::Failed);
        failed.error_message = Some("witness_gen failed".to_string());
        let result = EmbeddedBackend::determine_status(ProofType::ZiskPlonk, &[failed]);
        assert_eq!(result.status, ProofStatus::Failed);
    }

    #[test]
    fn determine_status_rejects_non_zisk_proof_types() {
        let result = EmbeddedBackend::determine_status(
            ProofType::OpSuccinctSp1ClusterCompressed,
            &[make_session(SessionType::Stark, DbSessionStatus::Completed)],
        );
        assert_eq!(result.status, ProofStatus::Failed);
    }
}
