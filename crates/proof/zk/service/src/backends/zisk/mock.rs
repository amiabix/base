//! Mock `ZisK` backend that produces deterministic synthetic proofs for tests.
//!
//! No witness generation, no prover client, no I/O. Every `prove` call writes
//! a fixed VADCOP receipt immediately; `ZiskPlonk` requests additionally
//! materialize a fixed Plonk receipt after the VADCOP session completes.

use std::{collections::HashMap, sync::Mutex};

use alloy_primitives::B256;
use async_trait::async_trait;
use base_proof_zisk_client_utils::BootInfoStruct;
use base_zk_client::ProveBlockRequest;
use base_zk_db::{
    CreateProofSession, ProofRequest, ProofRequestRepo, ProofSession, ProofStatus, ProofType,
    SessionStatus as DbSessionStatus, SessionType, UpdateReceipt,
};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

use crate::backends::traits::{
    BackendType, ProofProcessingResult, ProveResult, ProvingBackend, SessionStatus,
};

/// Synthetic `ZisK` proof bytes used by the mock receipt path. The shape is
/// opaque to the verifier; the mock backend's receipts are never expected to
/// pass `verify_zisk_proof_c`.
const MOCK_STARK_PROOF: &[u8] = b"mock-zisk-stark-receipt-v1";
const MOCK_PLONK_PROOF: &[u8] = b"mock-zisk-plonk-receipt-v1";

/// Mock backend producing fixed receipts without invoking any `ZisK` prover.
pub struct MockBackend {
    sessions: Mutex<HashMap<String, ()>>,
}

impl std::fmt::Debug for MockBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZiskMockBackend").finish_non_exhaustive()
    }
}

impl MockBackend {
    /// Construct a fresh mock backend with no in-flight sessions.
    pub fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()) }
    }

    fn build_mock_boot_info(request: &ProveBlockRequest) -> BootInfoStruct {
        let start = request.start_block_number;
        let end = start + request.number_of_blocks_to_prove;
        BootInfoStruct {
            l1Head: B256::repeat_byte(0x11),
            l2PreRoot: B256::repeat_byte(0x22),
            l2PostRoot: B256::repeat_byte(0x33),
            l2PreBlockNumber: start,
            l2BlockNumber: end,
            rollupConfigHash: B256::repeat_byte(0x44),
            intermediateRoots: Default::default(),
        }
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProvingBackend for MockBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Zisk
    }

    async fn prove(&self, request: &ProveBlockRequest) -> anyhow::Result<ProveResult> {
        let session_id = Uuid::new_v4().to_string();
        self.sessions.lock().expect("mock sessions mutex").insert(session_id.clone(), ());

        let boot_info = Self::build_mock_boot_info(request);
        info!(
            session_id = %session_id,
            start_block = boot_info.l2PreBlockNumber,
            end_block = boot_info.l2BlockNumber,
            "ZiskMockBackend issuing synthetic STARK receipt"
        );

        Ok(ProveResult {
            session_id: Some(session_id),
            metadata: Some(json!({
                "stage": "range",
                "mock": true,
            })),
            witness_gen_duration_ms: Some(0.0),
        })
    }

    async fn process_proof_request(
        &self,
        proof_request: &ProofRequest,
        repo: &ProofRequestRepo,
    ) -> anyhow::Result<ProofProcessingResult> {
        let sessions = repo.get_sessions_for_request(proof_request.id).await?;

        // Mark every Running session as Completed, attaching the fixed STARK receipt.
        for session in &sessions {
            if session.status == DbSessionStatus::Running
                && session.session_type == SessionType::Stark
            {
                let update = UpdateReceipt {
                    id: proof_request.id,
                    stark_receipt: Some(MOCK_STARK_PROOF.to_vec()),
                    snark_receipt: None,
                    status: ProofStatus::Running,
                    error_message: None,
                };
                repo.complete_session_and_update_receipt(&session.backend_session_id, update)
                    .await?;
            }
        }
        let refreshed = repo.get_sessions_for_request(proof_request.id).await?;

        // For ZiskPlonk requests, materialize a SNARK session with the mock Plonk receipt
        // once the STARK is complete.
        if proof_request.proof_type == ProofType::ZiskPlonk {
            let stark_done = refreshed.iter().any(|s| {
                s.session_type == SessionType::Stark && s.status == DbSessionStatus::Completed
            });
            let has_snark = refreshed.iter().any(|s| s.session_type == SessionType::Snark);
            if stark_done && !has_snark {
                let reservation_id = match repo
                    .reserve_proof_session(proof_request.id, SessionType::Snark)
                    .await?
                {
                    Some(id) => id,
                    None => {
                        return Ok(Self::determine_status(proof_request.proof_type, &refreshed));
                    }
                };
                let create = CreateProofSession {
                    proof_request_id: proof_request.id,
                    session_type: SessionType::Snark,
                    backend_session_id: Uuid::new_v4().to_string(),
                    metadata: Some(json!({"mock": true, "stage": "plonk"})),
                };
                let backend_session_id = create.backend_session_id.clone();
                repo.activate_reserved_proof_session(&reservation_id, create).await?;

                let update = UpdateReceipt {
                    id: proof_request.id,
                    stark_receipt: None,
                    snark_receipt: Some(MOCK_PLONK_PROOF.to_vec()),
                    status: ProofStatus::Running,
                    error_message: None,
                };
                repo.complete_session_and_update_receipt(&backend_session_id, update).await?;
                let after = repo.get_sessions_for_request(proof_request.id).await?;
                return Ok(Self::determine_status(proof_request.proof_type, &after));
            }
        }

        Ok(Self::determine_status(proof_request.proof_type, &refreshed))
    }

    async fn get_session_status(&self, session: &ProofSession) -> anyhow::Result<SessionStatus> {
        let known = self
            .sessions
            .lock()
            .expect("mock sessions mutex")
            .contains_key(&session.backend_session_id);
        if known { Ok(SessionStatus::Completed) } else { Ok(SessionStatus::NotFound) }
    }

    fn name(&self) -> &'static str {
        "ZisK (mock)"
    }
}

impl MockBackend {
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
                    "ZiskMockBackend invoked with non-ZisK proof type: {other:?}",
                )),
            },
        }
    }
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
            backend_session_id: "test-session".to_string(),
            status,
            error_message: None,
            metadata: None,
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    #[test]
    fn determine_status_empty_returns_pending() {
        let result = MockBackend::determine_status(ProofType::ZiskVadcop, &[]);
        assert_eq!(result.status, ProofStatus::Pending);
    }

    #[test]
    fn determine_status_vadcop_completed_returns_succeeded() {
        let sessions = vec![make_session(SessionType::Stark, DbSessionStatus::Completed)];
        let result = MockBackend::determine_status(ProofType::ZiskVadcop, &sessions);
        assert_eq!(result.status, ProofStatus::Succeeded);
    }

    #[test]
    fn determine_status_plonk_both_completed_returns_succeeded() {
        let sessions = vec![
            make_session(SessionType::Stark, DbSessionStatus::Completed),
            make_session(SessionType::Snark, DbSessionStatus::Completed),
        ];
        let result = MockBackend::determine_status(ProofType::ZiskPlonk, &sessions);
        assert_eq!(result.status, ProofStatus::Succeeded);
    }

    #[test]
    fn determine_status_plonk_only_stark_returns_running() {
        let sessions = vec![make_session(SessionType::Stark, DbSessionStatus::Completed)];
        let result = MockBackend::determine_status(ProofType::ZiskPlonk, &sessions);
        assert_eq!(result.status, ProofStatus::Running);
    }

    #[test]
    fn determine_status_failure_priority() {
        let mut failed = make_session(SessionType::Stark, DbSessionStatus::Failed);
        failed.error_message = Some("OOM".to_string());
        let result = MockBackend::determine_status(ProofType::ZiskPlonk, &[failed]);
        assert_eq!(result.status, ProofStatus::Failed);
        assert_eq!(result.error_message.as_deref(), Some("OOM"));
    }
}
