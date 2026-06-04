//! End-to-end integration tests using the mock `ZisK` backend.
//!
//! These tests require a running prover-service started with
//! `SP1_PROVER=zisk-mock`. The mock backend produces deterministic receipts
//! without witness generation or prover execution.

use std::time::{Duration, Instant};

use base_zk_client::{
    GetProofRequest, GetProofResponse, ProveBlockRequest, ReceiptType, get_proof_response,
    prover_service_client::ProverServiceClient,
};
use tonic::transport::Channel;
use uuid::Uuid;

const PROOF_TYPE_ZISK_VADCOP: i32 = 5;
const PROOF_TYPE_ZISK_PLONK: i32 = 6;
const MOCK_ZISK_STARK_RECEIPT: &[u8] = b"mock-zisk-stark-receipt-v1";
const MOCK_ZISK_PLONK_RECEIPT: &[u8] = b"mock-zisk-plonk-receipt-v1";

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const POLL_TIMEOUT: Duration = Duration::from_secs(30);

async fn connect() -> ProverServiceClient<Channel> {
    let addr =
        std::env::var("PROVER_GRPC_ADDR").unwrap_or_else(|_| "http://localhost:9000".to_string());

    ProverServiceClient::connect(addr).await.expect("failed to connect to prover-service")
}

async fn poll_until_terminal(
    client: &mut ProverServiceClient<Channel>,
    session_id: &str,
    receipt_type: Option<i32>,
) -> GetProofResponse {
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() <= POLL_TIMEOUT,
            "timed out after {POLL_TIMEOUT:?} waiting for proof {session_id}"
        );

        tokio::time::sleep(POLL_INTERVAL).await;

        let inner = client
            .get_proof(GetProofRequest { session_id: session_id.to_string(), receipt_type })
            .await
            .expect("GetProof should succeed")
            .into_inner();

        let status = get_proof_response::Status::try_from(inner.status)
            .unwrap_or(get_proof_response::Status::Unspecified);
        if matches!(
            status,
            get_proof_response::Status::Succeeded | get_proof_response::Status::Failed
        ) {
            return inner;
        }
    }
}

#[tokio::test]
#[ignore = "requires a running prover-service with SP1_PROVER=zisk-mock"]
async fn zisk_vadcop_proof_succeeds() {
    let mut client = connect().await;

    let response = client
        .prove_block(ProveBlockRequest {
            start_block_number: 7000,
            number_of_blocks_to_prove: 2,
            sequence_window: Some(50),
            proof_type: PROOF_TYPE_ZISK_VADCOP,
            session_id: None,
            prover_address: None,
            l1_head: None,
            intermediate_root_interval: None,
        })
        .await
        .expect("ProveBlock should succeed")
        .into_inner();

    Uuid::parse_str(&response.session_id).expect("session_id should be a UUID");

    let result = poll_until_terminal(
        &mut client,
        &response.session_id,
        Some(ReceiptType::ZiskVadcop as i32),
    )
    .await;

    assert_eq!(
        get_proof_response::Status::try_from(result.status).expect("known status"),
        get_proof_response::Status::Succeeded
    );
    assert_eq!(result.receipt, MOCK_ZISK_STARK_RECEIPT);
    assert!(result.error_message.is_none());
}

#[tokio::test]
#[ignore = "requires a running prover-service with SP1_PROVER=zisk-mock"]
async fn zisk_plonk_proof_exposes_both_receipts() {
    let mut client = connect().await;

    let response = client
        .prove_block(ProveBlockRequest {
            start_block_number: 8000,
            number_of_blocks_to_prove: 1,
            sequence_window: Some(50),
            proof_type: PROOF_TYPE_ZISK_PLONK,
            session_id: None,
            prover_address: Some("0x1234567890abcdef1234567890abcdef12345678".to_string()),
            l1_head: None,
            intermediate_root_interval: None,
        })
        .await
        .expect("ProveBlock should succeed")
        .into_inner();

    Uuid::parse_str(&response.session_id).expect("session_id should be a UUID");

    let plonk =
        poll_until_terminal(&mut client, &response.session_id, Some(ReceiptType::ZiskPlonk as i32))
            .await;
    assert_eq!(
        get_proof_response::Status::try_from(plonk.status).expect("known status"),
        get_proof_response::Status::Succeeded
    );
    assert_eq!(plonk.receipt, MOCK_ZISK_PLONK_RECEIPT);
    assert!(plonk.error_message.is_none());

    let vadcop = client
        .get_proof(GetProofRequest {
            session_id: response.session_id,
            receipt_type: Some(ReceiptType::ZiskVadcop as i32),
        })
        .await
        .expect("GetProof should succeed")
        .into_inner();
    assert_eq!(vadcop.receipt, MOCK_ZISK_STARK_RECEIPT);
}
