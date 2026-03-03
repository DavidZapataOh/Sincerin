use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;

use sincerin_common::types::ProofStatus;

use crate::auth::ApiKeyId;
use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct ProofStatusResponse {
    pub request_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// GET /v1/proof/:id
///
/// Returns the current status of a proof request by looking up the latest
/// NATS message on `sincerin.proofs.status.<request_id>`.
pub async fn get_proof_status(
    State(state): State<AppState>,
    _api_key: ApiKeyId,
    Path(request_id): Path<String>,
) -> Result<Json<ProofStatusResponse>, ApiError> {
    // Validate request_id format: 0x + 64 hex chars = 66 chars total
    if !is_valid_request_id(&request_id) {
        return Err(ApiError::InvalidRequestId(
            "Request ID must be 0x-prefixed 64-char hex string".to_string(),
        ));
    }

    // Look up the latest status from NATS JetStream
    let subject = format!("sincerin.proofs.status.{request_id}");

    // Try to get the last message for this subject from the PROOF_STATUS stream
    let stream = state
        .jetstream
        .get_stream("PROOF_STATUS")
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to access NATS stream: {e}")))?;

    let last_msg = stream
        .get_last_raw_message_by_subject(&subject)
        .await;

    match last_msg {
        Ok(msg) => {
            let status: ProofStatus = serde_json::from_slice(&msg.payload)
                .map_err(|e| ApiError::Internal(format!("Failed to deserialize status: {e}")))?;

            let response = build_status_response(&request_id, &status);
            Ok(Json(response))
        }
        Err(_) => {
            // No message found — proof request doesn't exist
            Err(ApiError::NotFound("Proof request not found".to_string()))
        }
    }
}

fn is_valid_request_id(id: &str) -> bool {
    if id.len() != 66 {
        return false;
    }
    if !id.starts_with("0x") {
        return false;
    }
    id[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn build_status_response(request_id: &str, status: &ProofStatus) -> ProofStatusResponse {
    let now = chrono::Utc::now().to_rfc3339();

    let (status_str, prover_id, tx_hash, block_number, proof_hash, failure_reason) = match status {
        ProofStatus::Pending => ("pending", None, None, None, None, None),
        ProofStatus::Assigned { prover_id } => {
            ("assigned", Some(prover_id.clone()), None, None, None, None)
        }
        ProofStatus::ClientComputing => ("client_computing", None, None, None, None, None),
        ProofStatus::Proving { .. } => ("proving", None, None, None, None, None),
        ProofStatus::Verifying => ("verifying_on_l1", None, None, None, None, None),
        ProofStatus::VerifiedL1 {
            proof_id, tx_hash, gas_used: _,
        } => (
            "verified",
            None,
            Some(tx_hash.clone()),
            None,
            Some(proof_id.clone()),
            None,
        ),
        ProofStatus::BatchPending { .. } => ("batch_pending", None, None, None, None, None),
        ProofStatus::VerifiedSettlement { chain: _, tx_hash } => (
            "verified",
            None,
            Some(tx_hash.clone()),
            None,
            None,
            None,
        ),
        ProofStatus::Failed { reason, stage } => (
            "failed",
            None,
            None,
            None,
            None,
            Some(format!("{reason} (stage: {stage})")),
        ),
        ProofStatus::Expired => ("expired", None, None, None, None, None),
    };

    ProofStatusResponse {
        request_id: request_id.to_string(),
        status: status_str.to_string(),
        prover_id,
        tx_hash,
        block_number,
        proof_hash,
        failure_reason,
        created_at: now.clone(),
        updated_at: now,
    }
}
