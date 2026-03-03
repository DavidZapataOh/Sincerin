use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sincerin_common::nats;
use sincerin_common::types::{
    Priority as CommonPriority, PrivacyLevel, ProofRequest, ProofStatus,
};

use crate::auth::ApiKeyId;
use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ProveRequestBody {
    pub circuit_id: String,
    pub public_inputs: serde_json::Value,
    pub private_inputs_hash: String,
    pub privacy: String,
    pub priority: String,
    pub deadline: u64,
    pub split_proving_data: Option<SplitProvingData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SplitProvingData {
    pub witness_commitment: String,
    pub commitment_hash: String,
    pub blinding_factors: String,
}

#[derive(Debug, Serialize)]
pub struct ProveResponse {
    pub request_id: String,
    pub status: String,
    pub estimated_time_ms: u64,
    pub websocket_topic: String,
}

/// POST /v1/prove
///
/// Accepts a proof request, validates it, publishes to NATS, and returns request_id.
pub async fn post_prove(
    State(state): State<AppState>,
    api_key: ApiKeyId,
    Json(body): Json<ProveRequestBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate circuit_id
    if !state.valid_circuits.contains(&body.circuit_id) {
        return Err(ApiError::UnknownCircuit(body.circuit_id));
    }

    // Validate privacy level
    let privacy_level = parse_privacy_level(&body.privacy)?;

    // Validate priority
    let priority = parse_priority(&body.priority)?;

    // Validate deadline is not in the past
    let now_secs = Utc::now().timestamp() as u64;
    if body.deadline < now_secs {
        return Err(ApiError::InvalidRequest("deadline is in the past".to_string()));
    }

    // Check rate limit
    if let Err(wait) = state.rate_limiter.try_acquire(&api_key.0) {
        return Err(ApiError::RateLimited {
            retry_after_ms: wait.as_millis() as u64,
        });
    }

    // Generate unique request_id = sha256(circuit_id || api_key || timestamp || nonce)
    let nonce = uuid::Uuid::new_v4();
    let mut hasher = Sha256::new();
    hasher.update(body.circuit_id.as_bytes());
    hasher.update(api_key.0.as_bytes());
    hasher.update(now_secs.to_be_bytes());
    hasher.update(nonce.as_bytes());
    let hash = hasher.finalize();
    let request_id = format!("0x{}", hex::encode(hash));

    // Build ProofRequest for NATS
    let proof_request = ProofRequest {
        request_id: request_id.clone(),
        circuit_id: body.circuit_id.clone(),
        requester: api_key.0.clone(),
        privacy_level,
        priority,
        max_fee: 0, // MVP: no fee market
        deadline: body.deadline,
        public_inputs: body.public_inputs.clone(),
        created_at: now_secs,
        status: ProofStatus::Pending,
    };

    // Publish to NATS
    nats::publish(&state.jetstream, nats::subjects::PROOF_REQUESTS, &proof_request)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to publish to NATS: {e}")))?;

    // Publish initial status update
    nats::publish_status_update(&state.jetstream, &request_id, &ProofStatus::Pending)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to publish initial status: {e}");
            ApiError::Internal(format!("Failed to publish status: {e}"))
        })?;

    // Record metrics
    sincerin_common::metrics::record_proof_request(&body.circuit_id, &body.priority);

    // Estimate time based on circuit
    let estimated_time_ms = estimate_time(&body.circuit_id);

    let response = ProveResponse {
        request_id: request_id.clone(),
        status: "pending".to_string(),
        estimated_time_ms,
        websocket_topic: format!("sincerin.proofs.status.{request_id}"),
    };

    Ok((StatusCode::ACCEPTED, Json(response)))
}

fn parse_privacy_level(s: &str) -> Result<PrivacyLevel, ApiError> {
    match s {
        "none" => Ok(PrivacyLevel::None),
        "optional" | "preferred" => Ok(PrivacyLevel::Preferred),
        "mandatory" => Ok(PrivacyLevel::Mandatory),
        other => Err(ApiError::InvalidPrivacyLevel(other.to_string())),
    }
}

fn parse_priority(s: &str) -> Result<CommonPriority, ApiError> {
    match s {
        "low" | "economy" => Ok(CommonPriority::Economy),
        "standard" => Ok(CommonPriority::Standard),
        "high" | "fast" => Ok(CommonPriority::Fast),
        other => Err(ApiError::InvalidPriority(other.to_string())),
    }
}

fn estimate_time(circuit_id: &str) -> u64 {
    match circuit_id {
        "proof-of-membership" => 3000,
        "proof-of-age" => 5000,
        _ => 10000,
    }
}
