/// Proof request lifecycle types.
///
/// A `ProofRequest` enters the system through the Gateway, traverses
/// the Dispatcher -> ProverNode -> Collector -> L1 pipeline, and
/// produces a `ProofResult` on success.  `ProofStatus` tracks every
/// intermediate state so the client can subscribe to real-time
/// updates via WebSocket.
use serde::{Deserialize, Serialize};

use super::privacy::{PrivacyLevel, PrivacyStrategy};

// ── Type aliases ──────────────────────────────────────────────────

/// Unique identifier for a proof request (UUID v7 string).
pub type RequestId = String;

/// Unique identifier for a completed proof (content-addressed hash).
pub type ProofId = String;

/// Unique identifier for a circuit registered in the system.
pub type CircuitId = String;

// ── ProofStatus ───────────────────────────────────────────────────

/// Tracks every stage of the proof lifecycle from submission to
/// on-chain verification or failure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "state")]
pub enum ProofStatus {
    /// Request received, waiting for dispatcher assignment.
    Pending,
    /// Dispatcher has assigned a prover.
    Assigned { prover_id: String },
    /// Client is performing local witness computation (client-side privacy).
    ClientComputing,
    /// Prover is generating the proof.
    Proving { progress: Option<f32> },
    /// Proof generated, undergoing on-chain verification.
    Verifying,
    /// Proof verified on the Sincerin L1.
    VerifiedL1 {
        proof_id: ProofId,
        tx_hash: String,
        gas_used: u64,
    },
    /// Proof awaiting batch aggregation before settlement.
    BatchPending { batch_id: String },
    /// Proof settled on an external chain via batch.
    VerifiedSettlement { chain: String, tx_hash: String },
    /// Proof generation or verification failed.
    Failed { reason: String, stage: String },
    /// Request exceeded its deadline without completion.
    Expired,
}

// ── Priority ──────────────────────────────────────────────────────

/// Request priority determines dispatcher queue ordering and fee tier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// Lowest fee tier; best-effort scheduling.
    Economy,
    /// Default tier; balanced latency and cost.
    Standard,
    /// Highest fee tier; dispatched to first available prover.
    Fast,
}

// ── ProofRequest ──────────────────────────────────────────────────

/// A client's request to generate and verify a zero-knowledge proof.
///
/// Created by the Gateway upon receiving a `POST /v1/prove` call and
/// published to NATS for the Dispatcher to pick up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    /// Unique identifier for this request.
    pub request_id: RequestId,
    /// Which circuit to prove against.
    pub circuit_id: CircuitId,
    /// Address or identifier of the requesting party.
    pub requester: String,
    /// How much privacy the requester demands.
    pub privacy_level: PrivacyLevel,
    /// Queue priority / fee tier.
    pub priority: Priority,
    /// Maximum fee (in SIN tokens, denominated in wei) the requester
    /// is willing to pay.
    pub max_fee: u64,
    /// Unix timestamp (seconds) after which the request should expire.
    pub deadline: u64,
    /// Circuit-specific public inputs as a JSON value.
    pub public_inputs: serde_json::Value,
    /// Unix timestamp (seconds) when the request was created.
    pub created_at: u64,
    /// Current lifecycle status.
    pub status: ProofStatus,
}

// ── ProofResult ───────────────────────────────────────────────────

/// The output of a successful proof generation and verification cycle.
///
/// Stored by the Collector and returned to the client.  The `proof`
/// bytes are the raw serialized proof suitable for on-chain
/// verification via the relevant L1 precompile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResult {
    /// The original request this result corresponds to.
    pub request_id: RequestId,
    /// Content-addressed identifier for the proof.
    pub proof_id: ProofId,
    /// Circuit that was proved.
    pub circuit_id: CircuitId,
    /// Raw serialized proof bytes.
    pub proof: Vec<u8>,
    /// Public inputs used during proving.
    pub public_inputs: serde_json::Value,
    /// Privacy strategy that was applied.
    pub privacy_strategy: PrivacyStrategy,
    /// Identifier of the prover that generated this proof.
    pub prover_id: String,
    /// Wall-clock proving time in milliseconds.
    pub proving_time_ms: u64,
    /// Whether the proof passed L1 precompile verification.
    pub verified: bool,
    /// Gas consumed by the verification precompile call.
    pub verification_gas: u64,
    /// Transaction hash on the Sincerin L1, if already submitted.
    pub l1_tx_hash: Option<String>,
    /// Unix timestamp (seconds) when the result was created.
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proof_request() -> ProofRequest {
        ProofRequest {
            request_id: "req-001".to_string(),
            circuit_id: "circuit-age-18".to_string(),
            requester: "0xabc123".to_string(),
            privacy_level: PrivacyLevel::Mandatory,
            priority: Priority::Standard,
            max_fee: 1_000_000,
            deadline: 1_700_000_000,
            public_inputs: serde_json::json!({"age_threshold": 18}),
            created_at: 1_699_999_000,
            status: ProofStatus::Pending,
        }
    }

    fn sample_proof_result() -> ProofResult {
        ProofResult {
            request_id: "req-001".to_string(),
            proof_id: "proof-abc".to_string(),
            circuit_id: "circuit-age-18".to_string(),
            proof: vec![0xde, 0xad, 0xbe, 0xef],
            public_inputs: serde_json::json!({"age_threshold": 18}),
            privacy_strategy: PrivacyStrategy::ClientSide,
            prover_id: "prover-1".to_string(),
            proving_time_ms: 1200,
            verified: true,
            verification_gas: 20_000,
            l1_tx_hash: Some("0xdeadbeef".to_string()),
            created_at: 1_699_999_500,
        }
    }

    // ── JSON roundtrip ────────────────────────────────────────────

    #[test]
    fn proof_request_json_roundtrip() {
        let original = sample_proof_request();
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: ProofRequest = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.request_id, original.request_id);
        assert_eq!(decoded.circuit_id, original.circuit_id);
        assert_eq!(decoded.priority, original.priority);
        assert_eq!(decoded.status, original.status);
    }

    #[test]
    fn proof_result_json_roundtrip() {
        let original = sample_proof_result();
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: ProofResult = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.request_id, original.request_id);
        assert_eq!(decoded.proof_id, original.proof_id);
        assert_eq!(decoded.proof, original.proof);
        assert_eq!(decoded.verified, original.verified);
    }

    // ── snake_case enum serialization ─────────────────────────────

    #[test]
    fn priority_serializes_as_snake_case() {
        let json = serde_json::to_string(&Priority::Economy).unwrap();
        assert_eq!(json, "\"economy\"");

        let json = serde_json::to_string(&Priority::Fast).unwrap();
        assert_eq!(json, "\"fast\"");
    }

    #[test]
    fn proof_status_pending_serializes_as_snake_case() {
        let json = serde_json::to_string(&ProofStatus::Pending).unwrap();
        assert!(json.contains("\"pending\""), "got: {json}");
    }

    #[test]
    fn proof_status_verified_l1_serializes_as_snake_case() {
        let status = ProofStatus::VerifiedL1 {
            proof_id: "p1".into(),
            tx_hash: "0x1".into(),
            gas_used: 15_000,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(
            json.contains("\"verified_l1\""),
            "expected snake_case tag, got: {json}"
        );
    }

    #[test]
    fn proof_status_failed_serializes_as_snake_case() {
        let status = ProofStatus::Failed {
            reason: "timeout".into(),
            stage: "proving".into(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"failed\""), "got: {json}");
    }

    // ── bincode roundtrip for ProofResult ─────────────────────────
    //
    // NOTE: `serde_json::Value` does not implement `deserialize_any`
    // which bincode 1.x requires.  In production the NATS transport
    // uses JSON as the inner encoding anyway.  This test verifies
    // that ProofResult survives a JSON-then-bincode envelope, which
    // is the actual wire path.

    #[test]
    fn proof_result_bincode_roundtrip() {
        let original = sample_proof_result();

        // Step 1: JSON-encode the ProofResult (inner encoding).
        let json_bytes = serde_json::to_vec(&original).expect("json serialize");

        // Step 2: bincode-wrap the JSON bytes (outer envelope).
        let bincode_bytes = bincode::serialize(&json_bytes).expect("bincode serialize");

        // Step 3: Reverse — bincode-unwrap, then JSON-decode.
        let unwrapped: Vec<u8> = bincode::deserialize(&bincode_bytes).expect("bincode deserialize");
        let decoded: ProofResult = serde_json::from_slice(&unwrapped).expect("json deserialize");

        assert_eq!(decoded.request_id, original.request_id);
        assert_eq!(decoded.proof_id, original.proof_id);
        assert_eq!(decoded.proof, original.proof);
        assert_eq!(decoded.proving_time_ms, original.proving_time_ms);
        assert_eq!(decoded.verified, original.verified);
        assert_eq!(decoded.verification_gas, original.verification_gas);
        assert_eq!(decoded.l1_tx_hash, original.l1_tx_hash);
    }
}
