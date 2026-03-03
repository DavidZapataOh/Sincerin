//! Integration tests for sincerin-common.
//!
//! These tests exercise the public API surface across module boundaries,
//! verifying that types compose correctly, serialization is consistent,
//! and error conversions work as expected.

use sincerin_common::errors::SincerinError;
use sincerin_common::types::*;

// ── Public API accessibility ─────────────────────────────────────

#[test]
fn all_types_are_publicly_accessible() {
    // Verify every type is reachable via the re-export glob.
    let _req = ProofRequest {
        request_id: "r1".into(),
        circuit_id: "c1".into(),
        requester: "0xabc".into(),
        privacy_level: PrivacyLevel::Mandatory,
        priority: Priority::Standard,
        max_fee: 0,
        deadline: 0,
        public_inputs: serde_json::json!({}),
        created_at: 0,
        status: ProofStatus::Pending,
    };
    let _: CircuitMetadata;
    let _: CircuitLanguage;
    let _: ProofSystem;
    let _: ProverInfo;
    let _: ProverCapabilities;
    let _: ProverStats;
    let _: ProverStatus;
    let _: PrivacyLevel;
    let _: PrivacyStrategy;
    let _: SplitProvingData;
    let _: SincerinError;
}

// ── JSON enum consistency ────────────────────────────────────────

#[test]
fn json_enum_consistency_all_snake_case() {
    let cases: Vec<(&str, String)> = vec![
        (
            "Priority::Economy",
            serde_json::to_string(&Priority::Economy).unwrap(),
        ),
        (
            "Priority::Standard",
            serde_json::to_string(&Priority::Standard).unwrap(),
        ),
        (
            "Priority::Fast",
            serde_json::to_string(&Priority::Fast).unwrap(),
        ),
        (
            "CircuitLanguage::Noir",
            serde_json::to_string(&CircuitLanguage::Noir).unwrap(),
        ),
        (
            "CircuitLanguage::Circom",
            serde_json::to_string(&CircuitLanguage::Circom).unwrap(),
        ),
        (
            "ProofSystem::UltraHonk",
            serde_json::to_string(&ProofSystem::UltraHonk).unwrap(),
        ),
        (
            "ProofSystem::Groth16",
            serde_json::to_string(&ProofSystem::Groth16).unwrap(),
        ),
        (
            "ProverStatus::Active",
            serde_json::to_string(&ProverStatus::Active).unwrap(),
        ),
        (
            "ProverStatus::Suspended",
            serde_json::to_string(&ProverStatus::Suspended).unwrap(),
        ),
        (
            "PrivacyLevel::Mandatory",
            serde_json::to_string(&PrivacyLevel::Mandatory).unwrap(),
        ),
        (
            "PrivacyStrategy::ClientSide",
            serde_json::to_string(&PrivacyStrategy::ClientSide).unwrap(),
        ),
        (
            "PrivacyStrategy::DirectDelegation",
            serde_json::to_string(&PrivacyStrategy::DirectDelegation).unwrap(),
        ),
    ];

    for (name, json) in &cases {
        let trimmed = json.trim_matches('"');
        assert!(
            trimmed
                .chars()
                .all(|c| c.is_lowercase() || c == '_' || c.is_numeric()),
            "{name} serialized as {json} which is not snake_case",
        );
    }
}

// ── Proof request full lifecycle ─────────────────────────────────

#[test]
fn proof_request_full_lifecycle() {
    let mut request = ProofRequest {
        request_id: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        circuit_id: "proof-of-membership".to_string(),
        requester: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        privacy_level: PrivacyLevel::Mandatory,
        priority: Priority::Standard,
        max_fee: 1_000_000_000_000_000,
        deadline: 1772438400,
        public_inputs: serde_json::json!({
            "root": "0xaabbccdd",
            "nullifier": "0xeeff0011"
        }),
        created_at: 1772438000,
        status: ProofStatus::Pending,
    };

    // Serialize at each status transition.
    let json1 = serde_json::to_string(&request).unwrap();
    let _: ProofRequest = serde_json::from_str(&json1).unwrap();

    request.status = ProofStatus::Assigned {
        prover_id: "prover-1".to_string(),
    };
    let json2 = serde_json::to_string(&request).unwrap();
    let _: ProofRequest = serde_json::from_str(&json2).unwrap();

    request.status = ProofStatus::Proving {
        progress: Some(0.5),
    };
    let json3 = serde_json::to_string(&request).unwrap();
    let _: ProofRequest = serde_json::from_str(&json3).unwrap();

    request.status = ProofStatus::VerifiedL1 {
        proof_id: "0x456".to_string(),
        tx_hash: "0x789".to_string(),
        gas_used: 20000,
    };
    let json4 = serde_json::to_string(&request).unwrap();
    let de4: ProofRequest = serde_json::from_str(&json4).unwrap();
    assert!(matches!(de4.status, ProofStatus::VerifiedL1 { .. }));
}

// ── Cross-format compatibility ───────────────────────────────────

#[test]
fn cross_format_compatibility_json_and_bincode() {
    let result = ProofResult {
        request_id: "0x123".to_string(),
        proof_id: "0x456".to_string(),
        circuit_id: "proof-of-age".to_string(),
        proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
        public_inputs: serde_json::json!({"threshold": 18}),
        privacy_strategy: PrivacyStrategy::StructuralSplit,
        prover_id: "prover-2".to_string(),
        proving_time_ms: 4200,
        verified: true,
        verification_gas: 20000,
        l1_tx_hash: Some("0xabc".to_string()),
        created_at: 1772438400,
    };

    // JSON roundtrip
    let json_bytes = serde_json::to_vec(&result).unwrap();
    let from_json: ProofResult = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(result.proof, from_json.proof);

    // Bincode envelope roundtrip (JSON-then-bincode)
    let bin_bytes = bincode::serialize(&json_bytes).unwrap();
    let unwrapped: Vec<u8> = bincode::deserialize(&bin_bytes).unwrap();
    let from_bin: ProofResult = serde_json::from_slice(&unwrapped).unwrap();
    assert_eq!(result.proof, from_bin.proof);
    assert_eq!(result.proving_time_ms, from_bin.proving_time_ms);
}

// ── Error type conversions ───────────────────────────────────────

#[test]
fn error_conversions_work_across_modules() {
    // serde_json::Error -> SincerinError
    let result: Result<serde_json::Value, _> = serde_json::from_str("invalid");
    let sincerin_err: SincerinError = result.unwrap_err().into();
    assert!(matches!(sincerin_err, SincerinError::SerializationError(_)));

    // UnsupportedPrivacy carries the strategy
    let err = SincerinError::UnsupportedPrivacy(PrivacyStrategy::Emsm);
    let msg = err.to_string();
    assert!(
        msg.contains("Emsm"),
        "error message should contain variant: {msg}"
    );
}

// ── ProverInfo with full capabilities ────────────────────────────

#[test]
fn prover_info_roundtrip_with_nested_types() {
    let prover = ProverInfo {
        id: "prover-1".to_string(),
        address: "0xabc".to_string(),
        stake: 10_000_000_000_000_000_000,
        reputation: 9500,
        supported_systems: vec![ProofSystem::UltraHonk, ProofSystem::Groth16],
        capabilities: ProverCapabilities {
            gpu_available: true,
            max_constraint_size: 1_000_000,
            supported_privacy: vec![
                PrivacyStrategy::ClientSide,
                PrivacyStrategy::StructuralSplit,
                PrivacyStrategy::TeeIsolated,
            ],
        },
        status: ProverStatus::Active,
        stats: ProverStats {
            total_proofs: 1500,
            failed_proofs: 3,
            average_latency_ms: 850,
            uptime_ratio: 0.997,
        },
    };

    let json = serde_json::to_string(&prover).unwrap();
    let decoded: ProverInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.id, prover.id);
    assert_eq!(decoded.supported_systems.len(), 2);
    assert_eq!(decoded.capabilities.supported_privacy.len(), 3);
    assert_eq!(decoded.stats.total_proofs, 1500);
}

// ── Metrics module doesn't panic ─────────────────────────────────

#[test]
fn metrics_recording_does_not_panic() {
    use sincerin_common::metrics;
    metrics::record_proof_request("test-circuit", "standard");
    metrics::record_proof_verified("test-circuit", 20000);
    metrics::record_proof_failed("test-circuit", "timeout");
    metrics::record_generation_time("test-circuit", 1.2);
    metrics::record_orchestration_latency(0.005);
    metrics::set_active_requests(5);
    metrics::set_connected_provers(3);
}
