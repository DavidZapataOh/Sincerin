/// Privacy strategy types.
///
/// Sincerin supports a spectrum of privacy levels, from full
/// client-side proving (maximum privacy, higher latency) to direct
/// delegation (no privacy, lowest latency).  The Dispatcher selects
/// a `PrivacyStrategy` based on the request's `PrivacyLevel`, the
/// circuit's capabilities, and the available provers.
///
/// See sincerin-paper.md Section 5 for the full privacy analysis.
use serde::{Deserialize, Serialize};

use super::proof_request::CircuitId;

// ── PrivacyLevel ──────────────────────────────────────────────────

/// Requester-specified privacy preference.
///
/// The Dispatcher maps this to a concrete `PrivacyStrategy` based on
/// circuit support and prover availability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyLevel {
    /// Witness data MUST NOT leave the client or must be provably
    /// hidden from any single prover.  The Dispatcher will reject
    /// the request if no privacy-preserving strategy is available.
    Mandatory,
    /// Prefer privacy-preserving strategies but fall back to direct
    /// delegation if none is feasible.
    Preferred,
    /// No privacy requirements; direct delegation is acceptable.
    None,
}

// ── PrivacyStrategy ───────────────────────────────────────────────

/// Concrete privacy strategy applied during proof generation.
///
/// Ordered roughly from most private to least private:
/// 1. ClientSide — witness never leaves client
/// 2. StructuralSplit — witness split across multiple provers
/// 3. Emsm — encrypted multi-scalar multiplication protocol
/// 4. CoSnark — collaborative SNARK generation
/// 5. TeeIsolated — trusted execution environment
/// 6. DirectDelegation — no privacy (baseline)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyStrategy {
    /// Client generates the proof locally (browser/mobile).
    /// Maximum privacy: witness never leaves the device.
    ClientSide,
    /// Circuit is structurally decomposed so that no single prover
    /// sees the full witness.  Requires `split_proving_supported`.
    StructuralSplit,
    /// Encrypted multi-scalar multiplication protocol.
    /// Witness is encrypted before being sent to the prover.
    Emsm,
    /// Collaborative SNARK: multiple provers each hold a share
    /// of the witness and jointly compute the proof.
    CoSnark,
    /// Proof generated inside a TEE (SGX/TDX).  The prover
    /// attestation is verified before dispatching.
    TeeIsolated,
    /// Witness is sent in cleartext to a single prover.
    /// No privacy guarantees.  Lowest latency.
    DirectDelegation,
}

// ── SplitProvingData ──────────────────────────────────────────────

/// Data produced during the split-proving handshake.
///
/// When `PrivacyStrategy::StructuralSplit` is selected, the client
/// commits to its witness share and publishes this structure so that
/// the prover(s) can complete their portion of the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitProvingData {
    /// Pedersen commitment to the client's witness share.
    pub witness_commitment: Vec<u8>,
    /// SHA-256 hash of the commitment, hex-encoded.
    pub commitment_hash: String,
    /// Blinding factors used in the commitment (encrypted for the
    /// verifier).
    pub blinding_factors: Vec<u8>,
    /// Circuit being proved.
    pub circuit_id: CircuitId,
    /// Public inputs shared between client and prover.
    pub public_inputs: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_split_data() -> SplitProvingData {
        SplitProvingData {
            witness_commitment: vec![0x01, 0x02, 0x03],
            commitment_hash: "abc123".to_string(),
            blinding_factors: vec![0xaa, 0xbb],
            circuit_id: "circuit-membership".to_string(),
            public_inputs: serde_json::json!({"group_root": "0xdef"}),
        }
    }

    // ── JSON roundtrip ────────────────────────────────────────────

    #[test]
    fn split_proving_data_json_roundtrip() {
        let original = sample_split_data();
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: SplitProvingData = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.witness_commitment, original.witness_commitment);
        assert_eq!(decoded.commitment_hash, original.commitment_hash);
        assert_eq!(decoded.blinding_factors, original.blinding_factors);
        assert_eq!(decoded.circuit_id, original.circuit_id);
    }

    // ── snake_case enum serialization ─────────────────────────────

    #[test]
    fn privacy_level_serializes_as_snake_case() {
        let json = serde_json::to_string(&PrivacyLevel::Mandatory).unwrap();
        assert_eq!(json, "\"mandatory\"");

        let json = serde_json::to_string(&PrivacyLevel::Preferred).unwrap();
        assert_eq!(json, "\"preferred\"");

        let json = serde_json::to_string(&PrivacyLevel::None).unwrap();
        assert_eq!(json, "\"none\"");
    }

    #[test]
    fn privacy_strategy_serializes_as_snake_case() {
        let json = serde_json::to_string(&PrivacyStrategy::ClientSide).unwrap();
        assert_eq!(json, "\"client_side\"");

        let json = serde_json::to_string(&PrivacyStrategy::StructuralSplit).unwrap();
        assert_eq!(json, "\"structural_split\"");

        let json = serde_json::to_string(&PrivacyStrategy::Emsm).unwrap();
        assert_eq!(json, "\"emsm\"");

        let json = serde_json::to_string(&PrivacyStrategy::CoSnark).unwrap();
        assert_eq!(json, "\"co_snark\"");

        let json = serde_json::to_string(&PrivacyStrategy::TeeIsolated).unwrap();
        assert_eq!(json, "\"tee_isolated\"");

        let json = serde_json::to_string(&PrivacyStrategy::DirectDelegation).unwrap();
        assert_eq!(json, "\"direct_delegation\"");
    }

    // ── No raw "witness" field in JSON ────────────────────────────

    #[test]
    fn split_proving_data_has_no_witness_field_in_json() {
        let data = sample_split_data();
        let json = serde_json::to_string(&data).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().expect("top-level must be object");

        // "witness_commitment" is allowed; bare "witness" is NOT.
        assert!(
            !obj.contains_key("witness"),
            "JSON must not contain a bare 'witness' field; \
             only 'witness_commitment' is acceptable.  Got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
        assert!(
            obj.contains_key("witness_commitment"),
            "JSON must contain 'witness_commitment'"
        );
    }
}
