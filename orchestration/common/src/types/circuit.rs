/// Circuit metadata types.
///
/// Each circuit registered in Sincerin carries metadata that the
/// Dispatcher uses to select a privacy strategy and route the request
/// to a capable prover.  The `CircuitLanguage` and `ProofSystem`
/// determine which backend and L1 precompile are involved.
use serde::{Deserialize, Serialize};

use super::proof_request::CircuitId;

// ── CircuitLanguage ───────────────────────────────────────────────

/// The high-level language used to author the circuit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitLanguage {
    /// Aztec Noir DSL — primary language for MVP.
    Noir,
    /// Circom (iden3) — supported for ecosystem compatibility.
    Circom,
}

// ── ProofSystem ───────────────────────────────────────────────────

/// The proving system / back-end used for proof generation and
/// on-chain verification.  Each variant maps to a specific L1
/// precompile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSystem {
    /// Barretenberg UltraHonk — MVP primary system.
    /// L1 precompile at 0x03...02, ~20K gas.
    UltraHonk,
    /// Groth16 — smallest proofs, trusted setup required.
    /// L1 precompile at 0x03...01, ~15K gas.
    Groth16,
    /// Standard PLONK — universal setup.
    Plonk,
    /// FFLONK — single-round PLONK variant.
    /// L1 precompile at 0x03...03, ~15K gas.
    Fflonk,
}

// ── CircuitMetadata ───────────────────────────────────────────────

/// Metadata describing a registered circuit.
///
/// Stored in the circuit registry and used by the Dispatcher to
/// determine routing, feasibility of client-side proving, and
/// compatibility with split-proving strategies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitMetadata {
    /// Unique circuit identifier (content-addressed hash of the ACIR/R1CS).
    pub id: CircuitId,
    /// Human-readable circuit name (e.g. "proof-of-age").
    pub name: String,
    /// Brief description of what this circuit proves.
    pub description: String,
    /// Language used to author the circuit.
    pub language: CircuitLanguage,
    /// Proving system / back-end for this circuit.
    pub proof_system: ProofSystem,
    /// Estimated number of constraints (gates).  Used by the
    /// Dispatcher to estimate proving time and prover requirements.
    pub estimated_constraints: u64,
    /// Whether this circuit is small enough to prove on the client
    /// device (browser / mobile).
    pub client_side_feasible: bool,
    /// Whether the circuit supports structural split proving for
    /// enhanced privacy.
    pub split_proving_supported: bool,
    /// SHA-256 hash of the verification key, hex-encoded.  Used for
    /// integrity checks against the on-chain registry.
    pub verification_key_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_circuit() -> CircuitMetadata {
        CircuitMetadata {
            id: "circuit-age-18".to_string(),
            name: "proof-of-age".to_string(),
            description: "Proves the holder is at least 18 years old".to_string(),
            language: CircuitLanguage::Noir,
            proof_system: ProofSystem::UltraHonk,
            estimated_constraints: 4096,
            client_side_feasible: true,
            split_proving_supported: true,
            verification_key_hash: "abcd1234".to_string(),
        }
    }

    // ── JSON roundtrip ────────────────────────────────────────────

    #[test]
    fn circuit_metadata_json_roundtrip() {
        let original = sample_circuit();
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: CircuitMetadata = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.id, original.id);
        assert_eq!(decoded.name, original.name);
        assert_eq!(decoded.language, original.language);
        assert_eq!(decoded.proof_system, original.proof_system);
        assert_eq!(
            decoded.estimated_constraints,
            original.estimated_constraints
        );
        assert_eq!(decoded.client_side_feasible, original.client_side_feasible);
    }

    // ── snake_case enum serialization ─────────────────────────────

    #[test]
    fn circuit_language_serializes_as_snake_case() {
        let json = serde_json::to_string(&CircuitLanguage::Noir).unwrap();
        assert_eq!(json, "\"noir\"");

        let json = serde_json::to_string(&CircuitLanguage::Circom).unwrap();
        assert_eq!(json, "\"circom\"");
    }

    #[test]
    fn proof_system_serializes_as_snake_case() {
        let json = serde_json::to_string(&ProofSystem::UltraHonk).unwrap();
        assert_eq!(json, "\"ultra_honk\"");

        let json = serde_json::to_string(&ProofSystem::Groth16).unwrap();
        assert_eq!(json, "\"groth16\"");

        let json = serde_json::to_string(&ProofSystem::Plonk).unwrap();
        assert_eq!(json, "\"plonk\"");

        let json = serde_json::to_string(&ProofSystem::Fflonk).unwrap();
        assert_eq!(json, "\"fflonk\"");
    }

    #[test]
    fn circuit_metadata_contains_expected_fields() {
        let circuit = sample_circuit();
        let json = serde_json::to_string(&circuit).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(v.get("id").is_some());
        assert!(v.get("name").is_some());
        assert!(v.get("language").is_some());
        assert!(v.get("proof_system").is_some());
        assert!(v.get("estimated_constraints").is_some());
        assert!(v.get("client_side_feasible").is_some());
        assert!(v.get("split_proving_supported").is_some());
        assert!(v.get("verification_key_hash").is_some());
    }
}
