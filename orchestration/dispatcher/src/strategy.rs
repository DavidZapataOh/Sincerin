use std::collections::HashMap;

use tracing::info;

use sincerin_common::types::{CircuitId, PrivacyLevel, PrivacyStrategy, ProofRequest, ProofSystem};

use crate::errors::DispatcherError;

/// Metadata about a circuit used for strategy selection.
#[derive(Debug, Clone)]
pub struct CircuitMetadata {
    pub circuit_id: CircuitId,
    pub proof_system: ProofSystem,
    pub circuit_size: u64,
    pub estimated_proving_time_ms: u64,
}

/// Registry of known circuits and their metadata.
pub struct CircuitRegistry {
    circuits: HashMap<String, CircuitMetadata>,
}

impl CircuitRegistry {
    /// Create a new registry with the MVP circuits hardcoded.
    pub fn new() -> Self {
        let mut circuits = HashMap::new();

        circuits.insert(
            "proof-of-membership".to_string(),
            CircuitMetadata {
                circuit_id: "proof-of-membership".to_string(),
                proof_system: ProofSystem::UltraHonk,
                circuit_size: 20_000,
                estimated_proving_time_ms: 3000,
            },
        );

        circuits.insert(
            "proof-of-age".to_string(),
            CircuitMetadata {
                circuit_id: "proof-of-age".to_string(),
                proof_system: ProofSystem::UltraHonk,
                circuit_size: 50_000,
                estimated_proving_time_ms: 5000,
            },
        );

        Self { circuits }
    }

    /// Look up circuit metadata by ID.
    pub fn get(&self, circuit_id: &str) -> Option<&CircuitMetadata> {
        self.circuits.get(circuit_id)
    }
}

impl Default for CircuitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Selects the privacy strategy for a proof request based on the
/// circuit's properties and the requester's privacy preference.
pub struct StrategySelector {
    registry: CircuitRegistry,
}

impl StrategySelector {
    pub fn new(registry: CircuitRegistry) -> Self {
        Self { registry }
    }

    /// Select the optimal privacy strategy for a request.
    ///
    /// Decision tree (from sincerin-paper.md Section 5.1):
    /// - PrivacyLevel::None → DirectDelegation
    /// - UltraHonk + circuit_size ≤ 2^19 (524,288) → ClientSide
    /// - UltraHonk + circuit_size > 2^19 → StructuralSplit
    /// - Any other proof system → StructuralSplit
    pub fn select(&self, request: &ProofRequest) -> Result<PrivacyStrategy, DispatcherError> {
        let metadata = self
            .registry
            .get(&request.circuit_id)
            .ok_or_else(|| DispatcherError::UnknownCircuit(request.circuit_id.clone()))?;

        let strategy = select_strategy(
            &metadata.proof_system,
            metadata.circuit_size,
            &request.privacy_level,
        );

        info!(
            circuit_id = %request.circuit_id,
            privacy_level = ?request.privacy_level,
            proof_system = ?metadata.proof_system,
            circuit_size = metadata.circuit_size,
            strategy = ?strategy,
            "Strategy selected"
        );

        metrics::counter!("sincerin_dispatcher_strategy_selected_total",
            "circuit_id" => request.circuit_id.clone(),
            "strategy" => format!("{strategy:?}")
        )
        .increment(1);

        Ok(strategy)
    }
}

/// Pure function implementing the privacy strategy decision tree.
///
/// Truth table:
/// | privacy_level | proof_system | circuit_size | strategy           |
/// |---------------|-------------|--------------|---------------------|
/// | None          | any         | any          | DirectDelegation    |
/// | Preferred     | UltraHonk  | <= 524,288   | ClientSide          |
/// | Preferred     | UltraHonk  | > 524,288    | StructuralSplit     |
/// | Preferred     | Groth16    | any          | StructuralSplit     |
/// | Mandatory     | UltraHonk  | <= 524,288   | ClientSide          |
/// | Mandatory     | UltraHonk  | > 524,288    | StructuralSplit     |
/// | Mandatory     | Groth16    | any          | StructuralSplit     |
pub fn select_strategy(
    proof_system: &ProofSystem,
    circuit_size: u64,
    privacy_level: &PrivacyLevel,
) -> PrivacyStrategy {
    const CLIENT_SIDE_THRESHOLD: u64 = 1 << 19; // 524,288

    match privacy_level {
        PrivacyLevel::None => PrivacyStrategy::DirectDelegation,
        PrivacyLevel::Preferred | PrivacyLevel::Mandatory => match proof_system {
            ProofSystem::UltraHonk => {
                if circuit_size <= CLIENT_SIDE_THRESHOLD {
                    PrivacyStrategy::ClientSide
                } else {
                    PrivacyStrategy::StructuralSplit
                }
            }
            // All other proof systems default to StructuralSplit
            _ => PrivacyStrategy::StructuralSplit,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_none_privacy_direct_delegation() {
        // None → DirectDelegation regardless of proof system or size
        assert_eq!(
            select_strategy(&ProofSystem::UltraHonk, 20_000, &PrivacyLevel::None),
            PrivacyStrategy::DirectDelegation
        );
        assert_eq!(
            select_strategy(&ProofSystem::Groth16, 1_000_000, &PrivacyLevel::None),
            PrivacyStrategy::DirectDelegation
        );
        assert_eq!(
            select_strategy(&ProofSystem::Plonk, 0, &PrivacyLevel::None),
            PrivacyStrategy::DirectDelegation
        );
    }

    #[test]
    fn test_strategy_mandatory_small_circuit_client_side() {
        assert_eq!(
            select_strategy(&ProofSystem::UltraHonk, 20_000, &PrivacyLevel::Mandatory),
            PrivacyStrategy::ClientSide
        );
    }

    #[test]
    fn test_strategy_mandatory_large_circuit_structural_split() {
        assert_eq!(
            select_strategy(&ProofSystem::UltraHonk, 600_000, &PrivacyLevel::Mandatory),
            PrivacyStrategy::StructuralSplit
        );
    }

    #[test]
    fn test_strategy_preferred_small_circuit_client_side() {
        // Exactly 2^19 = 524,288 should be ClientSide (<=)
        assert_eq!(
            select_strategy(&ProofSystem::UltraHonk, 524_288, &PrivacyLevel::Preferred),
            PrivacyStrategy::ClientSide
        );
    }

    #[test]
    fn test_strategy_preferred_boundary_circuit_structural_split() {
        // 2^19 + 1 = 524,289 should be StructuralSplit (>)
        assert_eq!(
            select_strategy(&ProofSystem::UltraHonk, 524_289, &PrivacyLevel::Preferred),
            PrivacyStrategy::StructuralSplit
        );
    }

    #[test]
    fn test_strategy_groth16_always_structural_split() {
        assert_eq!(
            select_strategy(&ProofSystem::Groth16, 100, &PrivacyLevel::Mandatory),
            PrivacyStrategy::StructuralSplit
        );
        assert_eq!(
            select_strategy(&ProofSystem::Groth16, 1_000_000, &PrivacyLevel::Preferred),
            PrivacyStrategy::StructuralSplit
        );
    }

    #[test]
    fn test_strategy_unknown_circuit() {
        let selector = StrategySelector::new(CircuitRegistry::new());
        let request = ProofRequest {
            request_id: "test".to_string(),
            circuit_id: "nonexistent-circuit".to_string(),
            requester: "test".to_string(),
            privacy_level: PrivacyLevel::Mandatory,
            priority: sincerin_common::types::Priority::Standard,
            max_fee: 0,
            deadline: 0,
            public_inputs: serde_json::json!({}),
            created_at: 0,
            status: sincerin_common::types::ProofStatus::Pending,
        };

        let result = selector.select(&request);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DispatcherError::UnknownCircuit(_)
        ));
    }

    #[test]
    fn test_strategy_all_combinations() {
        // Full truth table test
        let cases = vec![
            // (proof_system, circuit_size, privacy_level, expected)
            (ProofSystem::UltraHonk, 0, PrivacyLevel::None, PrivacyStrategy::DirectDelegation),
            (ProofSystem::Groth16, 0, PrivacyLevel::None, PrivacyStrategy::DirectDelegation),
            (ProofSystem::Plonk, 0, PrivacyLevel::None, PrivacyStrategy::DirectDelegation),
            (ProofSystem::UltraHonk, 524_288, PrivacyLevel::Preferred, PrivacyStrategy::ClientSide),
            (ProofSystem::UltraHonk, 524_289, PrivacyLevel::Preferred, PrivacyStrategy::StructuralSplit),
            (ProofSystem::Groth16, 100, PrivacyLevel::Preferred, PrivacyStrategy::StructuralSplit),
            (ProofSystem::UltraHonk, 524_288, PrivacyLevel::Mandatory, PrivacyStrategy::ClientSide),
            (ProofSystem::UltraHonk, 524_289, PrivacyLevel::Mandatory, PrivacyStrategy::StructuralSplit),
            (ProofSystem::Groth16, 100, PrivacyLevel::Mandatory, PrivacyStrategy::StructuralSplit),
        ];

        for (proof_system, size, privacy, expected) in cases {
            let result = select_strategy(&proof_system, size, &privacy);
            assert_eq!(
                result, expected,
                "Failed for {:?}, size={}, {:?}",
                proof_system, size, privacy
            );
        }
    }

    #[test]
    fn test_strategy_edge_case_zero_size() {
        // circuit_size: 0 is <= 524,288, so ClientSide if privacy != None
        assert_eq!(
            select_strategy(&ProofSystem::UltraHonk, 0, &PrivacyLevel::Mandatory),
            PrivacyStrategy::ClientSide
        );
    }

    #[test]
    fn test_strategy_edge_case_max_size() {
        // u64::MAX should not overflow, should be StructuralSplit
        assert_eq!(
            select_strategy(&ProofSystem::UltraHonk, u64::MAX, &PrivacyLevel::Mandatory),
            PrivacyStrategy::StructuralSplit
        );
    }
}
