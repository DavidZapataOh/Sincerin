/// Prover node types.
///
/// The prover registry tracks every prover that has staked SIN tokens
/// and registered on the L1 `ProverRegistry` contract.  These types
/// mirror the on-chain state and are kept in sync by the Collector.
/// The Dispatcher reads `ProverInfo` to select the best prover for
/// each request based on capabilities, reputation, and load.
use serde::{Deserialize, Serialize};

use super::circuit::ProofSystem;
use super::privacy::PrivacyStrategy;

// ── ProverStatus ──────────────────────────────────────────────────

/// Operational status of a prover node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverStatus {
    /// Prover is online, staked, and accepting requests.
    Active,
    /// Prover has been penalized or is temporarily offline.
    Suspended,
    /// Prover has withdrawn its stake and left the network.
    Deregistered,
}

// ── ProverCapabilities ────────────────────────────────────────────

/// Hardware and software capabilities of a prover node.
///
/// Reported by the prover at registration and updated via heartbeats.
/// The Dispatcher uses these to filter provers that can handle a
/// given request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverCapabilities {
    /// Whether the prover has GPU acceleration available (ICICLE).
    pub gpu_available: bool,
    /// Maximum number of constraints the prover can handle.
    pub max_constraint_size: u64,
    /// Privacy strategies this prover supports.
    pub supported_privacy: Vec<PrivacyStrategy>,
}

// ── ProverStats ───────────────────────────────────────────────────

/// Aggregated performance statistics for a prover node.
///
/// Updated after each completed (or failed) proof request.  The
/// Dispatcher uses these for reputation-weighted routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverStats {
    /// Total number of proofs generated (successful + failed).
    pub total_proofs: u64,
    /// Number of failed proof attempts.
    pub failed_proofs: u64,
    /// Rolling average proving latency in milliseconds.
    pub average_latency_ms: u64,
    /// Fraction of time the prover has been online (0.0 to 1.0).
    pub uptime_ratio: f64,
}

// ── ProverInfo ────────────────────────────────────────────────────

/// Complete prover node record as seen by the orchestration layer.
///
/// Combines on-chain registration data (id, address, stake) with
/// off-chain operational data (capabilities, stats, status).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverInfo {
    /// Unique prover identifier (derived from staking transaction).
    pub id: String,
    /// On-chain address that owns the prover stake.
    pub address: String,
    /// Amount of SIN tokens staked (in wei).
    pub stake: u64,
    /// Reputation score (0-10000 basis points).
    pub reputation: u32,
    /// Proof systems this prover can execute.
    pub supported_systems: Vec<ProofSystem>,
    /// Hardware and software capabilities.
    pub capabilities: ProverCapabilities,
    /// Current operational status.
    pub status: ProverStatus,
    /// Aggregated performance statistics.
    pub stats: ProverStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_prover() -> ProverInfo {
        ProverInfo {
            id: "prover-1".to_string(),
            address: "0xabc123".to_string(),
            stake: 10_000_000_000_000_000_000, // 10 SIN
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
        }
    }

    // ── JSON roundtrip ────────────────────────────────────────────

    #[test]
    fn prover_info_json_roundtrip() {
        let original = sample_prover();
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: ProverInfo = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.id, original.id);
        assert_eq!(decoded.address, original.address);
        assert_eq!(decoded.stake, original.stake);
        assert_eq!(decoded.reputation, original.reputation);
        assert_eq!(decoded.status, original.status);
        assert_eq!(decoded.stats.total_proofs, original.stats.total_proofs);
        assert_eq!(decoded.stats.uptime_ratio, original.stats.uptime_ratio);
    }

    // ── snake_case enum serialization ─────────────────────────────

    #[test]
    fn prover_status_serializes_as_snake_case() {
        let json = serde_json::to_string(&ProverStatus::Active).unwrap();
        assert_eq!(json, "\"active\"");

        let json = serde_json::to_string(&ProverStatus::Suspended).unwrap();
        assert_eq!(json, "\"suspended\"");

        let json = serde_json::to_string(&ProverStatus::Deregistered).unwrap();
        assert_eq!(json, "\"deregistered\"");
    }

    #[test]
    fn prover_capabilities_json_roundtrip() {
        let caps = ProverCapabilities {
            gpu_available: false,
            max_constraint_size: 500_000,
            supported_privacy: vec![PrivacyStrategy::DirectDelegation],
        };
        let json = serde_json::to_string(&caps).expect("serialize");
        let decoded: ProverCapabilities = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.gpu_available, caps.gpu_available);
        assert_eq!(decoded.max_constraint_size, caps.max_constraint_size);
        assert_eq!(decoded.supported_privacy.len(), 1);
    }

    #[test]
    fn prover_stats_json_roundtrip() {
        let stats = ProverStats {
            total_proofs: 42,
            failed_proofs: 1,
            average_latency_ms: 1100,
            uptime_ratio: 0.95,
        };
        let json = serde_json::to_string(&stats).expect("serialize");
        let decoded: ProverStats = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.total_proofs, stats.total_proofs);
        assert_eq!(decoded.failed_proofs, stats.failed_proofs);
        assert_eq!(decoded.average_latency_ms, stats.average_latency_ms);
        assert!((decoded.uptime_ratio - stats.uptime_ratio).abs() < f64::EPSILON);
    }
}
