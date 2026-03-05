//! Collector-specific Prometheus metrics.
//!
//! Supplements the common metrics (sincerin_proofs_verified_total, etc.)
//! with collector-specific counters and histograms for L1 transaction
//! tracking, verification latency, and gas usage.

use metrics::{counter, gauge, histogram};

/// Record a proof result received from NATS.
pub fn record_proof_received(circuit_id: &str, source: &str) {
    counter!(
        "sincerin_collector_proofs_received_total",
        "circuit_id" => circuit_id.to_owned(),
        "source" => source.to_owned()
    )
    .increment(1);
}

/// Record a successfully verified and registered proof.
pub fn record_proof_verified(circuit_id: &str, gas_used: u64, latency_ms: u64) {
    counter!(
        "sincerin_collector_proofs_verified_total",
        "circuit_id" => circuit_id.to_owned()
    )
    .increment(1);

    histogram!(
        "sincerin_collector_verification_latency_ms",
        "circuit_id" => circuit_id.to_owned()
    )
    .record(latency_ms as f64);

    histogram!(
        "sincerin_collector_gas_used",
        "circuit_id" => circuit_id.to_owned()
    )
    .record(gas_used as f64);
}

/// Record a failed proof verification.
pub fn record_proof_failed(circuit_id: &str, reason: &str) {
    counter!(
        "sincerin_collector_proofs_failed_total",
        "circuit_id" => circuit_id.to_owned(),
        "reason" => reason.to_owned()
    )
    .increment(1);
}

/// Record an L1 transaction sent (verify or register).
pub fn record_l1_tx(action: &str, status: &str, latency_ms: u64, gas_used: u64) {
    counter!(
        "sincerin_collector_l1_transactions_total",
        "action" => action.to_owned(),
        "status" => status.to_owned()
    )
    .increment(1);

    histogram!(
        "sincerin_collector_l1_tx_latency_ms",
        "action" => action.to_owned()
    )
    .record(latency_ms as f64);

    if gas_used > 0 {
        histogram!(
            "sincerin_collector_l1_tx_gas_used",
            "action" => action.to_owned()
        )
        .record(gas_used as f64);
    }
}

/// Set the gauge for currently active verification tasks.
pub fn set_active_verifications(count: u64) {
    gauge!("sincerin_collector_active_verifications").set(count as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that recording functions do not panic without a global
    /// metrics recorder installed (metrics crate silently drops).
    #[test]
    fn test_metrics_dont_panic() {
        record_proof_received("proof-of-membership", "prover");
        record_proof_received("proof-of-age", "client");
        record_proof_verified("proof-of-membership", 20_000, 1500);
        record_proof_failed("proof-of-age", "l1_verification_failed");
        record_l1_tx("submit_proof", "success", 800, 30_000);
        record_l1_tx("submit_proof", "reverted", 200, 0);
        set_active_verifications(3);
    }
}
