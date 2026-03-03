//! Prometheus metrics for the Sincerin orchestration layer.
//!
//! All metric names use the `sincerin_` prefix for namespace isolation.
//! Functions use the `metrics` crate macros (counter!, gauge!, histogram!)
//! so that any exporter backend (Prometheus, StatsD, etc.) works without
//! code changes.
//!
//! Design notes (Buterin): one metrics format, one naming convention,
//! no fragmentation.  Concrete numerical targets drive what we measure:
//! orchestration overhead <10ms, generation time per circuit, gas per
//! verification.

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

// ---------------------------------------------------------------------------
// Metric name constants
// ---------------------------------------------------------------------------

/// Well-known metric name constants.
///
/// Centralised here so that dashboards, alerts, and tests can reference
/// the canonical string without risk of typos.
pub mod names {
    /// Counter: total proof requests received by the Gateway.
    pub const PROOF_REQUESTS_TOTAL: &str = "sincerin_proof_requests_total";
    /// Counter: proofs that passed L1 precompile verification.
    pub const PROOFS_VERIFIED_TOTAL: &str = "sincerin_proofs_verified_total";
    /// Counter: proofs that failed generation or verification.
    pub const PROOFS_FAILED_TOTAL: &str = "sincerin_proofs_failed_total";
    /// Histogram: wall-clock proof generation time in seconds.
    pub const PROOF_GENERATION_TIME: &str = "sincerin_proof_generation_seconds";
    /// Histogram: end-to-end orchestration latency in seconds
    /// (Gateway ingestion to L1 verification).
    pub const ORCHESTRATION_LATENCY: &str = "sincerin_orchestration_latency_seconds";
    /// Gauge: number of proof requests currently in flight.
    pub const ACTIVE_PROOF_REQUESTS: &str = "sincerin_active_proof_requests";
    /// Gauge: number of prover nodes currently connected.
    pub const CONNECTED_PROVERS: &str = "sincerin_connected_provers";
    /// Histogram: gas consumed by verification precompile calls.
    pub const VERIFICATION_GAS_USED: &str = "sincerin_verification_gas_used";
}

// ---------------------------------------------------------------------------
// Recording helpers
// ---------------------------------------------------------------------------

/// Record a new proof request, labelled by circuit and priority tier.
pub fn record_proof_request(circuit_id: &str, priority: &str) {
    counter!(names::PROOF_REQUESTS_TOTAL, "circuit_id" => circuit_id.to_owned(), "priority" => priority.to_owned())
        .increment(1);
}

/// Record a successfully verified proof, labelled by circuit.
/// `gas_used` is recorded as a histogram observation so we can
/// track percentiles across different circuits and proof systems.
pub fn record_proof_verified(circuit_id: &str, gas_used: u64) {
    counter!(names::PROOFS_VERIFIED_TOTAL, "circuit_id" => circuit_id.to_owned()).increment(1);
    histogram!(names::VERIFICATION_GAS_USED, "circuit_id" => circuit_id.to_owned())
        .record(gas_used as f64);
}

/// Record a failed proof, labelled by circuit and failure reason.
pub fn record_proof_failed(circuit_id: &str, reason: &str) {
    counter!(names::PROOFS_FAILED_TOTAL, "circuit_id" => circuit_id.to_owned(), "reason" => reason.to_owned())
        .increment(1);
}

/// Record proof generation wall-clock time in seconds.
pub fn record_generation_time(circuit_id: &str, duration_secs: f64) {
    histogram!(names::PROOF_GENERATION_TIME, "circuit_id" => circuit_id.to_owned())
        .record(duration_secs);
}

/// Record end-to-end orchestration latency in seconds.
pub fn record_orchestration_latency(duration_secs: f64) {
    histogram!(names::ORCHESTRATION_LATENCY).record(duration_secs);
}

/// Set the current number of active (in-flight) proof requests.
pub fn set_active_requests(count: u64) {
    gauge!(names::ACTIVE_PROOF_REQUESTS).set(count as f64);
}

/// Set the current number of connected prover nodes.
pub fn set_connected_provers(count: u64) {
    gauge!(names::CONNECTED_PROVERS).set(count as f64);
}

// ---------------------------------------------------------------------------
// Exporter initialisation
// ---------------------------------------------------------------------------

/// Initialise a Prometheus metrics exporter listening on `0.0.0.0:{port}`.
///
/// This installs a global recorder; call it once at process start.
/// After this call, all `counter!` / `gauge!` / `histogram!` invocations
/// in any crate will be captured and served at `GET /metrics`.
pub fn init_metrics_exporter(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], port))
        .install()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that every metric name constant starts with "sincerin_".
    #[test]
    fn test_metric_names_consistent() {
        let all_names = [
            names::PROOF_REQUESTS_TOTAL,
            names::PROOFS_VERIFIED_TOTAL,
            names::PROOFS_FAILED_TOTAL,
            names::PROOF_GENERATION_TIME,
            names::ORCHESTRATION_LATENCY,
            names::ACTIVE_PROOF_REQUESTS,
            names::CONNECTED_PROVERS,
            names::VERIFICATION_GAS_USED,
        ];

        for name in &all_names {
            assert!(
                name.starts_with("sincerin_"),
                "metric name must start with 'sincerin_', got: {name}"
            );
        }
    }

    /// Verify that recording functions do not panic when called
    /// without a global recorder installed.  The `metrics` crate
    /// silently drops observations when no recorder is set, which
    /// is the correct behaviour during unit tests.
    #[test]
    fn test_record_functions_dont_panic() {
        record_proof_request("circuit-age-18", "standard");
        record_proof_verified("circuit-age-18", 20_000);
        record_proof_failed("circuit-age-18", "timeout");
        record_generation_time("circuit-age-18", 1.234);
        record_orchestration_latency(0.005);
        set_active_requests(42);
        set_connected_provers(8);
    }
}
