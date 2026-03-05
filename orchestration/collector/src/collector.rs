//! Core collector business logic — verify-then-register flow.
//!
//! The `Collector` struct ties together the NATS consumers, L1 verifier,
//! and status publishing into a single processing pipeline:
//!
//! 1. Receive `ProofResult` from NATS (prover or client stream)
//! 2. Validate proof format (basic sanity checks)
//! 3. Submit to `Coordinator.submitProof()` on the L1
//!    - Coordinator calls VerifyUltraHonk precompile (~20K gas)
//!    - On success, Coordinator calls ProofRegistry.registerProof()
//!      which uses MerkleTreeInsert precompile (~500 gas)
//! 4. Publish `ProofStatus::VerifiedL1` via NATS for Gateway WebSocket
//! 5. Ack the NATS message

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use async_nats::jetstream::Context as JetStream;
use tracing::{error, info, warn};

use sincerin_common::nats;
use sincerin_common::types::{ProofResult, ProofStatus};

use crate::config::CollectorConfig;
use crate::consumer::MessageHandle;
use crate::errors::CollectorError;
use crate::l1_verifier::L1Verifier;
use crate::metrics;

/// Active verification counter for the gauge metric.
static ACTIVE_VERIFICATIONS: AtomicU64 = AtomicU64::new(0);

/// Validate basic proof format before submitting to L1.
pub fn validate_proof(result: &ProofResult) -> Result<(), CollectorError> {
    if result.proof.is_empty() {
        return Err(CollectorError::EmptyProof);
    }

    // UltraHonk proofs are typically >100 bytes.
    if result.proof.len() < 100 {
        return Err(CollectorError::ProofTooSmall(result.proof.len()));
    }

    Ok(())
}

/// Encode public inputs from JSON to bytes for L1 submission.
///
/// The public inputs in ProofResult are stored as a JSON Value.
/// For L1 submission, we serialize them as JSON bytes that the
/// Coordinator contract will forward to the verification precompile.
pub fn encode_public_inputs(
    public_inputs: &serde_json::Value,
) -> Result<Vec<u8>, CollectorError> {
    serde_json::to_vec(public_inputs).map_err(CollectorError::SerializationError)
}

/// Core collector that processes proof results.
pub struct Collector {
    verifier: L1Verifier,
    js: JetStream,
    config: CollectorConfig,
}

impl Collector {
    /// Create a new Collector with the given L1 verifier and NATS context.
    pub fn new(verifier: L1Verifier, js: JetStream, config: CollectorConfig) -> Self {
        Self {
            verifier,
            js,
            config,
        }
    }

    /// Process a single proof result: validate, verify on L1, publish status.
    ///
    /// On success, acks the NATS message. On retryable error, nacks for
    /// redelivery. On non-retryable error, acks to prevent infinite loops.
    pub async fn process_proof(
        &self,
        result: ProofResult,
        handle: MessageHandle,
        source: &str,
    ) {
        let request_id = result.request_id.clone();
        let circuit_id = result.circuit_id.clone();

        metrics::record_proof_received(&circuit_id, source);

        match self.verify_and_register(&result).await {
            Ok(()) => {
                if let Err(e) = handle.ack().await {
                    error!(error = %e, request_id = %request_id, "Failed to ack message");
                }
            }
            Err(e) if e.is_retryable() => {
                error!(
                    error = %e,
                    request_id = %request_id,
                    "Retryable error — nacking for redelivery"
                );
                metrics::record_proof_failed(&circuit_id, "retryable");
                if let Err(nack_err) = handle.nack().await {
                    error!(error = %nack_err, "Failed to nack message");
                }
            }
            Err(e) => {
                error!(
                    error = %e,
                    request_id = %request_id,
                    "Non-retryable error — acking to prevent redelivery"
                );
                metrics::record_proof_failed(&circuit_id, &e.to_string());

                // Publish failure status so the client knows.
                let _ = nats::publish_status_update(
                    &self.js,
                    &request_id,
                    &ProofStatus::Failed {
                        reason: e.to_string(),
                        stage: "verification".to_string(),
                    },
                )
                .await;

                if let Err(ack_err) = handle.ack().await {
                    error!(error = %ack_err, "Failed to ack message after error");
                }
            }
        }
    }

    /// Core verify-then-register flow with retry logic.
    async fn verify_and_register(&self, result: &ProofResult) -> Result<(), CollectorError> {
        // 1. Validate proof format.
        validate_proof(result)?;

        // 2. Publish "Verifying" status.
        let _ = nats::publish_status_update(
            &self.js,
            &result.request_id,
            &ProofStatus::Verifying,
        )
        .await;

        // 3. Submit to L1 with retry logic.
        let start = Instant::now();
        ACTIVE_VERIFICATIONS.fetch_add(1, Ordering::Relaxed);
        metrics::set_active_verifications(ACTIVE_VERIFICATIONS.load(Ordering::Relaxed));

        let verification = self.submit_with_retry(result).await;

        ACTIVE_VERIFICATIONS.fetch_sub(1, Ordering::Relaxed);
        metrics::set_active_verifications(ACTIVE_VERIFICATIONS.load(Ordering::Relaxed));

        let verification = verification?;
        let latency_ms = start.elapsed().as_millis() as u64;

        // 4. Record metrics.
        metrics::record_proof_verified(
            &result.circuit_id,
            verification.gas_used,
            latency_ms,
        );
        metrics::record_l1_tx("submit_proof", "success", latency_ms, verification.gas_used);

        // 5. Publish VerifiedL1 status for Gateway WebSocket.
        let status = ProofStatus::VerifiedL1 {
            proof_id: verification.proof_id.clone(),
            tx_hash: verification.tx_hash.clone(),
            gas_used: verification.gas_used,
        };

        if let Err(e) = nats::publish_status_update(&self.js, &result.request_id, &status).await {
            warn!(
                error = %e,
                request_id = %result.request_id,
                "Failed to publish VerifiedL1 status (non-fatal)"
            );
        }

        info!(
            request_id = %result.request_id,
            proof_id = %verification.proof_id,
            tx_hash = %verification.tx_hash,
            gas_used = verification.gas_used,
            latency_ms = latency_ms,
            "Proof verified and registered on L1"
        );

        Ok(())
    }

    /// Submit proof to L1 with exponential backoff retry.
    async fn submit_with_retry(
        &self,
        result: &ProofResult,
    ) -> Result<crate::l1_verifier::VerificationResult, CollectorError> {
        let public_inputs_bytes = encode_public_inputs(&result.public_inputs)?;

        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                let delay_ms = self.config.retry_delay_ms * 2u64.pow(attempt - 1);
                warn!(
                    attempt = attempt,
                    delay_ms = delay_ms,
                    request_id = %result.request_id,
                    "Retrying L1 submission"
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            let start = Instant::now();
            match self
                .verifier
                .submit_proof(&result.request_id, &result.proof, &public_inputs_bytes)
                .await
            {
                Ok(verification) => return Ok(verification),
                Err(e) if e.is_retryable() => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    metrics::record_l1_tx("submit_proof", "retry", latency_ms, 0);
                    last_error = Some(e);
                    continue;
                }
                Err(e) => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    metrics::record_l1_tx("submit_proof", "failed", latency_ms, 0);
                    return Err(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            CollectorError::L1Error("max retries exceeded".to_string())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sincerin_common::types::privacy::PrivacyStrategy;

    fn sample_proof_result() -> ProofResult {
        ProofResult {
            request_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            proof_id: "proof-abc".to_string(),
            circuit_id: "circuit-age-18".to_string(),
            proof: vec![0u8; 200], // 200 bytes — passes minimum check
            public_inputs: serde_json::json!({"age_threshold": 18}),
            privacy_strategy: PrivacyStrategy::DirectDelegation,
            prover_id: "prover-1".to_string(),
            proving_time_ms: 1200,
            verified: false,
            verification_gas: 0,
            l1_tx_hash: None,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn test_validate_proof_empty() {
        let mut result = sample_proof_result();
        result.proof = vec![];

        assert!(matches!(
            validate_proof(&result),
            Err(CollectorError::EmptyProof)
        ));
    }

    #[test]
    fn test_validate_proof_too_small() {
        let mut result = sample_proof_result();
        result.proof = vec![0u8; 50];

        assert!(matches!(
            validate_proof(&result),
            Err(CollectorError::ProofTooSmall(50))
        ));
    }

    #[test]
    fn test_validate_proof_ok() {
        let result = sample_proof_result();
        assert!(validate_proof(&result).is_ok());
    }

    #[test]
    fn test_encode_public_inputs() {
        let inputs = serde_json::json!({"age_threshold": 18});
        let encoded = encode_public_inputs(&inputs).unwrap();

        // Should be valid JSON bytes.
        let decoded: serde_json::Value =
            serde_json::from_slice(&encoded).expect("should be valid JSON");
        assert_eq!(decoded["age_threshold"], 18);
    }

    #[test]
    fn test_validate_proof_exact_boundary() {
        let mut result = sample_proof_result();
        result.proof = vec![0u8; 100]; // exactly 100 bytes — should pass
        assert!(validate_proof(&result).is_ok());

        result.proof = vec![0u8; 99]; // 99 bytes — should fail
        assert!(matches!(
            validate_proof(&result),
            Err(CollectorError::ProofTooSmall(99))
        ));
    }
}
