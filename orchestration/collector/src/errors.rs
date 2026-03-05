//! Collector-specific error types.
//!
//! Each variant is classified as retryable or non-retryable to guide
//! the NATS ack/nack decision in the main loop.

use thiserror::Error;

/// Errors specific to the Collector service.
#[derive(Debug, Error)]
pub enum CollectorError {
    /// Proof bytes are empty — cannot submit to L1.
    #[error("empty proof: proof bytes are empty")]
    EmptyProof,

    /// Proof is suspiciously small (< 100 bytes for UltraHonk).
    #[error("proof too small: {0} bytes (minimum 100)")]
    ProofTooSmall(usize),

    /// A public input exceeds the 32-byte field element limit.
    #[error("invalid public input at index {0}: {1} bytes (max 32)")]
    InvalidPublicInput(usize, usize),

    /// L1 precompile rejected the proof (transaction reverted).
    #[error("verification failed on L1: {0}")]
    VerificationFailed(String),

    /// ProofRegistry insert failed after successful verification.
    /// This is a critical inconsistency — the proof is verified but
    /// not registered.
    #[error("registration failed: {0}")]
    RegistrationFailed(String),

    /// The ProofVerified event was not found in the transaction receipt.
    #[error("ProofVerified event not found in receipt")]
    EventNotFound,

    /// Generic L1 interaction error (RPC timeout, connection, nonce).
    #[error("L1 error: {0}")]
    L1Error(String),

    /// NATS messaging error.
    #[error("NATS error: {0}")]
    NatsError(String),

    /// JSON serialization/deserialization error.
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Consumer setup or fetch error.
    #[error("consumer error: {0}")]
    ConsumerError(String),
}

impl CollectorError {
    /// Whether this error should trigger a NATS nack for redelivery.
    ///
    /// Retryable: L1 timeouts, nonce errors, NATS failures.
    /// Non-retryable: invalid proofs, verification failures, bad inputs.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            CollectorError::L1Error(_) | CollectorError::NatsError(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retryable_classification() {
        assert!(CollectorError::L1Error("timeout".into()).is_retryable());
        assert!(CollectorError::NatsError("connection".into()).is_retryable());

        assert!(!CollectorError::EmptyProof.is_retryable());
        assert!(!CollectorError::ProofTooSmall(50).is_retryable());
        assert!(!CollectorError::VerificationFailed("invalid".into()).is_retryable());
        assert!(!CollectorError::EventNotFound.is_retryable());
        assert!(!CollectorError::InvalidPublicInput(0, 64).is_retryable());
    }

    #[test]
    fn test_error_display() {
        let err = CollectorError::ProofTooSmall(42);
        assert_eq!(err.to_string(), "proof too small: 42 bytes (minimum 100)");

        let err = CollectorError::InvalidPublicInput(3, 48);
        assert_eq!(
            err.to_string(),
            "invalid public input at index 3: 48 bytes (max 32)"
        );
    }
}
