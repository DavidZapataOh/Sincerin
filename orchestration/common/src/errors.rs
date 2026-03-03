//! Unified error type for the Sincerin orchestration layer.
//!
//! Every crate in the workspace converts its local errors into
//! `SincerinError` at the boundary so that callers see one coherent
//! type.  Variants are ordered by frequency of occurrence in
//! production to keep match arms readable.
//!
//! Design notes (Buterin): one error type, one serialization format.
//! Design notes (Drake): every failure path is named and typed so
//! that monitoring can bucket errors precisely.

use crate::types::PrivacyStrategy;
use thiserror::Error;

/// Canonical error type for all orchestration services.
#[derive(Debug, Error)]
pub enum SincerinError {
    /// The requested circuit ID was not found in the registry.
    #[error("Circuit not found: {0}")]
    CircuitNotFound(String),

    /// No prover is available to handle the request (all offline,
    /// at capacity, or lacking the required capabilities).
    #[error("Prover unavailable: {0}")]
    ProverUnavailable(String),

    /// The proof failed L1 precompile verification.
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// An error from the NATS JetStream transport layer.
    #[error("NATS error: {0}")]
    NatsError(#[from] async_nats::Error),

    /// An error from the Sincerin L1 (RPC failure, revert, etc.).
    #[error("L1 error: {0}")]
    L1Error(String),

    /// JSON serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// An operation exceeded its deadline.  The `u64` is the
    /// timeout in milliseconds.
    #[error("Timeout: operation exceeded {0}ms")]
    Timeout(u64),

    /// The dispatcher cannot fulfil the requested privacy strategy
    /// given the current prover fleet and circuit capabilities.
    #[error("Privacy strategy not supported: {0:?}")]
    UnsupportedPrivacy(PrivacyStrategy),

    /// A configuration value is missing or invalid.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Client-supplied input failed validation.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

// -- Manual `From` impls for types that cannot use `#[from]` ---------------

impl From<config::ConfigError> for SincerinError {
    fn from(err: config::ConfigError) -> Self {
        SincerinError::ConfigError(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SincerinError::CircuitNotFound("proof-of-age".to_string());
        assert_eq!(err.to_string(), "Circuit not found: proof-of-age");

        let err = SincerinError::Timeout(5000);
        assert_eq!(err.to_string(), "Timeout: operation exceeded 5000ms");
    }

    #[test]
    fn test_error_from_serde_json() {
        // Create a real serde_json::Error by trying to parse invalid JSON.
        let result: Result<serde_json::Value, _> = serde_json::from_str("not valid json");
        let json_err = result.unwrap_err();

        let sincerin_err: SincerinError = json_err.into();
        match &sincerin_err {
            SincerinError::SerializationError(_) => {} // expected
            other => panic!("expected SerializationError, got: {other:?}"),
        }

        // The Display impl should contain the underlying serde message.
        let msg = sincerin_err.to_string();
        assert!(
            msg.contains("Serialization error"),
            "expected 'Serialization error' in: {msg}"
        );
    }
}
