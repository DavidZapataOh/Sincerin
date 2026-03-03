use thiserror::Error;

/// Prover-node–specific errors.
#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Circuit not found: {0}")]
    CircuitNotFound(String),

    #[error("bb binary not found at {0}")]
    BbNotFound(String),

    #[error("Proof generation failed: {0}")]
    ProveFailed(String),

    #[error("Verification failed: {0}")]
    VerifyFailed(String),

    #[error("Missing witness for DirectDelegation task")]
    MissingWitness,

    #[error("Unexpected client-side task reached prover")]
    UnexpectedClientSideTask,

    #[error("Unsupported strategy: {0}")]
    UnsupportedStrategy(String),

    #[error("NATS error: {0}")]
    Nats(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Publish failed: {0}")]
    PublishFailed(String),

    #[error("Empty witness")]
    EmptyWitness,
}

impl ProverError {
    /// Whether this error is retryable (should nack the NATS message).
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Nats(_) | Self::PublishFailed(_))
    }
}
