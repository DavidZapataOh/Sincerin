use thiserror::Error;

/// Dispatcher-specific errors.
#[derive(Debug, Error)]
pub enum DispatcherError {
    #[error("Unknown circuit: {0}")]
    UnknownCircuit(String),

    #[error("NATS error: {0}")]
    Nats(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Consumer error: {0}")]
    Consumer(String),

    #[error("Publish failed: {0}")]
    PublishFailed(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

impl DispatcherError {
    /// Whether this error is retryable (should nack the message).
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Nats(_) | Self::PublishFailed(_))
    }
}
