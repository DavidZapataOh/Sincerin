use std::time::Duration;

use async_nats::jetstream::consumer::pull::Config as PullConfig;
use async_nats::jetstream::consumer::AckPolicy;
use async_nats::jetstream::Context as JetStream;
use futures::StreamExt;
use tracing::{error, info, warn};

use sincerin_common::nats::subjects;
use sincerin_common::types::ProofRequest;

use crate::config::DispatcherConfig;

/// A pull-based NATS JetStream consumer for proof requests.
pub struct RequestConsumer {
    js: JetStream,
    config: DispatcherConfig,
}

impl RequestConsumer {
    /// Create a new consumer, setting up (or reusing) the durable consumer
    /// on the PROOFS stream.
    pub async fn new(
        js: JetStream,
        config: DispatcherConfig,
    ) -> Result<Self, crate::errors::DispatcherError> {
        // Ensure the durable consumer exists (idempotent).
        let stream = js
            .get_stream("PROOF_REQUESTS")
            .await
            .map_err(|e| crate::errors::DispatcherError::Consumer(e.to_string()))?;

        let consumer_config = PullConfig {
            durable_name: Some(config.consumer_name.clone()),
            filter_subject: subjects::PROOF_REQUESTS.to_string(),
            ack_policy: AckPolicy::Explicit,
            max_deliver: config.max_retries as i64,
            ack_wait: Duration::from_secs(30),
            ..Default::default()
        };

        stream
            .get_or_create_consumer(&config.consumer_name, consumer_config)
            .await
            .map_err(|e| crate::errors::DispatcherError::Consumer(e.to_string()))?;

        info!(
            consumer = %config.consumer_name,
            filter = subjects::PROOF_REQUESTS,
            max_deliver = config.max_retries,
            "Durable consumer ready"
        );

        Ok(Self { js, config })
    }

    /// Fetch a batch of proof requests from the stream.
    ///
    /// Returns a vector of `(ProofRequest, AckHandle)` tuples.
    /// Malformed messages are acked immediately (no infinite redelivery).
    pub async fn fetch_batch(
        &self,
    ) -> Result<Vec<(ProofRequest, MessageHandle)>, crate::errors::DispatcherError> {
        let stream = self
            .js
            .get_stream("PROOF_REQUESTS")
            .await
            .map_err(|e| crate::errors::DispatcherError::Consumer(e.to_string()))?;

        let consumer = stream
            .get_consumer::<PullConfig>(&self.config.consumer_name)
            .await
            .map_err(|e| crate::errors::DispatcherError::Consumer(e.to_string()))?;

        let mut messages = consumer
            .fetch()
            .max_messages(self.config.batch_size)
            .expires(Duration::from_millis(self.config.batch_wait_ms))
            .messages()
            .await
            .map_err(|e| crate::errors::DispatcherError::Consumer(e.to_string()))?;

        let mut batch = Vec::new();

        while let Some(msg_result) = messages.next().await {
            match msg_result {
                Ok(msg) => {
                    let payload = &msg.payload;
                    match serde_json::from_slice::<ProofRequest>(payload) {
                        Ok(request) => {
                            batch.push((request, MessageHandle(msg)));
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "Malformed message in PROOF_REQUESTS — acking to prevent redelivery"
                            );
                            if let Err(ack_err) = msg.ack().await {
                                error!(error = %ack_err, "Failed to ack malformed message");
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Error fetching message from consumer");
                }
            }
        }

        Ok(batch)
    }
}

/// Wrapper around a NATS message for ack/nack operations.
pub struct MessageHandle(async_nats::jetstream::Message);

impl MessageHandle {
    /// Acknowledge successful processing.
    pub async fn ack(self) -> Result<(), crate::errors::DispatcherError> {
        self.0
            .ack()
            .await
            .map_err(|e| crate::errors::DispatcherError::Nats(e.to_string()))
    }

    /// Negative-acknowledge to trigger redelivery.
    pub async fn nack(self) -> Result<(), crate::errors::DispatcherError> {
        self.0
            .ack_with(async_nats::jetstream::AckKind::Nak(None))
            .await
            .map_err(|e| crate::errors::DispatcherError::Nats(e.to_string()))
    }
}
