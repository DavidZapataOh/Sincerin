//! NATS JetStream pull consumers for the Collector.
//!
//! The collector listens on two streams:
//! - **PROOF_RESULTS**: completed proofs from prover nodes (delegated proving).
//! - **PROOF_CLIENT**: proofs submitted directly by clients (client-side proving).
//!
//! Both consumers use pull-based delivery with explicit ack so that
//! failed verifications can be nacked for redelivery (retryable) or
//! acked to prevent infinite loops (non-retryable).

use std::time::Duration;

use async_nats::jetstream::consumer::pull::Config as PullConfig;
use async_nats::jetstream::consumer::AckPolicy;
use async_nats::jetstream::Context as JetStream;
use futures::StreamExt;
use tracing::{error, info, warn};

use sincerin_common::nats::subjects;
use sincerin_common::types::ProofResult;

use crate::config::CollectorConfig;
use crate::errors::CollectorError;

/// A pull-based NATS JetStream consumer for proof results from provers.
pub struct ResultConsumer {
    js: JetStream,
    config: CollectorConfig,
}

impl ResultConsumer {
    /// Create and register the durable consumer on PROOF_RESULTS.
    pub async fn new(js: JetStream, config: CollectorConfig) -> Result<Self, CollectorError> {
        let stream = js
            .get_stream("PROOF_RESULTS")
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        let consumer_config = PullConfig {
            durable_name: Some(config.consumer_name.clone()),
            filter_subject: subjects::PROOF_RESULTS.to_string(),
            ack_policy: AckPolicy::Explicit,
            max_deliver: config.max_retries as i64,
            ack_wait: Duration::from_secs(60),
            ..Default::default()
        };

        stream
            .get_or_create_consumer(&config.consumer_name, consumer_config)
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        info!(
            consumer = %config.consumer_name,
            filter = subjects::PROOF_RESULTS,
            max_deliver = config.max_retries,
            "Result consumer ready"
        );

        Ok(Self { js, config })
    }

    /// Fetch a batch of proof results from the stream.
    ///
    /// Malformed messages are acked immediately to prevent infinite redelivery.
    pub async fn fetch_batch(&self) -> Result<Vec<(ProofResult, MessageHandle)>, CollectorError> {
        let stream = self
            .js
            .get_stream("PROOF_RESULTS")
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        let consumer = stream
            .get_consumer::<PullConfig>(&self.config.consumer_name)
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        let mut messages = consumer
            .fetch()
            .max_messages(10)
            .expires(Duration::from_millis(500))
            .messages()
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        let mut batch = Vec::new();

        while let Some(msg_result) = messages.next().await {
            match msg_result {
                Ok(msg) => match serde_json::from_slice::<ProofResult>(&msg.payload) {
                    Ok(result) => {
                        batch.push((result, MessageHandle(msg)));
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Malformed message in PROOF_RESULTS — acking to prevent redelivery"
                        );
                        if let Err(ack_err) = msg.ack().await {
                            error!(error = %ack_err, "Failed to ack malformed message");
                        }
                    }
                },
                Err(e) => {
                    error!(error = %e, "Error fetching message from result consumer");
                }
            }
        }

        Ok(batch)
    }
}

/// A pull-based NATS JetStream consumer for client-side proofs.
///
/// When the dispatcher routes a request to client-side proving, the
/// original ProofRequest is published to `sincerin.proofs.client`.
/// The client SDK generates the proof locally and publishes the
/// ProofResult to the same subject for the collector to verify on-chain.
pub struct ClientConsumer {
    js: JetStream,
    config: CollectorConfig,
}

impl ClientConsumer {
    /// Create and register the durable consumer on PROOF_CLIENT.
    pub async fn new(js: JetStream, config: CollectorConfig) -> Result<Self, CollectorError> {
        let stream = js
            .get_stream("PROOF_CLIENT")
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        let consumer_config = PullConfig {
            durable_name: Some(config.client_consumer_name.clone()),
            filter_subject: subjects::PROOF_CLIENT.to_string(),
            ack_policy: AckPolicy::Explicit,
            max_deliver: config.max_retries as i64,
            ack_wait: Duration::from_secs(60),
            ..Default::default()
        };

        stream
            .get_or_create_consumer(&config.client_consumer_name, consumer_config)
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        info!(
            consumer = %config.client_consumer_name,
            filter = subjects::PROOF_CLIENT,
            max_deliver = config.max_retries,
            "Client consumer ready"
        );

        Ok(Self { js, config })
    }

    /// Fetch a batch of client-side proof results from the stream.
    pub async fn fetch_batch(&self) -> Result<Vec<(ProofResult, MessageHandle)>, CollectorError> {
        let stream = self
            .js
            .get_stream("PROOF_CLIENT")
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        let consumer = stream
            .get_consumer::<PullConfig>(&self.config.client_consumer_name)
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        let mut messages = consumer
            .fetch()
            .max_messages(10)
            .expires(Duration::from_millis(500))
            .messages()
            .await
            .map_err(|e| CollectorError::ConsumerError(e.to_string()))?;

        let mut batch = Vec::new();

        while let Some(msg_result) = messages.next().await {
            match msg_result {
                Ok(msg) => match serde_json::from_slice::<ProofResult>(&msg.payload) {
                    Ok(result) => {
                        batch.push((result, MessageHandle(msg)));
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Malformed message in PROOF_CLIENT — acking to prevent redelivery"
                        );
                        if let Err(ack_err) = msg.ack().await {
                            error!(error = %ack_err, "Failed to ack malformed message");
                        }
                    }
                },
                Err(e) => {
                    error!(error = %e, "Error fetching message from client consumer");
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
    pub async fn ack(self) -> Result<(), CollectorError> {
        self.0
            .ack()
            .await
            .map_err(|e| CollectorError::NatsError(e.to_string()))
    }

    /// Negative-acknowledge to trigger redelivery.
    pub async fn nack(self) -> Result<(), CollectorError> {
        self.0
            .ack_with(async_nats::jetstream::AckKind::Nak(None))
            .await
            .map_err(|e| CollectorError::NatsError(e.to_string()))
    }
}
