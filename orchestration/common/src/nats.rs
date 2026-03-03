//! NATS JetStream helpers for Sincerin orchestration.
//!
//! Provides connection management, stream setup, and typed publishing
//! over NATS JetStream. All inter-service communication in the Sincerin
//! orchestration layer flows through these primitives.
//!
//! # Design rationale
//!
//! **Standardize aggressively** (Buterin): one messaging transport, one
//! serialization format (JSON), one set of subject conventions.
//!
//! **Sovereign isolation** (Sirer): each service connects independently
//! and consumes from its own pull consumer. This module only provides
//! the shared setup and publish path -- consumer creation is left to
//! each service because the async_nats pull consumer API requires
//! service-specific configuration.
//!
//! **Encapsulate complexity** (Drake): stream retention policies, TTLs,
//! and subject naming are defined here once and reused everywhere.

use std::time::Duration;

use anyhow::Result;
// DeserializeOwned is re-exported for consumers that need to
// deserialize messages received from JetStream pull consumers.
use serde::Serialize;
#[allow(unused_imports)]
use serde::de::DeserializeOwned;

/// NATS subject constants for the Sincerin orchestration layer.
///
/// All subjects are prefixed with `sincerin.` to namespace them within
/// a shared NATS cluster. Status subjects use a wildcard segment for
/// the request ID, enabling per-request subscriptions.
pub mod subjects {
    /// Subject for new proof generation requests.
    /// Retention: WorkQueue (each request consumed exactly once).
    pub const PROOF_REQUESTS: &str = "sincerin.proofs.requests";

    /// Subject for completed proof results.
    /// Retention: WorkQueue (each result consumed exactly once).
    pub const PROOF_RESULTS: &str = "sincerin.proofs.results";

    /// Subject prefix for proof status updates.
    /// Full subject: `sincerin.proofs.status.<request_id>`.
    /// Retention: Limits (status history retained for observability).
    pub const PROOF_STATUS: &str = "sincerin.proofs.status";

    /// Subject prefix for prover task assignment.
    /// Full subject: `sincerin.proofs.tasks.<prover_id>`.
    /// Retention: WorkQueue (each task consumed exactly once).
    pub const PROOF_TASKS: &str = "sincerin.proofs.tasks";

    /// Subject for client-side proving requests.
    /// When the dispatcher routes a request to client-side proving,
    /// the original ProofRequest is published here for the collector.
    pub const PROOF_CLIENT: &str = "sincerin.proofs.client";

    /// Subject for prover node heartbeats.
    /// Used by the dispatcher for liveness tracking and load balancing.
    pub const PROVER_HEARTBEAT: &str = "sincerin.provers.heartbeat";
}

/// Connect to a NATS server at the given URL.
///
/// Logs the connection attempt and success via `tracing::info`.
/// Returns an `anyhow::Result` so callers get uniform error handling
/// across the orchestration layer.
pub async fn connect(url: &str) -> Result<async_nats::Client> {
    tracing::info!(url = url, "connecting to NATS server");
    let client = async_nats::connect(url).await?;
    tracing::info!(url = url, "connected to NATS server");
    Ok(client)
}

/// Create a JetStream context from an existing NATS client.
///
/// This is a thin wrapper around `async_nats::jetstream::new` that
/// provides a consistent API surface within the Sincerin codebase.
pub fn jetstream_context(client: &async_nats::Client) -> async_nats::jetstream::Context {
    async_nats::jetstream::new(client.clone())
}

/// Create (or verify existence of) the three core JetStream streams
/// required by the Sincerin orchestration layer.
///
/// | Stream | Retention | TTL | Subjects |
/// |--------|-----------|-----|----------|
/// | PROOF_REQUESTS | WorkQueue | 1h | `sincerin.proofs.requests` |
/// | PROOF_RESULTS | WorkQueue | 1h | `sincerin.proofs.results` |
/// | PROOF_STATUS | Limits | 24h | `sincerin.proofs.status.*` |
///
/// Uses `get_or_create_stream` so the function is idempotent -- safe
/// to call on every service startup without coordination.
pub async fn setup_streams(client: &async_nats::Client) -> Result<()> {
    use async_nats::jetstream::stream::{Config, RetentionPolicy};

    let js = async_nats::jetstream::new(client.clone());

    // PROOF_REQUESTS: work-queue semantics ensure each request is
    // dispatched to exactly one prover node.
    js.get_or_create_stream(Config {
        name: "PROOF_REQUESTS".to_string(),
        subjects: vec![subjects::PROOF_REQUESTS.to_string()],
        retention: RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(3600), // 1 hour TTL
        ..Default::default()
    })
    .await?;
    tracing::info!("stream PROOF_REQUESTS ready");

    // PROOF_RESULTS: work-queue semantics ensure each result is
    // collected exactly once by the collector service.
    js.get_or_create_stream(Config {
        name: "PROOF_RESULTS".to_string(),
        subjects: vec![subjects::PROOF_RESULTS.to_string()],
        retention: RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(3600), // 1 hour TTL
        ..Default::default()
    })
    .await?;
    tracing::info!("stream PROOF_RESULTS ready");

    // PROOF_STATUS: limits retention keeps a history of status updates
    // for observability and WebSocket replay. Wildcard subject allows
    // per-request filtering.
    js.get_or_create_stream(Config {
        name: "PROOF_STATUS".to_string(),
        subjects: vec![format!("{}.*", subjects::PROOF_STATUS)],
        retention: RetentionPolicy::Limits,
        max_age: Duration::from_secs(86400), // 24 hour TTL
        ..Default::default()
    })
    .await?;
    tracing::info!("stream PROOF_STATUS ready");

    // PROOF_TASKS: work-queue semantics ensure each prover task is
    // consumed by exactly one prover node. Wildcard subject allows
    // per-prover filtering via `sincerin.proofs.tasks.<prover_id>`.
    js.get_or_create_stream(Config {
        name: "PROOF_TASKS".to_string(),
        subjects: vec![format!("{}.>", subjects::PROOF_TASKS)],
        retention: RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(3600), // 1 hour TTL
        ..Default::default()
    })
    .await?;
    tracing::info!("stream PROOF_TASKS ready");

    // PROOF_CLIENT: work-queue for client-side proving requests.
    // When privacy requires client-side proving, the dispatcher
    // publishes here instead of routing to a prover node.
    js.get_or_create_stream(Config {
        name: "PROOF_CLIENT".to_string(),
        subjects: vec![subjects::PROOF_CLIENT.to_string()],
        retention: RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(3600), // 1 hour TTL
        ..Default::default()
    })
    .await?;
    tracing::info!("stream PROOF_CLIENT ready");

    Ok(())
}

/// Serialize `payload` to JSON and publish it to the given JetStream subject.
///
/// Awaits the publish acknowledgment from the server to guarantee
/// at-least-once delivery. Returns an error if serialization fails
/// or the server rejects the message (e.g., stream not found).
pub async fn publish<T: Serialize>(
    js: &async_nats::jetstream::Context,
    subject: &str,
    payload: &T,
) -> Result<()> {
    let data = serde_json::to_vec(payload)?;
    js.publish(subject.to_string(), data.into()).await?.await?;
    Ok(())
}

/// Publish a status update for a specific proof request.
///
/// The message is published to `sincerin.proofs.status.<request_id>`,
/// which the PROOF_STATUS stream captures via its `sincerin.proofs.status.*`
/// wildcard subscription. Clients can subscribe to their specific
/// request ID for real-time status updates over WebSocket.
pub async fn publish_status_update(
    js: &async_nats::jetstream::Context,
    request_id: &str,
    status: &crate::types::ProofStatus,
) -> Result<()> {
    let subject = format!("{}.{}", subjects::PROOF_STATUS, request_id);
    publish(js, &subject, status).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subjects_are_consistent() {
        // All subjects must start with "sincerin." to maintain namespace
        // isolation within a shared NATS cluster.
        assert!(
            subjects::PROOF_REQUESTS.starts_with("sincerin."),
            "PROOF_REQUESTS must start with 'sincerin.'"
        );
        assert!(
            subjects::PROOF_RESULTS.starts_with("sincerin."),
            "PROOF_RESULTS must start with 'sincerin.'"
        );
        assert!(
            subjects::PROOF_STATUS.starts_with("sincerin."),
            "PROOF_STATUS must start with 'sincerin.'"
        );
        assert!(
            subjects::PROVER_HEARTBEAT.starts_with("sincerin."),
            "PROVER_HEARTBEAT must start with 'sincerin.'"
        );
        assert!(
            subjects::PROOF_TASKS.starts_with("sincerin."),
            "PROOF_TASKS must start with 'sincerin.'"
        );
        assert!(
            subjects::PROOF_CLIENT.starts_with("sincerin."),
            "PROOF_CLIENT must start with 'sincerin.'"
        );
    }

    /// Integration test: connect to a local NATS server and create streams.
    ///
    /// Requires a running NATS server with JetStream enabled:
    ///   nats-server -js
    ///
    /// Run with: cargo test --package sincerin-common -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_connect_and_setup_streams() {
        let client = connect("nats://localhost:4222")
            .await
            .expect("failed to connect to NATS (is nats-server -js running?)");

        setup_streams(&client)
            .await
            .expect("failed to create JetStream streams");

        // Verify streams exist by fetching them.
        let js = jetstream_context(&client);
        let requests_stream = js.get_stream("PROOF_REQUESTS").await;
        assert!(
            requests_stream.is_ok(),
            "PROOF_REQUESTS stream should exist"
        );

        let results_stream = js.get_stream("PROOF_RESULTS").await;
        assert!(results_stream.is_ok(), "PROOF_RESULTS stream should exist");

        let status_stream = js.get_stream("PROOF_STATUS").await;
        assert!(status_stream.is_ok(), "PROOF_STATUS stream should exist");
    }

    /// Integration test: publish a message and receive it via core NATS subscription.
    ///
    /// Requires a running NATS server with JetStream enabled:
    ///   nats-server -js
    ///
    /// Run with: cargo test --package sincerin-common -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_publish_and_receive() {
        let client = connect("nats://localhost:4222")
            .await
            .expect("failed to connect to NATS");

        setup_streams(&client)
            .await
            .expect("failed to create streams");

        let js = jetstream_context(&client);

        // Publish a test payload.
        #[derive(Serialize, serde::Deserialize, Debug, PartialEq)]
        struct TestPayload {
            id: String,
            value: u64,
        }

        let payload = TestPayload {
            id: "test-001".to_string(),
            value: 42,
        };

        publish(&js, subjects::PROOF_REQUESTS, &payload)
            .await
            .expect("failed to publish message");

        // Verify message landed in the stream by checking stream info.
        let mut stream = js
            .get_stream("PROOF_REQUESTS")
            .await
            .expect("stream should exist");
        let info = stream.info().await.expect("should get stream info");
        assert!(
            info.state.messages >= 1,
            "stream should contain at least 1 message"
        );
    }
}
