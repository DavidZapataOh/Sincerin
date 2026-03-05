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
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde::de::DeserializeOwned;

use crate::{nats_consumers, nats_streams};

/// NATS subject constants for the Sincerin orchestration layer.
///
/// All subjects are prefixed with `sincerin.` to namespace them within
/// a shared NATS cluster. Status subjects use a wildcard segment for
/// the request ID, enabling per-request subscriptions.
pub mod subjects {
    // --- Proof pipeline ---

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

    /// Subject for verified proofs (post-L1 verification).
    /// Published by the collector after on-chain verification succeeds.
    /// Consumed by the gateway and external subscribers.
    pub const PROOF_VERIFIED: &str = "sincerin.proofs.verified";

    // --- Prover management ---

    /// Subject for prover node heartbeats.
    /// Used by the dispatcher for liveness tracking and load balancing.
    pub const PROVER_HEARTBEAT: &str = "sincerin.provers.heartbeat";

    /// Subject for prover registration announcements.
    pub const PROVER_REGISTER: &str = "sincerin.provers.register";

    /// Subject for prover deregistration announcements.
    pub const PROVER_DEREGISTER: &str = "sincerin.provers.deregister";

    // --- System ---

    /// Subject for system-wide metrics events.
    pub const SYSTEM_METRICS: &str = "sincerin.system.metrics";

    /// Subject for system alert events.
    pub const SYSTEM_ALERTS: &str = "sincerin.system.alerts";

    /// Build task subject for a specific prover.
    ///
    /// # Example
    /// ```
    /// # use sincerin_common::nats::subjects;
    /// assert_eq!(subjects::proof_tasks("prover-01"), "sincerin.proofs.tasks.prover-01");
    /// ```
    pub fn proof_tasks(prover_id: &str) -> String {
        format!("{PROOF_TASKS}.{prover_id}")
    }

    /// Build status subject for a specific request.
    ///
    /// # Example
    /// ```
    /// # use sincerin_common::nats::subjects;
    /// assert_eq!(subjects::proof_status("0xabc"), "sincerin.proofs.status.0xabc");
    /// ```
    pub fn proof_status(request_id: &str) -> String {
        format!("{PROOF_STATUS}.{request_id}")
    }
}

// ---------------------------------------------------------------------------
// NatsConfig — connection options for NATS JetStream
// ---------------------------------------------------------------------------

/// Configuration for connecting to a NATS server.
///
/// Provides sensible defaults for local development. Production
/// deployments should override `url` and `replicas` at minimum.
#[derive(Clone, Debug, Deserialize)]
pub struct NatsConfig {
    /// NATS server URL (e.g. `nats://localhost:4222`).
    pub url: String,
    /// Connection timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Delay between reconnection attempts in milliseconds.
    pub reconnect_delay_ms: u64,
    /// Maximum number of reconnection attempts before giving up.
    pub max_reconnects: usize,
    /// Stream replication factor: 1 for dev, 3 for production.
    pub replicas: usize,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: "nats://localhost:4222".to_string(),
            connect_timeout_ms: 5000,
            reconnect_delay_ms: 1000,
            max_reconnects: 60,
            replicas: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// High-level connection helper
// ---------------------------------------------------------------------------

/// Connect to NATS, create all streams and durable consumers, and return
/// both the raw client and a JetStream context ready for publishing.
///
/// This is the recommended entry point for services. It:
/// 1. Connects to the NATS server with timeout/reconnect options
/// 2. Creates all 8 JetStream streams (idempotent)
/// 3. Creates durable pull consumers (dispatcher, collector-results,
///    collector-client)
///
/// Prover consumers are created dynamically when a prover registers.
/// Gateway push consumers are created at runtime by the gateway service.
pub async fn connect_jetstream(
    config: &NatsConfig,
) -> Result<(async_nats::Client, async_nats::jetstream::Context)> {
    let options = async_nats::ConnectOptions::new()
        .connection_timeout(Duration::from_millis(config.connect_timeout_ms))
        .retry_on_initial_connect();

    tracing::info!(url = %config.url, "connecting to NATS server");
    let client = options.connect(&config.url).await?;
    tracing::info!(url = %config.url, "connected to NATS server");

    let js = async_nats::jetstream::new(client.clone());

    // Ensure streams exist (idempotent).
    setup_streams_with_replicas(&js, config.replicas).await?;

    // Ensure durable pull consumers exist (idempotent).
    ensure_consumers(&js).await?;

    tracing::info!("NATS JetStream streams and consumers ready");

    Ok((client, js))
}

// ---------------------------------------------------------------------------
// Legacy connection helpers (kept for backward compatibility)
// ---------------------------------------------------------------------------

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

/// Create (or verify existence of) all JetStream streams required by
/// the Sincerin orchestration layer.
///
/// Uses `get_or_create_stream` so the function is idempotent -- safe
/// to call on every service startup without coordination.
///
/// Uses replicas=1 (dev default). For production, use
/// [`connect_jetstream`] with a [`NatsConfig`] that sets `replicas: 3`.
pub async fn setup_streams(client: &async_nats::Client) -> Result<()> {
    let js = async_nats::jetstream::new(client.clone());
    setup_streams_with_replicas(&js, 1).await
}

/// Internal: create all streams with a configurable replica count.
///
/// Stream configurations come from [`nats_streams`] factory functions,
/// ensuring a single source of truth for retention policies, TTLs,
/// and subject patterns.
async fn setup_streams_with_replicas(
    js: &async_nats::jetstream::Context,
    replicas: usize,
) -> Result<()> {
    let stream_configs = [
        nats_streams::proof_requests_config(replicas),
        nats_streams::proof_results_config(replicas),
        nats_streams::proof_status_config(replicas),
        nats_streams::proof_tasks_config(replicas),
        nats_streams::proof_client_config(replicas),
        nats_streams::proof_verified_config(replicas),
        nats_streams::provers_config(replicas),
        nats_streams::system_config(replicas),
    ];

    for config in stream_configs {
        let name = config.name.clone();
        js.get_or_create_stream(config).await?;
        tracing::info!(stream = %name, "stream ready");
    }

    Ok(())
}

/// Create (or verify existence of) durable pull consumers for the
/// core services: dispatcher, collector-results, and collector-client.
///
/// Prover consumers (`prover-{id}`) are created dynamically when a
/// prover registers. Gateway push consumers are created at runtime.
pub async fn ensure_consumers(js: &async_nats::jetstream::Context) -> Result<()> {
    // Dispatcher: consumes proof requests from PROOF_REQUESTS stream.
    let requests_stream = js.get_stream("PROOF_REQUESTS").await?;
    requests_stream
        .get_or_create_consumer("dispatcher", nats_consumers::dispatcher_config())
        .await?;
    tracing::info!("consumer dispatcher ready");

    // Collector results: consumes completed proofs from PROOF_RESULTS.
    let results_stream = js.get_stream("PROOF_RESULTS").await?;
    results_stream
        .get_or_create_consumer("collector-results", nats_consumers::collector_results_config())
        .await?;
    tracing::info!("consumer collector-results ready");

    // Collector client: consumes client-side proofs from PROOF_CLIENT.
    let client_stream = js.get_stream("PROOF_CLIENT").await?;
    client_stream
        .get_or_create_consumer("collector-client", nats_consumers::collector_client_config())
        .await?;
    tracing::info!("consumer collector-client ready");

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
        let all_subjects = [
            subjects::PROOF_REQUESTS,
            subjects::PROOF_RESULTS,
            subjects::PROOF_STATUS,
            subjects::PROOF_TASKS,
            subjects::PROOF_CLIENT,
            subjects::PROOF_VERIFIED,
            subjects::PROVER_HEARTBEAT,
            subjects::PROVER_REGISTER,
            subjects::PROVER_DEREGISTER,
            subjects::SYSTEM_METRICS,
            subjects::SYSTEM_ALERTS,
        ];

        for subject in &all_subjects {
            assert!(
                subject.starts_with("sincerin."),
                "Subject '{subject}' must start with 'sincerin.'"
            );
        }

        // Verify uniqueness.
        let mut unique = std::collections::HashSet::new();
        for subject in &all_subjects {
            assert!(
                unique.insert(*subject),
                "Duplicate subject found: '{subject}'"
            );
        }
    }

    #[test]
    fn test_subject_proof_tasks() {
        assert_eq!(
            subjects::proof_tasks("prover-01"),
            "sincerin.proofs.tasks.prover-01"
        );
    }

    #[test]
    fn test_subject_proof_status() {
        assert_eq!(
            subjects::proof_status("0xabc123"),
            "sincerin.proofs.status.0xabc123"
        );
    }

    #[test]
    fn test_nats_config_default() {
        let config = NatsConfig::default();
        assert_eq!(config.url, "nats://localhost:4222");
        assert_eq!(config.connect_timeout_ms, 5000);
        assert_eq!(config.reconnect_delay_ms, 1000);
        assert_eq!(config.max_reconnects, 60);
        assert_eq!(config.replicas, 1);
    }

    #[test]
    fn test_nats_config_deserialize() {
        let json = r#"{
            "url": "nats://prod:4222",
            "connect_timeout_ms": 10000,
            "reconnect_delay_ms": 2000,
            "max_reconnects": 120,
            "replicas": 3
        }"#;
        let config: NatsConfig = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(config.url, "nats://prod:4222");
        assert_eq!(config.replicas, 3);
        assert_eq!(config.connect_timeout_ms, 10000);
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

    /// Integration test: connect_jetstream creates streams and consumers.
    ///
    /// Requires a running NATS server with JetStream enabled:
    ///   nats-server -js
    ///
    /// Run with: cargo test --package sincerin-common -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_connect_jetstream() {
        let config = NatsConfig::default();
        let (_client, js) = connect_jetstream(&config)
            .await
            .expect("failed to connect via connect_jetstream");

        // Verify all 8 streams exist.
        for name in [
            "PROOF_REQUESTS",
            "PROOF_RESULTS",
            "PROOF_STATUS",
            "PROOF_TASKS",
            "PROOF_CLIENT",
            "PROOF_VERIFIED",
            "PROVERS",
            "SYSTEM",
        ] {
            assert!(
                js.get_stream(name).await.is_ok(),
                "stream {name} should exist"
            );
        }

        // Verify durable consumers exist.
        let req_stream = js.get_stream("PROOF_REQUESTS").await.unwrap();
        assert!(
            req_stream.get_consumer::<async_nats::jetstream::consumer::pull::Config>("dispatcher").await.is_ok(),
            "dispatcher consumer should exist"
        );

        let res_stream = js.get_stream("PROOF_RESULTS").await.unwrap();
        assert!(
            res_stream.get_consumer::<async_nats::jetstream::consumer::pull::Config>("collector-results").await.is_ok(),
            "collector-results consumer should exist"
        );

        let client_stream = js.get_stream("PROOF_CLIENT").await.unwrap();
        assert!(
            client_stream.get_consumer::<async_nats::jetstream::consumer::pull::Config>("collector-client").await.is_ok(),
            "collector-client consumer should exist"
        );
    }

    /// Integration test: connect_jetstream is idempotent.
    ///
    /// Requires a running NATS server with JetStream enabled.
    /// Run with: cargo test --package sincerin-common -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_connect_jetstream_idempotent() {
        let config = NatsConfig::default();

        // Call twice — second call should not error.
        let _ = connect_jetstream(&config).await.expect("first connect");
        let _ = connect_jetstream(&config).await.expect("second connect should not error");
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
