#![allow(dead_code)]

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

use async_nats::jetstream::stream::{Config, RetentionPolicy};
use async_nats::jetstream::Context as JetStream;
use sincerin_common::nats;
use sincerin_common::types::{Priority, PrivacyLevel, ProofRequest, ProofStatus};

use sincerin_dispatcher::config::DispatcherConfig;

/// NATS server handle — kills the process on drop.
pub struct NatsServerHandle {
    pub url: String,
    pub port: u16,
    process: Child,
    store_dir: String,
}

impl Drop for NatsServerHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.store_dir);
    }
}

/// Path to the nats-server binary.
const NATS_SERVER_BIN: &str = "/tmp/nats-server-v2.10.27-darwin-arm64/nats-server";

/// Find an available TCP port.
fn find_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to random port")
        .local_addr()
        .expect("Failed to get local addr")
        .port()
}

/// Start a NATS server with JetStream enabled on a random port.
pub async fn start_nats_server() -> NatsServerHandle {
    let port = find_free_port();
    let store_dir = format!("/tmp/nats-test-{port}");
    let process = Command::new(NATS_SERVER_BIN)
        .args(["-js", "-p", &port.to_string(), "--store_dir", &store_dir])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start nats-server. Is it installed at /tmp/?");

    let url = format!("nats://127.0.0.1:{port}");

    // Wait for NATS to be ready (max 5 seconds)
    for i in 0..50 {
        if TcpListener::bind(format!("127.0.0.1:{port}")).is_err() {
            // Port is in use = NATS is listening
            if i > 2 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Extra grace time for JetStream init
    tokio::time::sleep(Duration::from_millis(200)).await;

    NatsServerHandle {
        url,
        port,
        process,
        store_dir,
    }
}

/// Connect to NATS and set up all required streams (core + dispatcher-specific).
pub async fn setup_test_nats(nats_handle: &NatsServerHandle) -> (async_nats::Client, JetStream) {
    let client = nats::connect(&nats_handle.url)
        .await
        .expect("Failed to connect to test NATS");

    // Set up core streams (PROOF_REQUESTS, PROOF_RESULTS, PROOF_STATUS)
    nats::setup_streams(&client)
        .await
        .expect("Failed to setup core streams");

    let js = nats::jetstream_context(&client);

    // Set up dispatcher-specific streams for router output subjects.
    // These capture messages the router publishes so tests can verify them.
    js.get_or_create_stream(Config {
        name: "PROOF_TASKS".to_string(),
        subjects: vec!["sincerin.proofs.tasks.>".to_string()],
        retention: RetentionPolicy::Limits,
        max_age: Duration::from_secs(3600),
        ..Default::default()
    })
    .await
    .expect("Failed to create PROOF_TASKS stream");

    js.get_or_create_stream(Config {
        name: "PROOF_CLIENT".to_string(),
        subjects: vec!["sincerin.proofs.client".to_string()],
        retention: RetentionPolicy::Limits,
        max_age: Duration::from_secs(3600),
        ..Default::default()
    })
    .await
    .expect("Failed to create PROOF_CLIENT stream");

    (client, js)
}

/// Create a DispatcherConfig suitable for tests.
pub fn create_test_config(nats_url: &str) -> DispatcherConfig {
    DispatcherConfig {
        nats_url: nats_url.to_string(),
        consumer_name: format!("test-dispatcher-{}", find_free_port()),
        batch_size: 10,
        batch_wait_ms: 500,
        max_retries: 3,
        metrics_port: find_free_port(),
        default_prover_id: "prover-test-01".to_string(),
        queue_max_size: 1000,
    }
}

/// Build a valid ProofRequest with configurable fields.
pub fn make_request(
    id: &str,
    circuit_id: &str,
    privacy_level: PrivacyLevel,
    deadline: u64,
) -> ProofRequest {
    ProofRequest {
        request_id: id.to_string(),
        circuit_id: circuit_id.to_string(),
        requester: "test-user".to_string(),
        privacy_level,
        priority: Priority::Standard,
        max_fee: 100,
        deadline,
        public_inputs: serde_json::json!({"root": "0x1234", "nullifier": "0x5678"}),
        created_at: chrono::Utc::now().timestamp() as u64,
        status: ProofStatus::Pending,
    }
}

/// Build a ProofRequest for proof-of-membership with sane defaults.
pub fn membership_request(id: &str, privacy: PrivacyLevel) -> ProofRequest {
    let deadline = chrono::Utc::now().timestamp() as u64 + 3600;
    make_request(id, "proof-of-membership", privacy, deadline)
}

/// Build a ProofRequest for proof-of-age with sane defaults.
pub fn age_request(id: &str, privacy: PrivacyLevel) -> ProofRequest {
    let deadline = chrono::Utc::now().timestamp() as u64 + 3600;
    make_request(id, "proof-of-age", privacy, deadline)
}
