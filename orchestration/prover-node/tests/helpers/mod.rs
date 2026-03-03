#![allow(dead_code)]

use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream::Context as JetStream;
use async_trait::async_trait;
use serde_json::json;
use sincerin_common::nats;

use sincerin_prover_node::backends::{ProofOutput, ProverBackend};
use sincerin_prover_node::config::ProverConfig;
use sincerin_prover_node::consumer::ProverTask;
use sincerin_prover_node::errors::ProverError;

use sincerin_common::types::PrivacyStrategy;

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

const NATS_SERVER_BIN: &str = "/tmp/nats-server-v2.10.27-darwin-arm64/nats-server";

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
    let store_dir = format!("/tmp/nats-test-prover-{port}");
    let process = Command::new(NATS_SERVER_BIN)
        .args(["-js", "-p", &port.to_string(), "--store_dir", &store_dir])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start nats-server. Is it installed at /tmp/?");

    let url = format!("nats://127.0.0.1:{port}");

    // Wait for NATS to be ready
    for i in 0..50 {
        if TcpListener::bind(format!("127.0.0.1:{port}")).is_err()
            && i > 2
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    NatsServerHandle {
        url,
        port,
        process,
        store_dir,
    }
}

/// Connect to NATS and set up all required streams.
pub async fn setup_test_nats(nats_handle: &NatsServerHandle) -> (async_nats::Client, JetStream) {
    let client = nats::connect(&nats_handle.url)
        .await
        .expect("Failed to connect to test NATS");

    nats::setup_streams(&client)
        .await
        .expect("Failed to setup streams");

    let js = nats::jetstream_context(&client);
    (client, js)
}

/// Create a ProverConfig suitable for tests.
pub fn create_test_config(nats_url: &str) -> ProverConfig {
    ProverConfig {
        prover_id: "prover-test-01".to_string(),
        nats_url: nats_url.to_string(),
        bb_binary_path: "/tmp/bb".into(),
        circuits_dir: "./circuits".into(),
        work_dir: "/tmp/sincerin-prover-test".into(),
        max_concurrent_proofs: 1,
        heartbeat_interval_secs: 1, // Fast heartbeats for testing
        metrics_port: find_free_port(),
    }
}

/// Build a ProverTask with configurable fields.
pub fn make_prover_task(
    request_id: &str,
    circuit_id: &str,
    strategy: PrivacyStrategy,
    witness: Option<Vec<u8>>,
) -> ProverTask {
    ProverTask {
        request_id: request_id.to_string(),
        circuit_id: circuit_id.to_string(),
        strategy,
        split_data: None,
        public_inputs: json!({"root": "0x1234", "nullifier": "0x5678"}),
        witness,
        client_proof: None,
        deadline: chrono::Utc::now().timestamp() as u64 + 3600,
        assigned_at: chrono::Utc::now().to_rfc3339(),
        prover_id: "prover-test-01".to_string(),
    }
}

/// Mock prover backend that returns configurable results.
pub struct MockProverBackend {
    pub prove_output: ProofOutput,
    pub prove_delay_ms: u64,
    pub should_fail: bool,
}

impl MockProverBackend {
    pub fn success(proof: Vec<u8>, proving_time_ms: u64) -> Self {
        Self {
            prove_output: ProofOutput {
                proof,
                proving_time_ms,
            },
            prove_delay_ms: 0,
            should_fail: false,
        }
    }

    pub fn failure() -> Self {
        Self {
            prove_output: ProofOutput {
                proof: vec![],
                proving_time_ms: 0,
            },
            prove_delay_ms: 0,
            should_fail: true,
        }
    }

    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.prove_delay_ms = delay_ms;
        self
    }
}

#[async_trait]
impl ProverBackend for MockProverBackend {
    async fn prove(&self, _circuit_id: &str, _witness: &[u8]) -> Result<ProofOutput, ProverError> {
        if self.prove_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.prove_delay_ms)).await;
        }

        if self.should_fail {
            return Err(ProverError::ProveFailed("mock failure".to_string()));
        }

        Ok(self.prove_output.clone())
    }

    async fn verify(&self, _circuit_id: &str, _proof: &[u8]) -> Result<bool, ProverError> {
        Ok(!self.should_fail)
    }
}

/// Helper to create an Arc'd mock backend.
pub fn mock_backend_success() -> Arc<dyn ProverBackend> {
    Arc::new(MockProverBackend::success(
        vec![0xde, 0xad, 0xbe, 0xef],
        1500,
    ))
}

pub fn mock_backend_failure() -> Arc<dyn ProverBackend> {
    Arc::new(MockProverBackend::failure())
}
