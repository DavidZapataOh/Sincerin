#![allow(dead_code)]

use std::collections::HashSet;
use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

use axum::Router;
use sincerin_common::nats;
use sincerin_gateway::config::GatewayConfig;
use sincerin_gateway::routes;
use sincerin_gateway::state::AppState;

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

/// The default test API key.
pub const TEST_API_KEY: &str = "test-key-001";

/// A second test API key for per-key isolation tests.
pub const TEST_API_KEY_B: &str = "test-key-002";

/// Path to the nats-server binary (downloaded during setup).
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

/// Create a GatewayConfig suitable for tests.
pub fn create_test_config(nats_url: &str) -> GatewayConfig {
    let mut api_keys = HashSet::new();
    api_keys.insert(TEST_API_KEY.to_string());
    api_keys.insert(TEST_API_KEY_B.to_string());

    GatewayConfig {
        host: "127.0.0.1".to_string(),
        port: find_free_port(),
        nats_url: nats_url.to_string(),
        metrics_port: find_free_port(),
        api_keys,
        rate_limit_rps: 100,
    }
}

/// Build a complete test app (Router) connected to a real NATS server.
pub async fn create_test_app(nats_handle: &NatsServerHandle) -> Router {
    let config = create_test_config(&nats_handle.url);
    create_test_app_with_config(config).await
}

/// Build a test app with a custom config.
pub async fn create_test_app_with_config(config: GatewayConfig) -> Router {
    let client = nats::connect(&config.nats_url)
        .await
        .expect("Failed to connect to test NATS");

    nats::setup_streams(&client)
        .await
        .expect("Failed to setup test streams");

    let js = nats::jetstream_context(&client);
    let state = AppState::new(js, config);

    routes::build_router(state)
}

/// Helper: build an HTTP request with the test API key header.
pub fn request_with_key(method: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", TEST_API_KEY)
        .header("content-type", "application/json")
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Helper: build a JSON POST request with the test API key.
pub fn post_json_with_key(uri: &str, body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("x-api-key", TEST_API_KEY)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// Helper: build a request without any API key.
pub fn request_no_key(method: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Helper: build a request with a specific API key.
pub fn request_with_specific_key(
    method: &str,
    uri: &str,
    api_key: &str,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", api_key)
        .header("content-type", "application/json")
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Helper: extract response body as JSON.
pub async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// A valid proof request body for POST /v1/prove tests.
pub fn valid_prove_body() -> serde_json::Value {
    let deadline = chrono::Utc::now().timestamp() as u64 + 3600; // 1 hour from now
    serde_json::json!({
        "circuit_id": "proof-of-membership",
        "public_inputs": {"root": "0x1234"},
        "private_inputs_hash": "0xabcdef",
        "privacy": "none",
        "priority": "standard",
        "deadline": deadline
    })
}
