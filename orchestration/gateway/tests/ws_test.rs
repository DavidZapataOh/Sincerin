mod helpers;

use futures::SinkExt;
use futures::stream::StreamExt;
use std::time::Duration;
use tokio::net::TcpListener;
use tower::ServiceExt;

type WsMessage = tokio_tungstenite::tungstenite::Message;

/// Helper: start the gateway on a real TCP port and return the base URL.
async fn start_server(nats_url: &str) -> (String, tokio::task::JoinHandle<()>) {
    let config = helpers::create_test_config(nats_url);
    let port = config.port;
    let app = helpers::create_test_app_with_config(config).await;

    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    (format!("127.0.0.1:{port}"), handle)
}

/// Read the next Text message from the WS stream, skipping Ping/Pong/Binary frames.
async fn read_next_text<S>(read: &mut S) -> serde_json::Value
where
    S: futures::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), read.next())
            .await
            .expect("Timeout waiting for WS message")
            .expect("WS stream ended")
            .expect("WS read error");

        match msg {
            WsMessage::Text(text) => {
                return serde_json::from_str(&text).expect("Invalid JSON in WS message");
            }
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            other => panic!("Unexpected WS message type: {other:?}"),
        }
    }
}

fn text_msg(s: &str) -> WsMessage {
    WsMessage::Text(s.into())
}

/// WebSocket connection with valid API key succeeds.
#[tokio::test]
async fn test_ws_connect() {
    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    let url = format!("ws://{addr}/v1/ws?api_key={}", helpers::TEST_API_KEY);
    let result = tokio_tungstenite::connect_async(&url).await;

    assert!(result.is_ok(), "WebSocket connection should succeed");
}

/// WebSocket connection without API key fails (HTTP 401 before upgrade).
#[tokio::test]
async fn test_ws_no_auth() {
    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    let url = format!("ws://{addr}/v1/ws");
    let result = tokio_tungstenite::connect_async(&url).await;

    // Should fail — server returns 401 before WebSocket upgrade
    assert!(result.is_err(), "WebSocket without auth should fail");
}

/// Subscribe to a request_id via WebSocket message.
#[tokio::test]
async fn test_ws_subscribe() {
    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    let url = format!("ws://{addr}/v1/ws?api_key={}", helpers::TEST_API_KEY);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect");

    let (mut write, mut read) = ws_stream.split();

    let fake_id = format!("0x{}", "a".repeat(64));
    let sub_msg = serde_json::json!({"action": "subscribe", "request_id": fake_id});
    write.send(text_msg(&sub_msg.to_string())).await.unwrap();

    let json = read_next_text(&mut read).await;
    assert_eq!(json["type"], "subscribed");
    assert_eq!(json["request_id"], fake_id);
}

/// Unsubscribe from a request_id.
#[tokio::test]
async fn test_ws_unsubscribe() {
    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    let url = format!("ws://{addr}/v1/ws?api_key={}", helpers::TEST_API_KEY);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect");

    let (mut write, mut read) = ws_stream.split();

    let fake_id = format!("0x{}", "b".repeat(64));

    // Subscribe
    let sub_msg = serde_json::json!({"action": "subscribe", "request_id": fake_id});
    write.send(text_msg(&sub_msg.to_string())).await.unwrap();

    // Read subscribe ack
    let json = read_next_text(&mut read).await;
    assert_eq!(json["type"], "subscribed");

    // Unsubscribe
    let unsub_msg = serde_json::json!({"action": "unsubscribe", "request_id": fake_id});
    write.send(text_msg(&unsub_msg.to_string())).await.unwrap();

    // Read unsubscribe ack
    let json = read_next_text(&mut read).await;
    assert_eq!(json["type"], "unsubscribed");
    assert_eq!(json["request_id"], fake_id);
}

/// Invalid JSON sent to WebSocket returns error (not close).
#[tokio::test]
async fn test_ws_invalid_json() {
    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    let url = format!("ws://{addr}/v1/ws?api_key={}", helpers::TEST_API_KEY);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect");

    let (mut write, mut read) = ws_stream.split();

    write.send(text_msg("not valid json!!!")).await.unwrap();

    let json = read_next_text(&mut read).await;
    assert_eq!(json["type"], "error");
    assert_eq!(json["message"], "invalid_json");
}

/// Subscribe with invalid request_id format returns error.
#[tokio::test]
async fn test_ws_invalid_request_id() {
    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    let url = format!("ws://{addr}/v1/ws?api_key={}", helpers::TEST_API_KEY);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect");

    let (mut write, mut read) = ws_stream.split();

    let msg = serde_json::json!({"action": "subscribe", "request_id": "invalid"});
    write.send(text_msg(&msg.to_string())).await.unwrap();

    let json = read_next_text(&mut read).await;
    assert_eq!(json["type"], "error");
    assert_eq!(json["message"], "invalid_request_id");
}

/// Full flow: prove → subscribe via WebSocket → receive status update from NATS.
#[tokio::test]
async fn test_full_flow_prove_and_ws() {
    use sincerin_common::nats as nats_helpers;
    use sincerin_common::types::ProofStatus;

    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    // 1. Submit a proof request via HTTP
    let config = helpers::create_test_config(&nats.url);
    let app = helpers::create_test_app_with_config(config).await;
    let body = helpers::valid_prove_body();
    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 202);

    let prove_body = helpers::body_json(resp).await;
    let request_id = prove_body["request_id"].as_str().unwrap().to_string();

    // 2. Connect WebSocket and subscribe to the request_id
    let url = format!("ws://{addr}/v1/ws?api_key={}", helpers::TEST_API_KEY);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WS");

    let (mut write, mut read) = ws_stream.split();

    let sub_msg = serde_json::json!({"action": "subscribe", "request_id": request_id});
    write.send(text_msg(&sub_msg.to_string())).await.unwrap();

    // Read subscribe ack
    let json = read_next_text(&mut read).await;
    assert_eq!(json["type"], "subscribed");

    // Wait for NATS push consumer to be fully established.
    // The consumer is created asynchronously in a spawned task.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 3. Publish a status update to NATS (simulating prover)
    let client = nats_helpers::connect(&nats.url).await.unwrap();
    let js = nats_helpers::jetstream_context(&client);

    let proving_status = ProofStatus::Proving {
        progress: Some(0.5),
    };
    nats_helpers::publish_status_update(&js, &request_id, &proving_status)
        .await
        .unwrap();

    // 4. WebSocket should receive the status update (longer timeout for NATS propagation)
    let msg = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let json = read_next_text(&mut read).await;
            if json["type"] == "status_update" {
                return json;
            }
            // Skip any other messages (e.g., late subscription acks)
        }
    })
    .await
    .expect("Timeout waiting for status_update on WebSocket");

    assert_eq!(msg["type"], "status_update");
    assert_eq!(msg["request_id"], request_id);
    assert!(msg["data"].is_object());
    assert!(msg["timestamp"].is_string());
}

/// Unknown action returns error.
#[tokio::test]
async fn test_ws_unknown_action() {
    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    let url = format!("ws://{addr}/v1/ws?api_key={}", helpers::TEST_API_KEY);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect");

    let (mut write, mut read) = ws_stream.split();

    let msg = serde_json::json!({"action": "do_something_weird"});
    write.send(text_msg(&msg.to_string())).await.unwrap();

    let json = read_next_text(&mut read).await;
    assert_eq!(json["type"], "error");
    assert_eq!(json["message"], "unknown_action");
}

/// Initial request_ids via query param get auto-subscribed.
#[tokio::test]
async fn test_ws_initial_subscriptions() {
    let nats = helpers::start_nats_server().await;
    let (addr, _handle) = start_server(&nats.url).await;

    let id1 = format!("0x{}", "a".repeat(64));
    let id2 = format!("0x{}", "b".repeat(64));
    let url = format!(
        "ws://{addr}/v1/ws?api_key={}&request_ids={id1},{id2}",
        helpers::TEST_API_KEY
    );

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect");

    let (_write, mut read) = ws_stream.split();

    // Should receive 2 subscription acks
    let mut ack_ids = Vec::new();
    for _ in 0..2 {
        let json = read_next_text(&mut read).await;
        assert_eq!(json["type"], "subscribed");
        ack_ids.push(json["request_id"].as_str().unwrap().to_string());
    }

    assert!(ack_ids.contains(&id1));
    assert!(ack_ids.contains(&id2));
}
