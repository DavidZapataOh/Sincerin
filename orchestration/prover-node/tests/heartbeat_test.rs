mod helpers;

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use sincerin_common::nats;
use sincerin_prover_node::heartbeat::{
    HeartbeatMessage, HeartbeatService, ProverNodeStatus, SharedState,
};

#[tokio::test]
async fn test_heartbeat_publishes_periodically() {
    let nats_handle = helpers::start_nats_server().await;
    let (client, js) = helpers::setup_test_nats(&nats_handle).await;

    // Subscribe to heartbeat subject via core NATS
    let mut subscriber = client
        .subscribe(nats::subjects::PROVER_HEARTBEAT.to_string())
        .await
        .unwrap();

    let shared_state = Arc::new(SharedState::new());
    let heartbeat = HeartbeatService::new(
        js.clone(),
        "prover-heartbeat-test".to_string(),
        Duration::from_millis(200), // Fast interval for testing
        shared_state,
        1,
    );

    let cancel = CancellationToken::new();
    let heartbeat_cancel = cancel.clone();
    tokio::spawn(async move {
        heartbeat.run(heartbeat_cancel).await;
    });

    // Collect heartbeats for ~1 second (should get at least 3)
    let mut count = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1000);

    loop {
        tokio::select! {
            Some(msg) = subscriber.next() => {
                let hb: HeartbeatMessage = serde_json::from_slice(&msg.payload).unwrap();
                assert_eq!(hb.prover_id, "prover-heartbeat-test");
                count += 1;
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }

    cancel.cancel();
    assert!(
        count >= 3,
        "Should have received at least 3 heartbeats in 1s (200ms interval), got {count}"
    );
}

#[tokio::test]
async fn test_heartbeat_reflects_idle_status() {
    let nats_handle = helpers::start_nats_server().await;
    let (client, js) = helpers::setup_test_nats(&nats_handle).await;

    let mut subscriber = client
        .subscribe(nats::subjects::PROVER_HEARTBEAT.to_string())
        .await
        .unwrap();

    let shared_state = Arc::new(SharedState::new());
    // Ensure state is idle
    assert_eq!(shared_state.get_status(), ProverNodeStatus::Idle);

    let heartbeat = HeartbeatService::new(
        js.clone(),
        "idle-test".to_string(),
        Duration::from_millis(100),
        shared_state,
        1,
    );

    let cancel = CancellationToken::new();
    let heartbeat_cancel = cancel.clone();
    tokio::spawn(async move {
        heartbeat.run(heartbeat_cancel).await;
    });

    // Wait for first heartbeat
    let msg = tokio::time::timeout(Duration::from_secs(2), subscriber.next())
        .await
        .expect("Timeout waiting for heartbeat")
        .expect("No heartbeat received");

    cancel.cancel();

    let hb: HeartbeatMessage = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(hb.status, ProverNodeStatus::Idle);
    assert_eq!(hb.current_load, 0.0);
    assert_eq!(hb.active_proofs, 0);
}

#[tokio::test]
async fn test_heartbeat_reflects_proving_status() {
    let nats_handle = helpers::start_nats_server().await;
    let (client, js) = helpers::setup_test_nats(&nats_handle).await;

    let mut subscriber = client
        .subscribe(nats::subjects::PROVER_HEARTBEAT.to_string())
        .await
        .unwrap();

    let shared_state = Arc::new(SharedState::new());
    // Simulate proving state
    shared_state.increment_active();

    let heartbeat = HeartbeatService::new(
        js.clone(),
        "proving-test".to_string(),
        Duration::from_millis(100),
        shared_state,
        1,
    );

    let cancel = CancellationToken::new();
    let heartbeat_cancel = cancel.clone();
    tokio::spawn(async move {
        heartbeat.run(heartbeat_cancel).await;
    });

    let msg = tokio::time::timeout(Duration::from_secs(2), subscriber.next())
        .await
        .expect("Timeout waiting for heartbeat")
        .expect("No heartbeat received");

    cancel.cancel();

    let hb: HeartbeatMessage = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(hb.status, ProverNodeStatus::Proving);
    assert_eq!(hb.current_load, 1.0);
    assert_eq!(hb.active_proofs, 1);
}

#[tokio::test]
async fn test_heartbeat_stops_on_cancel() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;

    let shared_state = Arc::new(SharedState::new());
    let heartbeat = HeartbeatService::new(
        js.clone(),
        "cancel-test".to_string(),
        Duration::from_millis(100),
        shared_state,
        1,
    );

    let cancel = CancellationToken::new();
    let heartbeat_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        heartbeat.run(heartbeat_cancel).await;
    });

    // Let it run briefly
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Cancel
    cancel.cancel();

    // Should finish within 1 second
    let result = tokio::time::timeout(Duration::from_secs(1), handle).await;
    assert!(result.is_ok(), "Heartbeat should stop promptly on cancel");
}

#[tokio::test]
async fn test_heartbeat_message_format() {
    let nats_handle = helpers::start_nats_server().await;
    let (client, js) = helpers::setup_test_nats(&nats_handle).await;

    let mut subscriber = client
        .subscribe(nats::subjects::PROVER_HEARTBEAT.to_string())
        .await
        .unwrap();

    let shared_state = Arc::new(SharedState::new());
    let heartbeat = HeartbeatService::new(
        js.clone(),
        "format-test".to_string(),
        Duration::from_millis(100),
        shared_state,
        2, // max_concurrent = 2
    );

    let cancel = CancellationToken::new();
    let heartbeat_cancel = cancel.clone();
    tokio::spawn(async move {
        heartbeat.run(heartbeat_cancel).await;
    });

    let msg = tokio::time::timeout(Duration::from_secs(2), subscriber.next())
        .await
        .expect("Timeout")
        .expect("No message");

    cancel.cancel();

    let hb: HeartbeatMessage = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(hb.prover_id, "format-test");
    assert_eq!(hb.max_concurrent, 2);
    assert!(hb.uptime_secs < 60); // Just started
    assert!(hb.hardware.cpu_cores > 0);
    assert!(!hb.timestamp.is_empty());
}
