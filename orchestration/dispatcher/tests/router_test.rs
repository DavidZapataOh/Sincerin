mod helpers;

use std::time::Duration;

use async_nats::jetstream::consumer::pull::Config as PullConfig;
use futures::StreamExt;

use sincerin_common::types::{PrivacyLevel, PrivacyStrategy, ProofStatus};
use sincerin_dispatcher::router::{ProverTask, Router};

#[tokio::test]
async fn test_route_client_side_publishes_to_client_subject() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;

    // Create a consumer on the client subject to capture routed messages
    let stream = js.get_stream("PROOF_CLIENT").await.unwrap();
    stream
        .get_or_create_consumer(
            "test-client-consumer",
            PullConfig {
                durable_name: Some("test-client-consumer".to_string()),
                filter_subject: "sincerin.proofs.client".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let router = Router::new("prover-test-01".to_string());
    let request = helpers::membership_request("route-client-01", PrivacyLevel::Mandatory);

    // Route with ClientSide strategy
    router
        .route_request(&request, &PrivacyStrategy::ClientSide, &js)
        .await
        .expect("Routing should succeed");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify message arrived on client subject
    let consumer = stream
        .get_consumer::<PullConfig>("test-client-consumer")
        .await
        .unwrap();

    let mut messages = consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages.next().await.expect("Should have a message").unwrap();
    let routed: sincerin_common::types::ProofRequest =
        serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(routed.request_id, "route-client-01");
}

#[tokio::test]
async fn test_route_direct_delegation_publishes_to_prover_tasks() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;

    let prover_id = "prover-test-01";

    // Create a consumer on the tasks subject
    let stream = js.get_stream("PROOF_TASKS").await.unwrap();
    stream
        .get_or_create_consumer(
            "test-tasks-consumer",
            PullConfig {
                durable_name: Some("test-tasks-consumer".to_string()),
                filter_subject: format!("sincerin.proofs.tasks.{prover_id}"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let router = Router::new(prover_id.to_string());
    let request = helpers::membership_request("route-dd-01", PrivacyLevel::None);

    // Route with DirectDelegation strategy
    router
        .route_request(&request, &PrivacyStrategy::DirectDelegation, &js)
        .await
        .expect("Routing should succeed");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify ProverTask arrived on tasks subject
    let consumer = stream
        .get_consumer::<PullConfig>("test-tasks-consumer")
        .await
        .unwrap();

    let mut messages = consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages.next().await.expect("Should have a message").unwrap();
    let task: ProverTask = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(task.request_id, "route-dd-01");
    assert_eq!(task.prover_id, prover_id);
    assert_eq!(task.strategy, PrivacyStrategy::DirectDelegation);
}

#[tokio::test]
async fn test_route_structural_split_publishes_to_prover_tasks() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;

    let prover_id = "prover-test-01";

    let stream = js.get_stream("PROOF_TASKS").await.unwrap();
    stream
        .get_or_create_consumer(
            "test-split-consumer",
            PullConfig {
                durable_name: Some("test-split-consumer".to_string()),
                filter_subject: format!("sincerin.proofs.tasks.{prover_id}"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let router = Router::new(prover_id.to_string());
    let request = helpers::age_request("route-split-01", PrivacyLevel::Mandatory);

    router
        .route_request(&request, &PrivacyStrategy::StructuralSplit, &js)
        .await
        .expect("Routing should succeed");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let consumer = stream
        .get_consumer::<PullConfig>("test-split-consumer")
        .await
        .unwrap();

    let mut messages = consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages.next().await.expect("Should have a message").unwrap();
    let task: ProverTask = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(task.request_id, "route-split-01");
    assert_eq!(task.strategy, PrivacyStrategy::StructuralSplit);
}

#[tokio::test]
async fn test_route_publishes_status_update() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;

    // Create a consumer on the status stream for this specific request
    let stream = js.get_stream("PROOF_STATUS").await.unwrap();
    stream
        .get_or_create_consumer(
            "test-status-consumer",
            PullConfig {
                durable_name: Some("test-status-consumer".to_string()),
                filter_subject: "sincerin.proofs.status.route-status-01".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let router = Router::new("prover-test-01".to_string());
    let request = helpers::membership_request("route-status-01", PrivacyLevel::None);

    // Route DirectDelegation → should publish Assigned status
    router
        .route_request(&request, &PrivacyStrategy::DirectDelegation, &js)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let consumer = stream
        .get_consumer::<PullConfig>("test-status-consumer")
        .await
        .unwrap();

    let mut messages = consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages.next().await.expect("Should have status update").unwrap();
    let status: ProofStatus = serde_json::from_slice(&msg.payload).unwrap();
    assert!(
        matches!(status, ProofStatus::Assigned { .. }),
        "Status should be Assigned, got: {status:?}"
    );
}

#[tokio::test]
async fn test_route_client_side_publishes_client_computing_status() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;

    let stream = js.get_stream("PROOF_STATUS").await.unwrap();
    stream
        .get_or_create_consumer(
            "test-client-status",
            PullConfig {
                durable_name: Some("test-client-status".to_string()),
                filter_subject: "sincerin.proofs.status.route-client-status-01".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let router = Router::new("prover-test-01".to_string());
    let request = helpers::membership_request("route-client-status-01", PrivacyLevel::Mandatory);

    router
        .route_request(&request, &PrivacyStrategy::ClientSide, &js)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let consumer = stream
        .get_consumer::<PullConfig>("test-client-status")
        .await
        .unwrap();

    let mut messages = consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages.next().await.expect("Should have status update").unwrap();
    let status: ProofStatus = serde_json::from_slice(&msg.payload).unwrap();
    assert!(
        matches!(status, ProofStatus::ClientComputing),
        "Status should be ClientComputing, got: {status:?}"
    );
}
