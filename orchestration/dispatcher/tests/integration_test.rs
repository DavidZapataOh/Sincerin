mod helpers;

use std::time::Duration;

use async_nats::jetstream::consumer::pull::Config as PullConfig;
use futures::StreamExt;

use sincerin_common::nats;
use sincerin_common::types::{PrivacyLevel, PrivacyStrategy};
use sincerin_dispatcher::consumer::RequestConsumer;
use sincerin_dispatcher::router::{ProverTask, Router};
use sincerin_dispatcher::strategy::{CircuitRegistry, StrategySelector};

/// Full E2E test: publish ProofRequest → consumer fetches → strategy selects
/// → router routes → verify ProverTask appears on the correct NATS subject.
#[tokio::test]
async fn test_e2e_direct_delegation_flow() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);
    let prover_id = &config.default_prover_id.clone();

    // Set up a consumer on the tasks subject to verify output
    let tasks_stream = js.get_stream("PROOF_TASKS").await.unwrap();
    tasks_stream
        .get_or_create_consumer(
            "e2e-tasks",
            PullConfig {
                durable_name: Some("e2e-tasks".to_string()),
                filter_subject: format!("sincerin.proofs.tasks.{prover_id}"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // 1. Publish a proof request (PrivacyLevel::None → DirectDelegation)
    let request = helpers::membership_request("e2e-dd-001", PrivacyLevel::None);
    nats::publish(&js, nats::subjects::PROOF_REQUESTS, &request)
        .await
        .expect("Failed to publish proof request");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Consumer fetches the request
    let consumer = RequestConsumer::new(js.clone(), config.clone())
        .await
        .expect("Failed to create consumer");

    let batch = consumer.fetch_batch().await.expect("Failed to fetch batch");
    assert_eq!(batch.len(), 1, "Should fetch exactly 1 message");

    let (fetched_request, handle) = batch.into_iter().next().unwrap();
    assert_eq!(fetched_request.request_id, "e2e-dd-001");

    // 3. Strategy selector picks the strategy
    let registry = CircuitRegistry::new();
    let selector = StrategySelector::new(registry);
    let strategy = selector
        .select(&fetched_request)
        .expect("Strategy selection should succeed");
    assert_eq!(
        strategy,
        PrivacyStrategy::DirectDelegation,
        "None privacy → DirectDelegation"
    );

    // 4. Router routes the request
    let router = Router::new(config.default_prover_id.clone());
    router
        .route_request(&fetched_request, &strategy, &js)
        .await
        .expect("Routing should succeed");

    // 5. Ack the original message
    handle.ack().await.expect("Failed to ack");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. Verify ProverTask appeared on the tasks subject
    let tasks_consumer = tasks_stream
        .get_consumer::<PullConfig>("e2e-tasks")
        .await
        .unwrap();

    let mut messages = tasks_consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages
        .next()
        .await
        .expect("Should have a ProverTask message")
        .unwrap();
    let task: ProverTask = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(task.request_id, "e2e-dd-001");
    assert_eq!(task.circuit_id, "proof-of-membership");
    assert_eq!(task.strategy, PrivacyStrategy::DirectDelegation);
    assert_eq!(task.prover_id, prover_id.as_str());
}

/// E2E: PrivacyLevel::Mandatory + small UltraHonk circuit → ClientSide
/// → message goes to sincerin.proofs.client, NOT to prover tasks.
#[tokio::test]
async fn test_e2e_client_side_flow() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    // Set up consumers on both client and tasks subjects
    let client_stream = js.get_stream("PROOF_CLIENT").await.unwrap();
    client_stream
        .get_or_create_consumer(
            "e2e-client",
            PullConfig {
                durable_name: Some("e2e-client".to_string()),
                filter_subject: "sincerin.proofs.client".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // 1. Publish a proof request (Mandatory + proof-of-membership = small UltraHonk → ClientSide)
    let request = helpers::membership_request("e2e-cs-001", PrivacyLevel::Mandatory);
    nats::publish(&js, nats::subjects::PROOF_REQUESTS, &request)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Consume
    let consumer = RequestConsumer::new(js.clone(), config.clone())
        .await
        .expect("Failed to create consumer");

    let batch = consumer.fetch_batch().await.unwrap();
    assert_eq!(batch.len(), 1);

    let (fetched, handle) = batch.into_iter().next().unwrap();

    // 3. Strategy → ClientSide
    let selector = StrategySelector::new(CircuitRegistry::new());
    let strategy = selector.select(&fetched).unwrap();
    assert_eq!(strategy, PrivacyStrategy::ClientSide);

    // 4. Route
    let router = Router::new(config.default_prover_id.clone());
    router.route_request(&fetched, &strategy, &js).await.unwrap();
    handle.ack().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 5. Verify message appeared on client subject
    let client_consumer = client_stream
        .get_consumer::<PullConfig>("e2e-client")
        .await
        .unwrap();

    let mut messages = client_consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages
        .next()
        .await
        .expect("Should have a client message")
        .unwrap();
    let routed: sincerin_common::types::ProofRequest =
        serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(routed.request_id, "e2e-cs-001");
}

/// Test multiple requests in a single batch are all processed correctly.
#[tokio::test]
async fn test_e2e_batch_processing() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);
    let prover_id = &config.default_prover_id.clone();

    let tasks_stream = js.get_stream("PROOF_TASKS").await.unwrap();
    tasks_stream
        .get_or_create_consumer(
            "e2e-batch-tasks",
            PullConfig {
                durable_name: Some("e2e-batch-tasks".to_string()),
                filter_subject: format!("sincerin.proofs.tasks.{prover_id}"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let client_stream = js.get_stream("PROOF_CLIENT").await.unwrap();
    client_stream
        .get_or_create_consumer(
            "e2e-batch-client",
            PullConfig {
                durable_name: Some("e2e-batch-client".to_string()),
                filter_subject: "sincerin.proofs.client".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Publish mixed requests: 2 DirectDelegation + 1 ClientSide
    let requests = vec![
        helpers::membership_request("batch-dd-1", PrivacyLevel::None),
        helpers::membership_request("batch-cs-1", PrivacyLevel::Mandatory),
        helpers::membership_request("batch-dd-2", PrivacyLevel::None),
    ];

    for req in &requests {
        nats::publish(&js, nats::subjects::PROOF_REQUESTS, req)
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Consume all
    let consumer = RequestConsumer::new(js.clone(), config.clone())
        .await
        .unwrap();
    let batch = consumer.fetch_batch().await.unwrap();
    assert_eq!(batch.len(), 3);

    // Process each through strategy + router
    let selector = StrategySelector::new(CircuitRegistry::new());
    let router = Router::new(config.default_prover_id.clone());

    for (req, handle) in batch {
        let strategy = selector.select(&req).unwrap();
        router.route_request(&req, &strategy, &js).await.unwrap();
        handle.ack().await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify: 2 tasks on prover subject, 1 on client subject
    let tasks_consumer = tasks_stream
        .get_consumer::<PullConfig>("e2e-batch-tasks")
        .await
        .unwrap();

    let mut task_msgs = tasks_consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let mut task_ids = Vec::new();
    while let Some(Ok(msg)) = task_msgs.next().await {
        let task: ProverTask = serde_json::from_slice(&msg.payload).unwrap();
        task_ids.push(task.request_id);
    }
    assert_eq!(task_ids.len(), 2, "Should have 2 prover tasks");
    assert!(task_ids.contains(&"batch-dd-1".to_string()));
    assert!(task_ids.contains(&"batch-dd-2".to_string()));

    let client_consumer = client_stream
        .get_consumer::<PullConfig>("e2e-batch-client")
        .await
        .unwrap();

    let mut client_msgs = client_consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let mut client_ids = Vec::new();
    while let Some(Ok(msg)) = client_msgs.next().await {
        let req: sincerin_common::types::ProofRequest =
            serde_json::from_slice(&msg.payload).unwrap();
        client_ids.push(req.request_id);
    }
    assert_eq!(client_ids.len(), 1, "Should have 1 client-side request");
    assert_eq!(client_ids[0], "batch-cs-1");
}

/// Test that unknown circuit_id results in an error.
#[tokio::test]
async fn test_e2e_unknown_circuit_error() {
    let selector = StrategySelector::new(CircuitRegistry::new());

    let mut request = helpers::membership_request("unknown-circuit", PrivacyLevel::Mandatory);
    request.circuit_id = "nonexistent-circuit".to_string();

    let result = selector.select(&request);
    assert!(result.is_err(), "Unknown circuit should fail");
}
