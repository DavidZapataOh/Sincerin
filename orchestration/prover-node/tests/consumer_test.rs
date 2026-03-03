mod helpers;

use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream::consumer::pull::Config as PullConfig;
use futures::StreamExt;

use sincerin_common::nats;
use sincerin_common::types::{PrivacyStrategy, ProofResult, ProofStatus};
use sincerin_prover_node::consumer::TaskConsumer;
use sincerin_prover_node::executor::Executor;

#[tokio::test]
async fn test_consumer_receives_and_processes_task() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    // Set up a consumer on the results subject to capture output
    let results_stream = js.get_stream("PROOF_RESULTS").await.unwrap();
    results_stream
        .get_or_create_consumer(
            "test-results",
            PullConfig {
                durable_name: Some("test-results".to_string()),
                filter_subject: nats::subjects::PROOF_RESULTS.to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Publish a task to the prover's subject
    let task = helpers::make_prover_task(
        "consumer-001",
        "proof-of-membership",
        PrivacyStrategy::DirectDelegation,
        Some(vec![1, 2, 3, 4]),
    );

    let task_subject = format!(
        "{}.{}",
        nats::subjects::PROOF_TASKS,
        config.prover_id
    );
    nats::publish(&js, &task_subject, &task).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create executor with mock backend
    let backend = helpers::mock_backend_success();
    let executor = Arc::new(Executor::new(backend, config.prover_id.clone()));

    // Run consumer in a task with cancellation
    let cancel = tokio_util::sync::CancellationToken::new();
    let consumer = TaskConsumer::new(js.clone(), executor, config.clone());

    let consumer_cancel = cancel.clone();
    let consumer_handle = tokio::spawn(async move {
        let _ = consumer.run(consumer_cancel).await;
    });

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Cancel and wait
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), consumer_handle).await;

    // Verify ProofResult appeared on results subject
    let results_consumer = results_stream
        .get_consumer::<PullConfig>("test-results")
        .await
        .unwrap();

    let mut messages = results_consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages.next().await.expect("Should have a result message").unwrap();
    let result: ProofResult = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(result.request_id, "consumer-001");
    assert_eq!(result.circuit_id, "proof-of-membership");
    assert_eq!(result.proof, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[tokio::test]
async fn test_consumer_publishes_proving_status() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    // Set up a consumer on the status subject for this request
    let status_stream = js.get_stream("PROOF_STATUS").await.unwrap();
    status_stream
        .get_or_create_consumer(
            "test-status",
            PullConfig {
                durable_name: Some("test-status".to_string()),
                filter_subject: "sincerin.proofs.status.status-001".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Publish task
    let task = helpers::make_prover_task(
        "status-001",
        "proof-of-membership",
        PrivacyStrategy::DirectDelegation,
        Some(vec![1, 2, 3]),
    );

    let task_subject = format!("{}.{}", nats::subjects::PROOF_TASKS, config.prover_id);
    nats::publish(&js, &task_subject, &task).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run consumer with mock backend (with small delay to observe status)
    let backend = Arc::new(helpers::MockProverBackend::success(
        vec![0xaa, 0xbb],
        200,
    ).with_delay(100));
    let executor = Arc::new(Executor::new(backend, config.prover_id.clone()));

    let cancel = tokio_util::sync::CancellationToken::new();
    let consumer = TaskConsumer::new(js.clone(), executor, config.clone());

    let consumer_cancel = cancel.clone();
    let consumer_handle = tokio::spawn(async move {
        let _ = consumer.run(consumer_cancel).await;
    });

    tokio::time::sleep(Duration::from_millis(1500)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), consumer_handle).await;

    // Verify status updates
    let status_consumer = status_stream
        .get_consumer::<PullConfig>("test-status")
        .await
        .unwrap();

    let mut messages = status_consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let mut statuses = Vec::new();
    while let Some(Ok(msg)) = messages.next().await {
        let status: ProofStatus = serde_json::from_slice(&msg.payload).unwrap();
        statuses.push(status);
    }

    // Should have at least Proving and Verifying statuses
    assert!(
        statuses.len() >= 2,
        "Should have at least 2 status updates, got {}",
        statuses.len()
    );
    assert!(
        matches!(statuses[0], ProofStatus::Proving { .. }),
        "First status should be Proving, got: {:?}",
        statuses[0]
    );
    assert!(
        matches!(statuses[1], ProofStatus::Verifying),
        "Second status should be Verifying, got: {:?}",
        statuses[1]
    );
}

#[tokio::test]
async fn test_consumer_publishes_failed_status_on_error() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    let status_stream = js.get_stream("PROOF_STATUS").await.unwrap();
    status_stream
        .get_or_create_consumer(
            "test-fail-status",
            PullConfig {
                durable_name: Some("test-fail-status".to_string()),
                filter_subject: "sincerin.proofs.status.fail-001".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Publish task
    let task = helpers::make_prover_task(
        "fail-001",
        "proof-of-membership",
        PrivacyStrategy::DirectDelegation,
        Some(vec![1, 2, 3]),
    );

    let task_subject = format!("{}.{}", nats::subjects::PROOF_TASKS, config.prover_id);
    nats::publish(&js, &task_subject, &task).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run consumer with failing backend
    let backend = helpers::mock_backend_failure();
    let executor = Arc::new(Executor::new(backend, config.prover_id.clone()));

    let cancel = tokio_util::sync::CancellationToken::new();
    let consumer = TaskConsumer::new(js.clone(), executor, config.clone());

    let consumer_cancel = cancel.clone();
    let consumer_handle = tokio::spawn(async move {
        let _ = consumer.run(consumer_cancel).await;
    });

    tokio::time::sleep(Duration::from_millis(1000)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), consumer_handle).await;

    // Verify Failed status was published
    let status_consumer = status_stream
        .get_consumer::<PullConfig>("test-fail-status")
        .await
        .unwrap();

    let mut messages = status_consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let mut found_failed = false;
    while let Some(Ok(msg)) = messages.next().await {
        let status: ProofStatus = serde_json::from_slice(&msg.payload).unwrap();
        if matches!(status, ProofStatus::Failed { .. }) {
            found_failed = true;
        }
    }

    assert!(found_failed, "Should have published a Failed status");
}

#[tokio::test]
async fn test_consumer_acks_malformed_messages() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    // Publish invalid JSON to the tasks subject
    let task_subject = format!("{}.{}", nats::subjects::PROOF_TASKS, config.prover_id);
    js.publish(task_subject.clone(), "{not valid json}".into())
        .await
        .unwrap()
        .await
        .unwrap();

    // Then publish a valid task
    let task = helpers::make_prover_task(
        "after-malformed-001",
        "proof-of-membership",
        PrivacyStrategy::DirectDelegation,
        Some(vec![1, 2, 3]),
    );
    nats::publish(&js, &task_subject, &task).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Set up results consumer
    let results_stream = js.get_stream("PROOF_RESULTS").await.unwrap();
    results_stream
        .get_or_create_consumer(
            "test-malformed-results",
            PullConfig {
                durable_name: Some("test-malformed-results".to_string()),
                filter_subject: nats::subjects::PROOF_RESULTS.to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let backend = helpers::mock_backend_success();
    let executor = Arc::new(Executor::new(backend, config.prover_id.clone()));

    let cancel = tokio_util::sync::CancellationToken::new();
    let consumer = TaskConsumer::new(js.clone(), executor, config.clone());

    let consumer_cancel = cancel.clone();
    let consumer_handle = tokio::spawn(async move {
        let _ = consumer.run(consumer_cancel).await;
    });

    tokio::time::sleep(Duration::from_millis(1500)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), consumer_handle).await;

    // The valid task should have been processed despite the malformed one
    let results_consumer = results_stream
        .get_consumer::<PullConfig>("test-malformed-results")
        .await
        .unwrap();

    let mut messages = results_consumer
        .fetch()
        .max_messages(10)
        .expires(Duration::from_millis(500))
        .messages()
        .await
        .unwrap();

    let msg = messages.next().await.expect("Should have processed valid task").unwrap();
    let result: ProofResult = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(result.request_id, "after-malformed-001");
}
