mod helpers;

use std::time::Duration;

use sincerin_common::nats;
use sincerin_common::types::PrivacyLevel;
use sincerin_dispatcher::consumer::RequestConsumer;

#[tokio::test]
async fn test_consumer_creates_durable_consumer() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    let consumer = RequestConsumer::new(js, config.clone()).await;
    assert!(consumer.is_ok(), "Consumer should be created successfully");
}

#[tokio::test]
async fn test_consumer_fetches_published_messages() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    // Publish 3 proof requests
    let requests: Vec<_> = (1..=3)
        .map(|i| helpers::membership_request(&format!("req-{i}"), PrivacyLevel::Mandatory))
        .collect();

    for req in &requests {
        nats::publish(&js, nats::subjects::PROOF_REQUESTS, req)
            .await
            .expect("Failed to publish request");
    }

    // Small delay for stream persistence
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create consumer and fetch batch
    let consumer = RequestConsumer::new(js, config)
        .await
        .expect("Failed to create consumer");

    let batch = consumer.fetch_batch().await.expect("Failed to fetch batch");

    assert_eq!(batch.len(), 3, "Should fetch all 3 messages");

    let ids: Vec<&str> = batch.iter().map(|(r, _)| r.request_id.as_str()).collect();
    assert!(ids.contains(&"req-1"));
    assert!(ids.contains(&"req-2"));
    assert!(ids.contains(&"req-3"));

    // Ack all messages
    for (_, handle) in batch {
        handle.ack().await.expect("Failed to ack");
    }
}

#[tokio::test]
async fn test_consumer_ack_prevents_redelivery() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    let req = helpers::membership_request("req-ack-test", PrivacyLevel::None);
    nats::publish(&js, nats::subjects::PROOF_REQUESTS, &req)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let consumer = RequestConsumer::new(js, config)
        .await
        .expect("Failed to create consumer");

    // First fetch: should get the message
    let batch = consumer.fetch_batch().await.unwrap();
    assert_eq!(batch.len(), 1);

    // Ack it
    let (fetched, handle) = batch.into_iter().next().unwrap();
    assert_eq!(fetched.request_id, "req-ack-test");
    handle.ack().await.unwrap();

    // Second fetch: should be empty (message was acked)
    let batch2 = consumer.fetch_batch().await.unwrap();
    assert_eq!(batch2.len(), 0, "Acked message should not be redelivered");
}

#[tokio::test]
async fn test_consumer_malformed_message_is_acked() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let config = helpers::create_test_config(&nats_handle.url);

    // Publish invalid JSON directly to the stream
    js.publish(
        nats::subjects::PROOF_REQUESTS.to_string(),
        "{not valid json!!!}".into(),
    )
    .await
    .unwrap()
    .await
    .unwrap();

    // Publish a valid request after the malformed one
    let req = helpers::membership_request("req-after-malformed", PrivacyLevel::None);
    nats::publish(&js, nats::subjects::PROOF_REQUESTS, &req)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let consumer = RequestConsumer::new(js, config)
        .await
        .expect("Failed to create consumer");

    let batch = consumer.fetch_batch().await.unwrap();

    // Only the valid message should be in the batch (malformed was acked internally)
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].0.request_id, "req-after-malformed");

    // Cleanup
    for (_, handle) in batch {
        handle.ack().await.unwrap();
    }
}

#[tokio::test]
async fn test_consumer_respects_batch_size() {
    let nats_handle = helpers::start_nats_server().await;
    let (_, js) = helpers::setup_test_nats(&nats_handle).await;
    let mut config = helpers::create_test_config(&nats_handle.url);
    config.batch_size = 2; // Only fetch 2 at a time

    // Publish 5 requests
    for i in 1..=5 {
        let req = helpers::membership_request(&format!("batch-{i}"), PrivacyLevel::None);
        nats::publish(&js, nats::subjects::PROOF_REQUESTS, &req)
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let consumer = RequestConsumer::new(js, config)
        .await
        .expect("Failed to create consumer");

    // First batch: should get at most 2
    let batch1 = consumer.fetch_batch().await.unwrap();
    assert!(
        batch1.len() <= 2,
        "Batch size should be respected, got {}",
        batch1.len()
    );

    for (_, handle) in batch1 {
        handle.ack().await.unwrap();
    }
}
