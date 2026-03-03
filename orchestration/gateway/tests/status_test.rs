mod helpers;

use tower::ServiceExt;

/// Full flow: POST /v1/prove then GET /v1/proof/:id returns pending status.
#[tokio::test]
async fn test_full_flow_prove_and_status() {
    let nats = helpers::start_nats_server().await;

    // 1. Submit a proof request
    let app = helpers::create_test_app(&nats).await;
    let body = helpers::valid_prove_body();
    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 202);

    let prove_body = helpers::body_json(resp).await;
    let request_id = prove_body["request_id"].as_str().unwrap();

    // 2. Query the status — should be "pending"
    let app = helpers::create_test_app(&nats).await;
    let req = helpers::request_with_key("GET", &format!("/v1/proof/{request_id}"));
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 200);
    let status_body = helpers::body_json(resp).await;
    assert_eq!(status_body["request_id"], request_id);
    assert_eq!(status_body["status"], "pending");
}

/// GET /v1/proof/:id with non-existent request_id returns 404.
#[tokio::test]
async fn test_status_not_found() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    // Valid format but doesn't exist
    let fake_id = "0x".to_string() + &"a".repeat(64);
    let req = helpers::request_with_key("GET", &format!("/v1/proof/{fake_id}"));
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 404);
    let body = helpers::body_json(resp).await;
    assert_eq!(body["error"], "not_found");
}

/// GET /v1/proof/:id with invalid format returns 400.
#[tokio::test]
async fn test_status_invalid_request_id_format() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    // Too short
    let req = helpers::request_with_key("GET", "/v1/proof/0xabc");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["error"], "invalid_request_id");
}

/// GET /v1/proof/:id without 0x prefix returns 400.
#[tokio::test]
async fn test_status_no_0x_prefix() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let bad_id = "a".repeat(66); // right length but no 0x prefix
    let req = helpers::request_with_key("GET", &format!("/v1/proof/{bad_id}"));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
}

/// GET /v1/proof/:id with non-hex chars returns 400.
#[tokio::test]
async fn test_status_non_hex_chars() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let bad_id = "0x".to_string() + &"g".repeat(64); // 'g' is not hex
    let req = helpers::request_with_key("GET", &format!("/v1/proof/{bad_id}"));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
}

/// GET /v1/proof/:id without auth returns 401.
#[tokio::test]
async fn test_status_no_auth() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let fake_id = "0x".to_string() + &"a".repeat(64);
    let req = helpers::request_no_key("GET", &format!("/v1/proof/{fake_id}"));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

/// Status update published to NATS is reflected in GET response.
#[tokio::test]
async fn test_status_reflects_nats_update() {
    use sincerin_common::nats as nats_helpers;
    use sincerin_common::types::ProofStatus;

    let nats = helpers::start_nats_server().await;

    // 1. Submit a proof request
    let app = helpers::create_test_app(&nats).await;
    let body = helpers::valid_prove_body();
    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 202);

    let prove_body = helpers::body_json(resp).await;
    let request_id = prove_body["request_id"].as_str().unwrap();

    // 2. Publish a status update to NATS (simulating the prover)
    let client = nats_helpers::connect(&nats.url).await.unwrap();
    let js = nats_helpers::jetstream_context(&client);

    let assigned_status = ProofStatus::Assigned {
        prover_id: "prover-001".to_string(),
    };
    nats_helpers::publish_status_update(&js, request_id, &assigned_status)
        .await
        .unwrap();

    // Small delay for NATS to propagate
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 3. Query status — should now be "assigned"
    let app = helpers::create_test_app(&nats).await;
    let req = helpers::request_with_key("GET", &format!("/v1/proof/{request_id}"));
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 200);
    let status_body = helpers::body_json(resp).await;
    assert_eq!(status_body["status"], "assigned");
    assert_eq!(status_body["prover_id"], "prover-001");
}
