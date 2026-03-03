mod helpers;

use tower::ServiceExt;

/// POST /v1/prove with valid body returns 202 with request_id.
#[tokio::test]
async fn test_prove_valid_request() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let body = helpers::valid_prove_body();
    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 202);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["status"], "pending");

    // request_id should be 0x-prefixed 64-char hex
    let rid = body["request_id"].as_str().unwrap();
    assert!(rid.starts_with("0x"));
    assert_eq!(rid.len(), 66);

    // Should have estimated_time_ms
    assert!(body["estimated_time_ms"].is_number());

    // Should have websocket_topic
    let topic = body["websocket_topic"].as_str().unwrap();
    assert!(topic.starts_with("sincerin.proofs.status."));
}

/// POST /v1/prove with unknown circuit returns 400.
#[tokio::test]
async fn test_prove_unknown_circuit() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let mut body = helpers::valid_prove_body();
    body["circuit_id"] = serde_json::json!("unknown-circuit-xyz");

    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 400);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["error"], "unknown_circuit");
}

/// POST /v1/prove with invalid privacy level returns 400.
#[tokio::test]
async fn test_prove_invalid_privacy() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let mut body = helpers::valid_prove_body();
    body["privacy"] = serde_json::json!("invalid_privacy");

    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 400);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["error"], "invalid_privacy_level");
}

/// POST /v1/prove with invalid priority returns 400.
#[tokio::test]
async fn test_prove_invalid_priority() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let mut body = helpers::valid_prove_body();
    body["priority"] = serde_json::json!("ultra_mega_fast");

    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 400);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["error"], "invalid_priority");
}

/// POST /v1/prove with deadline in the past returns 400.
#[tokio::test]
async fn test_prove_deadline_in_past() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let mut body = helpers::valid_prove_body();
    body["deadline"] = serde_json::json!(1000); // epoch 1000 is definitely in the past

    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 400);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(body["message"].as_str().unwrap().contains("deadline"));
}

/// POST /v1/prove without auth returns 401.
#[tokio::test]
async fn test_prove_no_auth() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let body = helpers::valid_prove_body();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/prove")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

/// POST /v1/prove with all valid privacy levels.
#[tokio::test]
async fn test_prove_valid_privacy_levels() {
    let nats = helpers::start_nats_server().await;

    for privacy in &["none", "optional", "mandatory"] {
        let app = helpers::create_test_app(&nats).await;
        let mut body = helpers::valid_prove_body();
        body["privacy"] = serde_json::json!(privacy);

        let req = helpers::post_json_with_key("/v1/prove", body);
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), 202, "Privacy level '{privacy}' should be accepted");
    }
}

/// POST /v1/prove with all valid priority levels.
#[tokio::test]
async fn test_prove_valid_priority_levels() {
    let nats = helpers::start_nats_server().await;

    for priority in &["low", "standard", "high"] {
        let app = helpers::create_test_app(&nats).await;
        let mut body = helpers::valid_prove_body();
        body["priority"] = serde_json::json!(priority);

        let req = helpers::post_json_with_key("/v1/prove", body);
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), 202, "Priority '{priority}' should be accepted");
    }
}

/// POST /v1/prove with proof-of-age circuit.
#[tokio::test]
async fn test_prove_proof_of_age() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let mut body = helpers::valid_prove_body();
    body["circuit_id"] = serde_json::json!("proof-of-age");

    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 202);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["estimated_time_ms"], 5000);
}

/// Each POST /v1/prove generates a unique request_id.
#[tokio::test]
async fn test_prove_unique_request_ids() {
    let nats = helpers::start_nats_server().await;

    let mut ids = std::collections::HashSet::new();

    for _ in 0..5 {
        let app = helpers::create_test_app(&nats).await;
        let body = helpers::valid_prove_body();
        let req = helpers::post_json_with_key("/v1/prove", body);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 202);

        let body = helpers::body_json(resp).await;
        let rid = body["request_id"].as_str().unwrap().to_string();
        ids.insert(rid);
    }

    assert_eq!(ids.len(), 5, "All 5 request_ids should be unique");
}
