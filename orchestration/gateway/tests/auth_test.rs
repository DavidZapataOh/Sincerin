mod helpers;

use tower::ServiceExt;

/// Request with valid X-API-Key header passes auth and reaches the handler.
#[tokio::test]
async fn test_auth_valid_header() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    // GET /v1/circuits is public, but let's test a protected route.
    // Use /v1/proof/:id with a valid key — it will return 400 (bad ID format) not 401.
    let req = helpers::request_with_key("GET", "/v1/proof/0xinvalid");
    let resp = app.oneshot(req).await.unwrap();

    // Should NOT be 401 — auth passed, but the request_id format is invalid (400)
    assert_eq!(resp.status(), 400);
}

/// Request with valid api_key query param passes auth.
#[tokio::test]
async fn test_auth_valid_query_param() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let uri = format!("/v1/proof/0xinvalid?api_key={}", helpers::TEST_API_KEY);
    let req = helpers::request_no_key("GET", &uri);
    let resp = app.oneshot(req).await.unwrap();

    // Auth passed (not 401), gets 400 for bad request_id format
    assert_eq!(resp.status(), 400);
}

/// Header takes priority over query param.
#[tokio::test]
async fn test_auth_header_takes_priority() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    // Header has valid key, query param has invalid key
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/proof/0xinvalid?api_key=wrong-key")
        .header("x-api-key", helpers::TEST_API_KEY)
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // Auth should pass (header key is valid), get 400 for bad format
    assert_eq!(resp.status(), 400);
}

/// Request without any API key returns 401.
#[tokio::test]
async fn test_auth_no_key() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let req = helpers::request_no_key("GET", "/v1/proof/0xabc");
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 401);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["error"], "unauthorized");
    assert!(body["message"].as_str().unwrap().contains("API key required"));
}

/// Request with invalid API key returns 401.
#[tokio::test]
async fn test_auth_invalid_key() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let req = helpers::request_with_specific_key("GET", "/v1/proof/0xabc", "wrong-key-999");
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 401);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["error"], "unauthorized");
    assert_eq!(body["message"], "Invalid API key");
}

/// Public routes bypass auth — GET /health and GET /v1/circuits return 200 without key.
#[tokio::test]
async fn test_auth_public_routes_bypass() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    // /health — public
    let req = helpers::request_no_key("GET", "/health");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // /v1/circuits — public
    let req = helpers::request_no_key("GET", "/v1/circuits");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

/// Empty API key returns 401.
#[tokio::test]
async fn test_auth_empty_key() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/proof/0xabc")
        .header("x-api-key", "")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

/// Lowercase x-api-key header works (Axum normalizes headers).
#[tokio::test]
async fn test_auth_lowercase_header() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/proof/0xinvalid")
        .header("x-api-key", helpers::TEST_API_KEY)
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Should not be 401
    assert_ne!(resp.status(), 401);
}
