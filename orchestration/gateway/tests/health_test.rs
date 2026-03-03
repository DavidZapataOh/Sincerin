mod helpers;

use tower::ServiceExt;

#[tokio::test]
async fn test_health_endpoint() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let req = helpers::request_no_key("GET", "/health");
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 200);

    let body = helpers::body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], "0.1.0");
    assert_eq!(body["nats_connected"], true);
    assert!(body["uptime_seconds"].is_number());
}

#[tokio::test]
async fn test_health_no_auth_required() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    // Health endpoint should work without any API key
    let req = helpers::request_no_key("GET", "/health");
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 200);
}
