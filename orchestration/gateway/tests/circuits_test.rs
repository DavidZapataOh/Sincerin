mod helpers;

use tower::ServiceExt;

#[tokio::test]
async fn test_circuits_endpoint() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let req = helpers::request_no_key("GET", "/v1/circuits");
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 200);

    let body = helpers::body_json(resp).await;
    let circuits = body["circuits"].as_array().unwrap();

    // Should have at least our 2 MVP circuits
    assert!(circuits.len() >= 2);

    let ids: Vec<&str> = circuits.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"proof-of-membership"));
    assert!(ids.contains(&"proof-of-age"));
}

#[tokio::test]
async fn test_circuits_no_auth_required() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let req = helpers::request_no_key("GET", "/v1/circuits");
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_circuits_response_format() {
    let nats = helpers::start_nats_server().await;
    let app = helpers::create_test_app(&nats).await;

    let req = helpers::request_no_key("GET", "/v1/circuits");
    let resp = app.oneshot(req).await.unwrap();
    let body = helpers::body_json(resp).await;

    let circuits = body["circuits"].as_array().unwrap();
    for circuit in circuits {
        // Each circuit should have all required fields
        assert!(circuit["id"].is_string());
        assert!(circuit["name"].is_string());
        assert!(circuit["description"].is_string());
        assert!(circuit["proof_system"].is_string());
        assert!(circuit["estimated_constraints"].is_number());
        assert!(circuit["client_side_feasible"].is_boolean());
        assert!(circuit["estimated_time_ms"].is_number());
    }
}
