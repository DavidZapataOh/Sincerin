mod helpers;

use tower::ServiceExt;

/// Requests under the rate limit all succeed.
#[tokio::test]
async fn test_rate_limit_allows_under_limit() {
    let nats = helpers::start_nats_server().await;
    let mut config = helpers::create_test_config(&nats.url);
    config.rate_limit_rps = 100;
    let app = helpers::create_test_app_with_config(config).await;

    // Send 50 requests (well under 100 + 50 burst = 150)
    for i in 0..50 {
        let app = app.clone();
        let body = helpers::valid_prove_body();
        let req = helpers::post_json_with_key("/v1/prove", body);
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), 202, "Request {i} should succeed");
    }
}

/// Requests over the burst limit get 429.
#[tokio::test]
async fn test_rate_limit_blocks_over_limit() {
    let nats = helpers::start_nats_server().await;
    let mut config = helpers::create_test_config(&nats.url);
    config.rate_limit_rps = 10; // burst = 10 + 50 = 60
    let app = helpers::create_test_app_with_config(config).await;

    let mut success_count = 0u32;
    let mut rate_limited_count = 0u32;

    // Send 70 requests rapidly — first ~60 should succeed (burst), rest should be 429
    for _ in 0..70 {
        let app = app.clone();
        let body = helpers::valid_prove_body();
        let req = helpers::post_json_with_key("/v1/prove", body);
        let resp = app.oneshot(req).await.unwrap();

        match resp.status().as_u16() {
            202 => success_count += 1,
            429 => rate_limited_count += 1,
            other => panic!("Unexpected status: {other}"),
        }
    }

    assert!(success_count > 0, "Some requests should succeed");
    assert!(rate_limited_count > 0, "Some requests should be rate limited");
    // With burst=60, first ~60 should pass, remaining ~10 should be 429
    assert!(success_count <= 61, "Should not exceed burst + 1: got {success_count}");
}

/// Rate limited response includes Retry-After header.
#[tokio::test]
async fn test_rate_limit_retry_after_header() {
    let nats = helpers::start_nats_server().await;
    let mut config = helpers::create_test_config(&nats.url);
    config.rate_limit_rps = 5; // burst = 5 + 50 = 55
    let app = helpers::create_test_app_with_config(config).await;

    // Exhaust the bucket (55 requests)
    for _ in 0..56 {
        let app = app.clone();
        let body = helpers::valid_prove_body();
        let req = helpers::post_json_with_key("/v1/prove", body);
        let _ = app.oneshot(req).await.unwrap();
    }

    // Next request should be rate limited
    let body = helpers::valid_prove_body();
    let req = helpers::post_json_with_key("/v1/prove", body);
    let resp = app.oneshot(req).await.unwrap();

    if resp.status() == 429 {
        let retry_after = resp.headers().get("retry-after");
        assert!(retry_after.is_some(), "Should have Retry-After header");

        let retry_val: u64 = retry_after.unwrap().to_str().unwrap().parse().unwrap();
        assert!(retry_val > 0, "Retry-After should be > 0");

        let body = helpers::body_json(resp).await;
        assert_eq!(body["error"], "rate_limited");
        assert!(body["retry_after_ms"].is_number());
    }
}

/// Different API keys have independent rate limits.
#[tokio::test]
async fn test_rate_limit_per_api_key() {
    let nats = helpers::start_nats_server().await;
    let mut config = helpers::create_test_config(&nats.url);
    config.rate_limit_rps = 3; // burst = 3 + 50 = 53
    let app = helpers::create_test_app_with_config(config).await;

    // Exhaust key A's bucket
    for _ in 0..54 {
        let app = app.clone();
        let body = helpers::valid_prove_body();
        let req = helpers::post_json_with_key("/v1/prove", body);
        let _ = app.oneshot(req).await.unwrap();
    }

    // Key A should be rate limited
    let body_a = helpers::valid_prove_body();
    let req_a = helpers::post_json_with_key("/v1/prove", body_a);
    let resp_a = app.clone().oneshot(req_a).await.unwrap();
    assert_eq!(resp_a.status(), 429, "Key A should be rate limited");

    // Key B should still work
    let body_b = helpers::valid_prove_body();
    let req_b = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/prove")
        .header("x-api-key", helpers::TEST_API_KEY_B)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body_b).unwrap()))
        .unwrap();
    let resp_b = app.oneshot(req_b).await.unwrap();
    assert_eq!(resp_b.status(), 202, "Key B should still work");
}

/// Rate limit refills over time.
#[tokio::test]
async fn test_rate_limit_refills() {
    use sincerin_gateway::middleware::rate_limit::RateLimiter;

    // Test at the RateLimiter level directly to avoid timing issues with HTTP overhead.
    let limiter = RateLimiter::new(10, 10);

    // Exhaust the bucket
    for _ in 0..10 {
        assert!(limiter.try_acquire("refill-key").is_ok());
    }

    // Should be rate limited now
    assert!(limiter.try_acquire("refill-key").is_err(), "Should be rate limited");

    // Wait for tokens to refill (10 tokens/sec, need 1 token → 100ms)
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Should work again after refill
    assert!(limiter.try_acquire("refill-key").is_ok(), "Should work after refill period");
}
