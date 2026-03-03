use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::config::GatewayConfig;
use crate::middleware::rate_limit::RateLimiter;

/// Shared application state passed to all handlers via Axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    pub jetstream: async_nats::jetstream::Context,
    pub config: Arc<GatewayConfig>,
    pub api_keys: Arc<HashSet<String>>,
    pub valid_circuits: Arc<HashSet<String>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub start_time: Instant,
}

impl AppState {
    pub fn new(
        jetstream: async_nats::jetstream::Context,
        config: GatewayConfig,
    ) -> Self {
        let rate_limiter = RateLimiter::new(config.rate_limit_rps, config.rate_limit_rps + 50);

        let valid_circuits: HashSet<String> = [
            "proof-of-membership".to_string(),
            "proof-of-age".to_string(),
        ]
        .into_iter()
        .collect();

        Self {
            jetstream,
            api_keys: Arc::new(config.api_keys.clone()),
            config: Arc::new(config),
            valid_circuits: Arc::new(valid_circuits),
            rate_limiter: Arc::new(rate_limiter),
            start_time: Instant::now(),
        }
    }
}
