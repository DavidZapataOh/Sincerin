use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub nats_connected: bool,
    pub uptime_seconds: u64,
}

pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    let uptime = state.start_time.elapsed().as_secs();

    // Check NATS connectivity by attempting a simple operation
    let nats_connected = state
        .jetstream
        .get_stream("PROOF_REQUESTS")
        .await
        .is_ok();

    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        nats_connected,
        uptime_seconds: uptime,
    })
}
