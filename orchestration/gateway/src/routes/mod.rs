pub mod circuits;
pub mod health;
pub mod prove;
pub mod status;

use axum::Router;
use axum::routing::{get, post};

use crate::state::AppState;

/// Build the complete Axum router with all routes and middleware.
pub fn build_router(state: AppState) -> Router {
    // Protected routes require API key authentication.
    // The ApiKeyId extractor checks the X-API-Key header or ?api_key= query param.
    // Valid keys are injected into request extensions via a layer.
    let protected = Router::new()
        .route("/v1/prove", post(prove::post_prove))
        .route("/v1/proof/{id}", get(status::get_proof_status))
        .route("/v1/ws", get(crate::ws::handler::ws_handler))
        .layer(axum::Extension(state.api_keys.clone()));

    // Public routes — no auth required
    let public = Router::new()
        .route("/health", get(health::health_check))
        .route("/v1/circuits", get(circuits::list_circuits));

    Router::new()
        .merge(protected)
        .merge(public)
        .with_state(state)
}
