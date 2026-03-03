use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// API error codes returned to clients.
#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorBody {
    pub error: String,
    pub message: String,
}

/// Unified API error type for all gateway endpoints.
#[derive(Debug)]
pub enum ApiError {
    /// 400 — Unknown circuit ID
    UnknownCircuit(String),
    /// 400 — Invalid privacy level
    InvalidPrivacyLevel(String),
    /// 400 — Invalid priority
    InvalidPriority(String),
    /// 400 — Malformed request (missing fields, bad JSON, etc.)
    InvalidRequest(String),
    /// 400 — Invalid request ID format
    InvalidRequestId(String),
    /// 401 — Missing or invalid API key
    Unauthorized(String),
    /// 404 — Proof request not found
    NotFound(String),
    /// 413 — Payload too large
    PayloadTooLarge,
    /// 429 — Rate limit exceeded
    RateLimited { retry_after_ms: u64 },
    /// 500 — Internal server error
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            ApiError::UnknownCircuit(c) => (
                StatusCode::BAD_REQUEST,
                "unknown_circuit",
                format!("Circuit '{c}' not found in registry"),
            ),
            ApiError::InvalidPrivacyLevel(v) => (
                StatusCode::BAD_REQUEST,
                "invalid_privacy_level",
                format!("Invalid privacy level: '{v}'. Must be one of: none, optional, mandatory"),
            ),
            ApiError::InvalidPriority(v) => (
                StatusCode::BAD_REQUEST,
                "invalid_priority",
                format!("Invalid priority: '{v}'. Must be one of: low, standard, high"),
            ),
            ApiError::InvalidRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                msg,
            ),
            ApiError::InvalidRequestId(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_request_id",
                msg,
            ),
            ApiError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                msg,
            ),
            ApiError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                "not_found",
                msg,
            ),
            ApiError::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "Request body exceeds 1MB limit".to_string(),
            ),
            ApiError::RateLimited { retry_after_ms } => {
                let retry_secs = (retry_after_ms as f64 / 1000.0).ceil() as u64;
                let body = ApiErrorBody {
                    error: "rate_limited".to_string(),
                    message: "Rate limit exceeded".to_string(),
                };
                // Include retry_after_ms in a custom body
                let body_with_retry = serde_json::json!({
                    "error": body.error,
                    "message": body.message,
                    "retry_after_ms": retry_after_ms,
                });
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("Retry-After", retry_secs.to_string())],
                    axum::Json(body_with_retry),
                )
                    .into_response();
            }
            ApiError::Internal(msg) => {
                tracing::error!("Internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
                )
            }
        };

        let body = ApiErrorBody {
            error: error_code.to_string(),
            message,
        };

        (status, axum::Json(body)).into_response()
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::InvalidRequest(format!("Invalid JSON: {e}"))
    }
}

impl From<sincerin_common::errors::SincerinError> for ApiError {
    fn from(e: sincerin_common::errors::SincerinError) -> Self {
        ApiError::Internal(e.to_string())
    }
}
