use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

/// Inserted into request extensions after successful auth.
/// Handlers can extract this to know which API key was used.
#[derive(Debug, Clone)]
pub struct ApiKeyId(pub String);

/// Query params that may contain an api_key (for WebSocket).
#[derive(Deserialize)]
struct ApiKeyQuery {
    api_key: Option<String>,
}

/// Auth rejection type.
pub struct AuthRejection {
    message: String,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": "unauthorized",
            "message": self.message,
        });
        (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
    }
}

/// Axum extractor that validates API keys from header or query param.
///
/// Checks `X-API-Key` header first, then `?api_key=` query param.
/// Inserts `ApiKeyId` into request extensions on success.
impl<S> FromRequestParts<S> for ApiKeyId
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get valid keys from extensions (set by middleware layer)
        let valid_keys = parts
            .extensions
            .get::<Arc<HashSet<String>>>()
            .cloned()
            .unwrap_or_default();

        // Try X-API-Key header first
        let key = parts
            .headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Fall back to query param
        let key = match key {
            Some(k) => Some(k),
            None => {
                let query = parts.uri.query().unwrap_or("");
                let params: Result<ApiKeyQuery, _> =
                    serde_urlencoded::from_str(query);
                params.ok().and_then(|q| q.api_key)
            }
        };

        match key {
            None => Err(AuthRejection {
                message: "API key required. Provide via X-API-Key header or api_key query parameter.".to_string(),
            }),
            Some(ref k) if k.is_empty() => Err(AuthRejection {
                message: "API key required. Provide via X-API-Key header or api_key query parameter.".to_string(),
            }),
            Some(ref k) if !valid_keys.contains(k.as_str()) => Err(AuthRejection {
                message: "Invalid API key".to_string(),
            }),
            Some(k) => Ok(ApiKeyId(k)),
        }
    }
}
