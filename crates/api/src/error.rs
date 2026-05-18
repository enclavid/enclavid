//! Handler error type that carries either a bare HTTP status or a
//! status + JSON body.
//!
//! Existing handler code returns `StatusCode` directly for the vast
//! majority of failures (network/store/wiring errors that have no
//! useful per-error payload). A handful of cases — primarily policy
//! traps surfaced to the API consumer — benefit from a structured
//! body so the consumer / frontend can render a specific message
//! instead of a generic "internal error". This enum + `IntoResponse`
//! covers both shapes with one return type, and `From<StatusCode>`
//! keeps `?` ergonomics intact for the StatusCode-returning helper
//! functions that handlers chain.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub enum ApiError {
    Status(StatusCode),
    StatusWithBody(StatusCode, serde_json::Value),
}

impl From<StatusCode> for ApiError {
    fn from(s: StatusCode) -> Self {
        ApiError::Status(s)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Status(s) => s.into_response(),
            ApiError::StatusWithBody(s, v) => (s, Json(v)).into_response(),
        }
    }
}

impl ApiError {
    /// Convenience for callers building JSON-body error responses
    /// inline (the common shape: status + serde_json::json! body).
    pub fn with_body(status: StatusCode, body: serde_json::Value) -> Self {
        ApiError::StatusWithBody(status, body)
    }
}
