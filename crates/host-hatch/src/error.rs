//! Hatch error → HTTP status mapping.
//!
//! Control-flow-significant outcomes ride on status codes (the
//! `hatch-client` branches on them): 401/403/429 for the auth deny path,
//! 404 for an absent OCI manifest. The response body, when present, is
//! a UTF-8 diagnostic string, except a 429's, which says when to ask again —
//! that and the success payloads are CBOR-encoded DTOs (see
//! `hatch_protocol`).

use std::time::Duration;

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hatch_protocol::RateLimited;
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug)]
pub enum HatchError {
    /// 400 — malformed request body / unsupported ref or auth scheme.
    BadRequest(String),
    /// 401 — missing / invalid credential.
    Unauthorized,
    /// 403 — credential valid but not permitted (or no org binding).
    Forbidden,
    /// 404 — OCI manifest not found.
    NotFound,
    /// 429 — the principal is over its rate limit for the operation; it may
    /// retry after this long.
    RateLimited(Duration),
    /// 500 — internal / upstream failure.
    Internal(String),
}

impl IntoResponse for HatchError {
    fn into_response(self) -> Response {
        match self {
            HatchError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            HatchError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            HatchError::Forbidden => StatusCode::FORBIDDEN.into_response(),
            HatchError::NotFound => StatusCode::NOT_FOUND.into_response(),
            HatchError::RateLimited(wait) => {
                // Rounded up, never to zero: a retry before `wait` is refused.
                let retry_after_secs = u32::try_from(wait.as_secs() + 1).unwrap_or(u32::MAX);
                match encode_body(&RateLimited { retry_after_secs }) {
                    Ok(body) => (StatusCode::TOO_MANY_REQUESTS, body).into_response(),
                    Err(e) => e.into_response(),
                }
            }
            HatchError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m).into_response(),
        }
    }
}

/// Decode a bincode request body into a wire DTO; malformed → 400.
pub fn decode_body<T: DeserializeOwned>(body: &Bytes) -> Result<T, HatchError> {
    hatch_protocol::decode(body.as_ref()).map_err(|e| HatchError::BadRequest(e.to_string()))
}

/// Encode a wire DTO to a bincode response body; failure → 500.
pub fn encode_body<T: Serialize>(value: &T) -> Result<Vec<u8>, HatchError> {
    hatch_protocol::encode(value).map_err(|e| HatchError::Internal(e.to_string()))
}
