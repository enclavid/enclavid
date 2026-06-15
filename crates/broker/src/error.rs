//! Broker error → HTTP status mapping.
//!
//! Control-flow-significant outcomes ride on status codes (the
//! `broker-client` branches on them): 401/403 for the auth deny path,
//! 404 for absent session/manifest, 412 for a write CAS conflict. The
//! response body, when present, is a UTF-8 diagnostic string — the
//! success payloads are bincode-encoded DTOs (see `broker_protocol`).

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug)]
pub enum BrokerError {
    /// 400 — malformed request body / unsupported ref or auth scheme.
    BadRequest(String),
    /// 401 — missing / invalid credential.
    Unauthorized,
    /// 403 — credential valid but not permitted (or no org binding).
    Forbidden,
    /// 404 — session / manifest not found.
    NotFound,
    /// 412 — write `expected_version` precondition failed (CAS).
    VersionMismatch,
    /// 500 — internal / upstream failure.
    Internal(String),
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        match self {
            BrokerError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            BrokerError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            BrokerError::Forbidden => StatusCode::FORBIDDEN.into_response(),
            BrokerError::NotFound => StatusCode::NOT_FOUND.into_response(),
            BrokerError::VersionMismatch => StatusCode::PRECONDITION_FAILED.into_response(),
            BrokerError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m).into_response(),
        }
    }
}

/// Decode a bincode request body into a wire DTO; malformed → 400.
pub fn decode_body<T: DeserializeOwned>(body: &Bytes) -> Result<T, BrokerError> {
    broker_protocol::decode(body.as_ref()).map_err(|e| BrokerError::BadRequest(e.to_string()))
}

/// Encode a wire DTO to a bincode response body; failure → 500.
pub fn encode_body<T: Serialize>(value: &T) -> Result<Vec<u8>, BrokerError> {
    broker_protocol::encode(value).map_err(|e| BrokerError::Internal(e.to_string()))
}
