//! Hatch error → HTTP status mapping.
//!
//! Control-flow-significant outcomes ride on status codes (the
//! `hatch-client` branches on them): 401/403 for the auth deny path,
//! 404 for absent session/manifest, 412 for a write CAS conflict. The
//! response body, when present, is a UTF-8 diagnostic string — the
//! success payloads are bincode-encoded DTOs (see `hatch_protocol`).

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
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
    /// 404 — session / manifest not found.
    NotFound,
    /// 412 — write `expected_version` precondition failed (CAS).
    VersionMismatch,
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
            HatchError::VersionMismatch => StatusCode::PRECONDITION_FAILED.into_response(),
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
