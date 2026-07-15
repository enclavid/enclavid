//! L2 compiled-artifact (`cwasm`) cache — a dumb, content-agnostic blob
//! store fronted by [`object_store`].
//!
//! `POST /cache/{key}` writes the (sealed, opaque) body under `key`;
//! `GET /cache/{key}` reads it back (or 404). The broker never
//! interprets the bytes — the TEE seals them under a key only the
//! enclave holds and reconstructs the compiled component on read. Every
//! cache property (confidentiality, integrity, staleness, format
//! compatibility) is enforced TEE-side above this transport; the broker
//! only moves opaque blobs.
//!
//! Backend is an [`ObjectStore`]: today a local filesystem (per-instance
//! disk that survives a TEE / broker restart, so a cold start re-uses
//! the compile instead of re-pulling + re-running Cranelift), swappable
//! to S3/GCS for a shared fleet cache by config alone — a fleet cache
//! additionally needs a fleet-wide TEE-only seal key (KBS), out of scope
//! here. Torn / partial writes are self-correcting: a reader that gets
//! an incomplete blob fails the AEAD check TEE-side and treats it as a
//! miss.
//!
//! `key` is a hex label computed in the TEE
//! (`broker-client::CacheStore`), so it is pure lowercase hex — validated
//! here as a path-traversal guard so a host-supplied segment can never
//! escape the store prefix.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use object_store::{ObjectStore, path::Path as ObjPath};

use crate::AppState;
use crate::error::BrokerError;

/// Max accepted key length — a hex SHA-256-sized label is 64 chars;
/// allow headroom without permitting an unbounded name.
const MAX_KEY_LEN: usize = 128;

/// Validate `key` is non-empty bounded hex and map it to an object path.
/// The accepted alphabet excludes `/`, `.` and `\`, so the location
/// cannot traverse out of the store's prefix — no `..`, no nested
/// segment, no absolute path.
fn object_path(key: &str) -> Result<ObjPath, BrokerError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return Err(BrokerError::BadRequest("cache key length".to_string()));
    }
    if !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BrokerError::BadRequest(
            "cache key must be hex (path-traversal guard)".to_string(),
        ));
    }
    Ok(ObjPath::from(key))
}

/// `POST /cache/{key}` — store the (sealed, opaque) body under `key`.
/// Overwrites any existing blob; the key is content-addressed TEE-side,
/// so a re-write is either identical bytes or a fresh compile replacing
/// a stale one.
pub async fn store(
    State(state): State<AppState>,
    AxumPath(key): AxumPath<String>,
    body: Bytes,
) -> Result<StatusCode, BrokerError> {
    let path = object_path(&key)?;
    state
        .cache_store
        .put(&path, body.into())
        .await
        .map_err(|e| BrokerError::Internal(format!("cache write: {e}")))?;
    Ok(StatusCode::OK)
}

/// `GET /cache/{key}` — return the stored bytes, or 404 if absent.
pub async fn load(
    State(state): State<AppState>,
    AxumPath(key): AxumPath<String>,
) -> Result<Response, BrokerError> {
    let path = object_path(&key)?;
    match state.cache_store.get(&path).await {
        Ok(res) => {
            let bytes = res
                .bytes()
                .await
                .map_err(|e| BrokerError::Internal(format!("cache read: {e}")))?;
            Ok((StatusCode::OK, bytes).into_response())
        }
        Err(object_store::Error::NotFound { .. }) => Err(BrokerError::NotFound),
        Err(e) => Err(BrokerError::Internal(format!("cache get: {e}"))),
    }
}

/// Alias for the object-store handle stored in [`AppState`]. Behind the
/// trait so the backend (local FS today, S3 later) is a construction
/// detail invisible to the handlers.
pub type CacheBackend = Arc<dyn ObjectStore>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_and_non_hex() {
        assert!(object_path("deadbeef00").is_ok());
        // Uppercase hex is a safe (traversal-free) filename too; the TEE
        // emits lowercase.
        assert!(object_path("ABCDEF").is_ok());
        // Traversal / separators / dotfiles / non-hex rejected before
        // touching the store.
        assert!(object_path("../etc/passwd").is_err());
        assert!(object_path("a/b").is_err());
        assert!(object_path("..").is_err());
        assert!(object_path("a.b").is_err());
        assert!(object_path("beefg0").is_err());
        assert!(object_path("dead-beef").is_err());
        assert!(object_path("").is_err());
        assert!(object_path(&"a".repeat(MAX_KEY_LEN + 1)).is_err());
    }
}
