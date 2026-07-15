//! `broker` — the outside-TEE companion service.
//!
//! Runs OUTSIDE the TEE on the host VM. Serves the TEE's storage and
//! outbound-IO needs over HTTP-over-vsock: session state (Redis), the
//! client `Authorization` gate (`BROKER_AUTH=oidc` JWKS verification, or
//! `none` for local dev), and OCI registry pulls. Untrusted on content —
//! every security property is enforced
//! TEE-side above the transport (AEAD-sealed metadata, OCI digest
//! verification). Replaces the former `enclavid-host` gRPC server.
//!
//! Endpoints:
//!   POST   /sessions/{id}/read    (ReadRequest  -> ReadResponse)
//!   POST   /sessions/{id}/write   (WriteRequest -> WriteResponse | 412)
//!   DELETE /sessions/{id}/state   (-> DeleteResponse)   [/reset]
//!   HEAD   /sessions/{id}         (-> 200 | 404)         [exists]
//!   POST   /authorize             (AuthorizeRequest -> AuthorizeResponse | 401/403)
//!   POST   /oci/pull              (PullRequest -> PullResponse | 404)
//!   POST   /kbs/relay             (KbsRelayRequest -> KbsRelayResponse)
//!   POST   /cache/{key}           (sealed cwasm bytes -> 200)     [L2 store]
//!   GET    /cache/{key}           (-> 200 sealed bytes | 404)     [L2 load]

mod auth;
mod cache;
mod error;
mod kbs;
mod oci;
mod sessions;
mod transport;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, head, post};
use object_store::local::LocalFileSystem;
use redis::aio::ConnectionManager;

use crate::auth::AuthState;
use crate::cache::CacheBackend;

/// Request-body cap for the broker. Axum defaults to 2 MB, but a
/// `/sessions/{id}/write` body co-commits the sealed session STATE with the
/// round's captured media blobs (one sealed frame per capture, `Op::MediaWrite`
/// into `session:{id}:media`) — easily past 2 MB. This is a host-side DoS
/// guard, NOT a trust boundary: the TEE already bounds what it writes via the
/// attested per-input limit (`api::limits::APPLICANT_INPUT_BODY_LIMIT`, 16 MB),
/// so the host can't make the TEE write more. Sized for a realistic
/// multi-capture session.
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Shared handler state. `Clone` is cheap: `ConnectionManager` and
/// `AuthState` are both Arc-backed.
#[derive(Clone)]
pub struct AppState {
    pub redis: ConnectionManager,
    pub auth: AuthState,
    /// Blob backend for the L2 `cwasm` cache (`/cache/{key}`). Local
    /// filesystem today, swappable to S3/GCS by config; opaque sealed
    /// blobs written/read by key. See [`cache`].
    pub cache_store: CacheBackend,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "broker=info".into()),
        )
        .init();

    // ---- config ----
    let listen_addr = required_env("BROKER_LISTEN_ADDR")?;
    let redis_url = required_env("BROKER_REDIS_URL")?;
    // L2 cwasm-cache directory (required, fail-fast — no silent default).
    // Created if absent so a fresh host boots clean, then rooted as a
    // local `ObjectStore` (the future S3/GCS swap replaces only this
    // construction; the `/cache` handlers speak the `ObjectStore` trait).
    let cache_dir = PathBuf::from(required_env("BROKER_CACHE_DIR")?);
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("create cache dir {}", cache_dir.display()))?;
    let cache_store: CacheBackend = Arc::new(
        LocalFileSystem::new_with_prefix(&cache_dir)
            .with_context(|| format!("open cache store at {}", cache_dir.display()))?,
    );

    // ---- auth (BROKER_AUTH: `oidc` | `none`, required) ----
    let auth = AuthState::from_env()?;

    // ---- redis ----
    let client = redis::Client::open(redis_url.as_str())
        .with_context(|| format!("redis client at {redis_url}"))?;
    let redis = ConnectionManager::new(client)
        .await
        .context("redis connection manager")?;

    // ---- state ----
    let state = AppState { redis, auth, cache_store };

    let app = Router::new()
        .route("/sessions/{id}/read", post(sessions::read))
        .route("/sessions/{id}/write", post(sessions::write))
        .route("/sessions/{id}/state", delete(sessions::delete_state))
        .route("/sessions/{id}", head(sessions::exists))
        .route("/authorize", post(auth::authorize))
        .route("/oci/pull", post(oci::pull))
        .route("/kbs/relay", post(kbs::relay))
        .route("/cache/{key}", post(cache::store).get(cache::load))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state);

    tracing::info!(addr = %listen_addr, "starting broker HTTP server");
    transport::serve(app, &listen_addr).await;
    Ok(())
}

pub(crate) fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("env var {name} is required"))
}
