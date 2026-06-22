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

mod auth;
mod error;
mod kbs;
mod oci;
mod sessions;
mod transport;

use anyhow::Context;
use axum::Router;
use axum::routing::{delete, head, post};
use redis::aio::ConnectionManager;

use crate::auth::AuthState;

/// Shared handler state. `Clone` is cheap: `ConnectionManager` and
/// `AuthState` are both Arc-backed.
#[derive(Clone)]
pub struct AppState {
    pub redis: ConnectionManager,
    pub auth: AuthState,
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

    // ---- auth (BROKER_AUTH: `oidc` | `none`, required) ----
    let auth = AuthState::from_env()?;

    // ---- redis ----
    let client = redis::Client::open(redis_url.as_str())
        .with_context(|| format!("redis client at {redis_url}"))?;
    let redis = ConnectionManager::new(client)
        .await
        .context("redis connection manager")?;

    // ---- state ----
    let state = AppState { redis, auth };

    let app = Router::new()
        .route("/sessions/{id}/read", post(sessions::read))
        .route("/sessions/{id}/write", post(sessions::write))
        .route("/sessions/{id}/state", delete(sessions::delete_state))
        .route("/sessions/{id}", head(sessions::exists))
        .route("/authorize", post(auth::authorize))
        .route("/oci/pull", post(oci::pull))
        .route("/kbs/relay", post(kbs::relay))
        .with_state(state);

    tracing::info!(addr = %listen_addr, "starting broker HTTP server");
    transport::serve(app, &listen_addr).await;
    Ok(())
}

pub(crate) fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("env var {name} is required"))
}
