//! `hatch` — the outside-TEE companion service.
//!
//! Runs OUTSIDE the TEE on the host VM. Serves the TEE's outbound-IO
//! needs over HTTP-over-vsock: the client `Authorization` gate
//! (`HATCH_AUTH=oidc` JWKS verification, or `none` for local dev), OCI
//! registry pulls, and the KBS relay. Untrusted on content — every
//! security property is enforced TEE-side above the transport (OCI
//! digest verification, JWE-to-ephemeral-key on the KBS path).
//!
//! Durable sealed state (session KV + L2 `cwasm` cache) NO LONGER lives
//! here: it moved into the trusted RA-TLS storage-CVM (`crates/storage`),
//! so the hatch holds ZERO internal state and only fronts external
//! egress. Replaces the former `enclavid-host` gRPC server.
//!
//! Endpoints:
//!   POST   /authorize             (AuthorizeRequest -> AuthorizeResponse | 401/403)
//!   POST   /oci/pull              (PullRequest -> PullResponse | 404)
//!   POST   /kbs/relay             (KbsRelayRequest -> KbsRelayResponse)

mod auth;
mod error;
mod kbs;
mod oci;
mod transport;

use axum::Router;
use axum::routing::post;

use crate::auth::AuthState;

/// Shared handler state. `Clone` is cheap: `AuthState` is Arc-backed.
#[derive(Clone)]
pub struct AppState {
    pub auth: AuthState,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hatch=info".into()),
        )
        .init();

    // ---- config ----
    let listen_addr = required_env("HATCH_LISTEN_ADDR")?;

    // ---- auth (HATCH_AUTH: `oidc` | `none`, required) ----
    let auth = AuthState::from_env()?;

    // ---- state ----
    let state = AppState { auth };

    let app = Router::new()
        .route("/authorize", post(auth::authorize))
        .route("/oci/pull", post(oci::pull))
        .route("/kbs/relay", post(kbs::relay))
        .with_state(state);

    tracing::info!(addr = %listen_addr, "starting hatch HTTP server");
    transport::serve(app, &listen_addr).await;
    Ok(())
}

pub(crate) fn required_env(name: &str) -> anyhow::Result<String> {
    use anyhow::Context;
    std::env::var(name).with_context(|| format!("env var {name} is required"))
}
