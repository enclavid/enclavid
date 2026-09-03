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
//! so the hatch holds no session state at all and only fronts external
//! egress. What it does hold is public material it fetched on someone's
//! behalf and can refetch at any time — the issuer's JWKS, and the AMD
//! certificate endorsing this machine's chip. Replaces the former
//! `enclavid-host` gRPC server.
//!
//! Endpoints:
//!   GET    /health                (liveness only — see the route table)
//!   POST   /authorize             (AuthorizeRequest -> AuthorizeResponse | 401/403)
//!   POST   /oci/pull              (PullRequest -> PullResponse | 404)
//!   POST   /kbs/relay             (KbsRelayRequest -> KbsRelayResponse)
//!   POST   /kds/vcek              (VcekRequest -> VcekResponse | 404)

mod auth;
mod error;
mod kbs;
mod kds;
mod oci;
mod transport;

use axum::Router;
use axum::routing::{get, post};

use crate::auth::AuthState;

/// Shared handler state. `Clone` is cheap: both fields are Arc-backed.
#[derive(Clone)]
pub struct AppState {
    pub auth: AuthState,
    pub vcek: kds::VcekCache,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "host_hatch=info".into()),
        )
        .init();

    // ---- config ----
    let listen_addr = required_env("HATCH_LISTEN_ADDR")?;

    // ---- auth (HATCH_AUTH: `oidc` | `none`, required) ----
    let auth = AuthState::from_env()?;

    // ---- state ----
    let state = AppState {
        auth,
        vcek: kds::VcekCache::default(),
    };

    let app = Router::new()
        // Liveness, and deliberately nothing beyond it. What a 200 here tells
        // the asking guest is that its vsock path to this process works and
        // this process answered — and the first half is the part only the guest
        // can observe, since whatever supervises this process already knows the
        // second half better than any probe could report it.
        //
        // It must stay free of the issuer, the registry, the key broker and
        // AMD. Those are other people's uptime; reaching them from here would
        // turn a fact about one hop into a claim about theirs, and would make a
        // guest's fixed-cadence probe into fixed-cadence traffic to third
        // parties.
        .route("/health", get(health))
        .route("/authorize", post(auth::authorize))
        .route("/oci/pull", post(oci::pull))
        .route("/kbs/relay", post(kbs::relay))
        .route("/kds/vcek", post(kds::vcek))
        .with_state(state);

    tracing::info!(addr = %listen_addr, "starting hatch HTTP server");
    transport::serve(app, &listen_addr).await;
    Ok(())
}

/// See the route table for what this does and does not claim. A literal: there
/// is nothing here to compute and nothing it could depend on.
async fn health() -> &'static str {
    "ok\n"
}

pub(crate) fn required_env(name: &str) -> anyhow::Result<String> {
    use anyhow::Context;
    std::env::var(name).with_context(|| format!("env var {name} is required"))
}
