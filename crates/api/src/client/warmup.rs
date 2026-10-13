//! `POST /api/v1/warmup` — have a composition compiled and kept before any
//! session asks for it.
//!
//! The body is what a session pins: the policy, its plugins, their keys, the
//! registry bearers — the same fields, held to the same checks, as
//! `POST /api/v1/sessions`. The answer is `202 Accepted` as soon as the pins are
//! valid; the compile runs after it, and a composition already kept, or already
//! being compiled, is not compiled again. Nothing is answered about how it went:
//! a session pinning the same composition meets any failure at its own first
//! round, as it would without a warmup.
//!
//! Authorized as a session creation is: it spends what creating a session with
//! these pins would — one compile — and nothing a creation does not.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use serde::Deserialize;

use crate::client_state::ClientState;

use super::auth::Principal;
use super::create::{KeyRequest, PluginRequest, pins};

/// The pins of a composition, as `POST /api/v1/sessions` takes them.
#[derive(Deserialize)]
pub struct WarmupRequest {
    /// Full pinned OCI reference for the policy artifact,
    /// `<registry>/<repository>@sha256:<hex>`.
    pub policy: String,
    /// Per-hostname registry bearer map, as for a session.
    #[serde(default)]
    pub registry_auth: BTreeMap<String, String>,
    /// Plugin pins, in composition order.
    #[serde(default)]
    pub plugins: Vec<PluginRequest>,
    /// The policy artifact's decryption key. Omit ⇒ not encrypted.
    #[serde(default)]
    pub policy_key: Option<KeyRequest>,
}

/// Route factory: bare `post(handler)` MethodRouter. Auth is attached at the
/// router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn post_warmup() -> MethodRouter<Arc<ClientState>> {
    post(warmup)
}

async fn warmup(
    State(state): State<Arc<ClientState>>,
    Principal(principal): Principal,
    headers: HeaderMap,
    Json(body): Json<WarmupRequest>,
) -> Result<StatusCode, StatusCode> {
    let pins = pins(
        body.policy,
        body.plugins,
        body.registry_auth,
        body.policy_key,
        &headers,
    )?;
    let composition = pins.composition(principal.as_deref());
    let compositions = state.compositions.clone();
    tokio::spawn(async move { compositions.warm(composition).await });
    Ok(StatusCode::ACCEPTED)
}
