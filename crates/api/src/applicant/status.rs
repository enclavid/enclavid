use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct StatusResponse {
    pub initialized: bool,
    pub completed: bool,
}

/// Route factory. Public (no auth layer) — see `applicant::router`.
pub(super) fn get_status() -> MethodRouter<Arc<AppState>> {
    get(status)
}

/// GET /session/:id/status — public, no auth.
///
/// Frontend uses this as the first request to decide which UI flow to
/// run: claim the session via /connect (first time) or connect + supply
/// input (returning visit). Whether a session exists at all leaks via
/// 404, which is acceptable since session_ids are unguessable (≥128
/// bits entropy).
async fn status(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<StatusResponse>, StatusCode> {
    // Existence-only probe: only the discriminator matters. We accept
    // the host's claim (UX hint, decryption on /connect is the real
    // boundary) and bail with 404 if it says no record.
    state
        .metadata_store
        .get(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .trust_unchecked()
        .ok_or(StatusCode::NOT_FOUND)?;

    // Advisory UI hint, not a security boundary. A lying host (claims
    // true when no blob exists, or vice versa) only causes UX confusion:
    // any branch funnels into /connect, where decryption is the actual
    // ownership check. `trust_unchecked` documents the delegation.
    let initialized = state
        .state_store
        .exists(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .trust_unchecked();

    Ok(Json(StatusResponse {
        initialized,
        completed: false,
    }))
}
