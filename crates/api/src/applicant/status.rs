use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use enclavid_host_bridge::{AuthN, Replay, SessionStatus, Status, reason};

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
    // Single Read on the plaintext status sidecar. Host can lie about
    // status — we accept it as an advisory UX hint (decryption on
    // /connect is the actual ownership check). 404 if no status record
    // exists at all.
    let ((status_opt,), _version) = state
        .session_store
        .read(&session_id, (Status,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let session_status = status_opt
        .trust_unchecked::<AuthN, _>(reason!(r#"
Advisory UX hint only. The actual ownership boundary in the
applicant flow is AEAD-decryption of state via applicant_key on
/connect — wrong key, no progress.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale status returns yesterday's label string; not a security
gate.
        "#))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(StatusResponse {
        initialized: matches!(
            session_status,
            SessionStatus::Running | SessionStatus::Completed
        ),
        completed: session_status == SessionStatus::Completed,
    }))
}
