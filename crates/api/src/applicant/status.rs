use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use enclavid_host_bridge::{AuthZ, Metadata, Replay, SessionStatus, reason};

use crate::dto;
use crate::state::AppState;

#[derive(Serialize)]
pub struct StatusResponse {
    /// Lifecycle label — same wire shape as the client API's
    /// `GET /sessions/:id` so frontends can switch on the same
    /// strings ("running" / "completed" / "failed" / "expired").
    /// Renders via the shared `dto::SessionStatusDef` remote.
    #[serde(with = "dto::SessionStatusDef")]
    pub status: SessionStatus,
}

/// Route factory. Public (no auth layer) — see `applicant::router`.
pub(super) fn get_status() -> MethodRouter<Arc<AppState>> {
    get(status)
}

/// GET /session/:id/status — public, no auth.
///
/// Frontend uses this as the first request to decide which UI flow
/// to run (continue running session / show "done" / show "ended").
/// We read the encrypted metadata (AEAD-bound to session_id) and
/// surface its `status` field — the host-plaintext `BlobField::Status`
/// is a TTL hint only and a lying host can flip it freely, so we
/// ignore it for any applicant-visible decision.
async fn status(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let ((metadata_opt,), _version) = state
        .session_store
        .read(&session_id, (Metadata,))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Applicant flow has no tenant_id in scope — security here
    // relies on the bearer-key auth layer at routes that mutate
    // state, plus AEAD-binding on session_id. /status itself is
    // public; we just need to know whether a session exists for
    // this id.
    let metadata = metadata_opt
        .trust_unchecked::<AuthZ, _>(reason!(r#"
Applicant flow doesn't authenticate per-tenant — /status is
public, used by the frontend on first page load before the
applicant has any credential. Existence of the session_id is
acceptable to leak (32-byte random, ≥128 bits entropy).
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale metadata might return an older status (e.g. show
"running" when session has since completed). Worst case is the
applicant frontend renders an old UI and the next /connect
fixes it via fresh state read. Not a security gate.
        "#))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)?;

    let status = SessionStatus::try_from(metadata.status)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(StatusResponse { status }))
}
