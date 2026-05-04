use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use enclavid_host_bridge::{AuthN, AuthZ, Metadata, Replay, SessionStatus, Status, reason};

use crate::client_state::ClientState;

use super::auth::Workspace;

#[derive(Serialize)]
pub struct StatusResponse {
    pub session_id: String,
    pub status: &'static str,
}

/// Route factory: bare `get(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth(op))` — see `client::router`.
pub(super) fn get_status() -> MethodRouter<Arc<ClientState>> {
    get(status)
}

async fn status(
    State(state): State<Arc<ClientState>>,
    Workspace(workspace_id): Workspace,
    Path(session_id): Path<String>,
) -> Result<Json<StatusResponse>, StatusCode> {
    // Need both: status (to label) and metadata (to enforce workspace
    // boundary). Single Read RPC fetches both fields; missing or
    // wrong-workspace collapse to 404 to avoid leaking existence of
    // other workspaces' sessions.
    let ((status_opt, metadata_opt), _version) = state
        .session_store
        .read(&session_id, (Status, Metadata))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Metadata: AuthN cleared at decode (AEAD). AuthZ checked inline
    // — workspace_id match is the whole point of fetching metadata
    // here.
    let _metadata = metadata_opt
        .trust::<AuthZ, _, _, _>(|m| match m {
            Some(m) if m.workspace_id == workspace_id => Ok(()),
            _ => Err(StatusCode::NOT_FOUND),
        })?
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale metadata only affects which historical workspace_id we
check against. AEAD-binding to session_id ensures we're never
comparing a different session's metadata.
        "#))
        .into_inner();

    let status_value = status_opt
        .trust_unchecked::<AuthN, _>(reason!(r#"
Status here is an advisory UX label only. Actual ownership
boundary is the workspace check on metadata above — a lying
status byte just changes the label string.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Stale status returns yesterday's label string; not a security
gate.
        "#))
        .into_inner()
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(StatusResponse {
        session_id,
        status: status_label(status_value),
    }))
}

fn status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::PendingInit => "pending_init",
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Failed => "failed",
        SessionStatus::FailedInit => "failed_init",
        SessionStatus::Expired => "expired",
        SessionStatus::Unspecified => "unspecified",
    }
}
