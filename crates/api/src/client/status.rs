use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use enclavid_session_store::SessionStatus;

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
    // Trust gate: session only visible to its own workspace. NOT_FOUND
    // (not 403) so we don't leak existence of other workspaces' sessions.
    let metadata = state
        .metadata_store
        .get(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?
        .trust(|m| {
            if m.workspace_id == workspace_id {
                Ok(())
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        })?;

    Ok(Json(StatusResponse {
        session_id,
        status: status_label(metadata.status),
    }))
}

fn status_label(status: i32) -> &'static str {
    match SessionStatus::try_from(status).unwrap_or(SessionStatus::Unspecified) {
        SessionStatus::PendingInit => "pending_init",
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Failed => "failed",
        SessionStatus::FailedInit => "failed_init",
        SessionStatus::Expired => "expired",
        SessionStatus::Unspecified => "unspecified",
    }
}
