use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct StatusResponse {
    pub initialized: bool,
    pub completed: bool,
}

/// GET /session/:id/status — public, no auth.
///
/// Frontend uses this as the first request to decide which UI flow to
/// run: claim the session via /init or supply input. Whether a session
/// exists at all leaks via 404, which is acceptable since session_ids
/// are unguessable (≥128 bits entropy).
pub async fn get_status(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<StatusResponse>, StatusCode> {
    state
        .metadata_store
        .get(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let initialized = state
        .state_store
        .exists(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(StatusResponse {
        initialized,
        completed: false,
    }))
}
