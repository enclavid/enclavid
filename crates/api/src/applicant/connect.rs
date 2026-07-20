use std::sync::Arc;

use axum::response::Json;
use axum::routing::{MethodRouter, post};

use hatch_client::{Event, SessionState};

use crate::error::ApiError;
use crate::state::AppState;

use super::shared::SessionRunCtx;
use super::views::SessionProgress;

/// Route factory: bare `post(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth())` — see `applicant::router`.
pub(super) fn post_connect() -> MethodRouter<Arc<AppState>> {
    post(connect)
}

/// POST /session/:id/connect — applicant binds a bearer key to the
/// session and gets the first prompt. Genesis: the policy reducer is
/// driven from a fresh `SessionState::default()` (empty opaque `state`,
/// no `current_prompt`) with `Event::Start`, and the resulting state +
/// prompt are persisted. Re-issuing `/connect` re-runs genesis from
/// scratch and overwrites any persisted state for the session. A
/// different key on an already-claimed session is rejected at the auth
/// layer with 403; recovery requires `DELETE /session/:id/state` first
/// (no auth, by design — see reset.rs).
async fn connect(ctx: SessionRunCtx) -> Result<Json<SessionProgress>, ApiError> {
    Ok(Json(ctx.run(SessionState::default(), Event::Start).await?))
}
