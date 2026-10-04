use std::sync::Arc;

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

/// POST /api/v1/sessions/{id}/connect — applicant binds a bearer key to the
/// session and gets where it stands. A session no round has reached yet runs
/// genesis: the policy reducer is driven from a fresh `SessionState::default()`
/// (empty opaque `state`, no `current_prompt`) with `Event::Start`, and the
/// resulting state + prompt are persisted. A session already started answers
/// with the prompt it is waiting on, and one already completed with its
/// decision — neither runs the policy (see `shared::standing`). A different key
/// on an already-claimed session is rejected at the auth layer with 403;
/// recovery requires `DELETE /api/v1/sessions/{id}/state` first (no auth, by
/// design — see reset.rs).
async fn connect(ctx: SessionRunCtx) -> Result<SessionProgress, ApiError> {
    if let Some(standing) = ctx.standing()? {
        return Ok(standing);
    }
    ctx.run(SessionState::default(), Event::Start).await
}
