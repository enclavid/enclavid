use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};

use crate::state::AppState;

use super::shared::SessionRunCtx;
use super::views::SessionProgress;

/// Route factory: bare `post(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth())` — see `applicant::router`.
pub(super) fn post_connect() -> MethodRouter<Arc<AppState>> {
    post(connect)
}

/// POST /session/:id/connect — applicant binds a bearer key to the
/// session and gets the current progress. Idempotent: first call
/// initializes state and runs the policy from scratch; subsequent
/// calls with the same key replay existing state and return the same
/// suspension point (cheap — replay path skips host calls). A
/// different key on an already-claimed session is rejected at the
/// auth layer with 403; recovery requires `DELETE /session/:id/state`
/// first (no auth, by design — see reset.rs).
async fn connect(mut ctx: SessionRunCtx) -> Result<Json<SessionProgress>, StatusCode> {
    // No persisted state means a brand-new session — start from a
    // default-initialised SessionState. (input.rs treats the same
    // case as 404; that divergence is the only logic split between
    // the two handlers.)
    let session_state = ctx.session_state.take().unwrap_or_default();
    Ok(Json(ctx.run(session_state).await?))
}
