use std::sync::Arc;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, post};

use session_types::Prompt;

use crate::state::AppState;

use super::input::moved_on;
use super::round::SessionRunCtx;

/// Route factory. Auth attached at router level via `.layer(auth())` — see
/// `applicant::router`.
pub(super) fn post_start() -> MethodRouter<Arc<AppState>> {
    post(start)
}

/// POST /api/v1/sessions/{id}/start/{awaiting_seq} — the page starts the media
/// prompt the session awaits, as it opens the camera for its steps. The first
/// start of a wait writes its time before it answers; a later one, after a
/// reload, keeps it. The answer is the wait as `/connect` gives it: a prompt
/// with a time limit now with its steps whole and the time left.
///
/// The page starts every media prompt, with a limit or not, so whether a
/// prompt is timed, which its policy chose, is not told by whether a start is
/// written.
async fn start(
    Path((_session_id, awaiting_seq)): Path<(String, u64)>,
    mut ctx: SessionRunCtx,
) -> Response {
    let Some(session_state) = ctx.session_state.take() else {
        return StatusCode::CONFLICT.into_response();
    };
    if awaiting_seq != session_state.awaiting_seq {
        return moved_on(&session_state, &ctx);
    }
    if !matches!(session_state.current_prompt, Some(Prompt::Media(_))) {
        return StatusCode::CONFLICT.into_response();
    }
    match ctx.keep_start(session_state).await {
        Ok(progress) => progress.into_response(),
        Err(status) => status.into_response(),
    }
}
