use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::{MethodRouter, post};

use session_types::{Event, SessionState};

use crate::state::AppState;

use super::round::SessionRunCtx;
use super::views::{SessionProgress, prompt_view};

/// Route factory: bare `post(handler)` MethodRouter. Auth attached at
/// router level via `.layer(auth())` — see `applicant::router`.
pub(super) fn post_connect() -> MethodRouter<Arc<AppState>> {
    post(connect)
}

/// POST /api/v1/sessions/{id}/connect — applicant binds a bearer key to the
/// session and gets where it stands. A session no round has reached yet runs
/// genesis: the policy reducer is driven from a fresh `SessionState::default()`
/// (empty opaque `state`, no `current_prompt`) with `Event::Start`, and the
/// resulting state + prompt are persisted, beside the lock of the data key that
/// claims the session for this key. A different key on an already-claimed
/// session does not open that lock and is rejected with 403; recovery requires
/// `DELETE /api/v1/sessions/{id}/state` first (no auth, by design — see
/// reset.rs), or a hand-over from the device that holds it (handoff.rs).
async fn connect(ctx: SessionRunCtx) -> Result<SessionProgress, StatusCode> {
    // A started session answers with the prompt it waits on, so reopening the
    // link carries on where the applicant was instead of starting over. One that
    // has ended never reaches here: the extractor answers it (`round::extract`).
    if let Some(state) = ctx.session_state.as_ref()
        && let Some(prompt) = state.current_prompt.as_ref()
    {
        return Ok(SessionProgress::AwaitingInput {
            awaiting_seq: state.awaiting_seq,
            request: prompt_view(prompt, &ctx.locale),
        });
    }
    ctx.run(SessionState::default(), Event::Start).await
}
