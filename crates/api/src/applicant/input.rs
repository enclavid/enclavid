use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Multipart, Path};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};

use hatch_client::{Clip, Event, MediaResult, Prompt, SessionState};

use crate::error::ApiError;
use crate::limits::APPLICANT_INPUT_BODY_LIMIT;
use crate::state::AppState;

use super::shared::SessionRunCtx;
use super::views::SessionProgress;

/// Route factory. Auth attached at router level via
/// `.layer(auth())` — see `applicant::router`.
pub(super) fn post_input() -> MethodRouter<Arc<AppState>> {
    post(input).layer(DefaultBodyLimit::max(APPLICANT_INPUT_BODY_LIMIT))
}

/// POST /session/:id/input/:slot_id — submits applicant input for the
/// prompt the session is currently awaiting.
///
/// `slot_id` shapes:
///   * `media-N` — capture-step `N` of the current `Prompt::Media`'s
///     `captures` (multipart parts = JPEG frames, in order); builds an
///     [`Event::Media`].
///   * `consent` — text part `accepted=true|false`; builds an
///     [`Event::ConsentDisclosure`].
///
/// The `slot_id` must match the kind/shape of the prompt persisted as
/// `current_prompt`. A mismatch returns 409 (kind/shape desync) or 400
/// (unknown slot id) — the desync is surfaced explicitly rather than
/// silently reinterpreting the body, which could trip fraud heuristics
/// downstream.
async fn input(
    Path((session_id, slot_id)): Path<(String, String)>,
    mut ctx: SessionRunCtx,
    multipart: Multipart,
) -> Result<Json<SessionProgress>, ApiError> {
    let session_state = ctx.session_state.take().ok_or_else(|| {
        // /input fires with the assumption that /connect already
        // persisted at least one rendered prompt. If state is None
        // here, either /connect never reached this far (frontend
        // bug — going to /input without /connect succeeding) or
        // /connect ran but the listener silently failed to persist
        // (engine bug). 409 (not 404): the session itself exists
        // (auth passed), but its engine state isn't initialised —
        // a precondition failure, consistent with the
        // wrong-prompt-shape branches in `build_event`. Log enough to
        // disambiguate either cause.
        eprintln!(
            "/input/{slot_id}: session_state missing for {session_id} — \
             /connect either never ran or its persistence step did \
             not commit before this /input arrived",
        );
        StatusCode::CONFLICT
    })?;
    let event = build_event(&session_state, &slot_id, multipart).await?;
    Ok(Json(ctx.run(session_state, event).await?))
}

/// Build the inbound [`Event`] from the applicant's `/input`, validated
/// against the prompt the session is awaiting (`current_prompt`). The
/// `slot_id` selects the input kind; it MUST match the kind of the
/// current prompt — otherwise the desync is a 409 (or 400 for an
/// unrecognised slot id). Frame counts and per-frame bounds are
/// document-specific and live in the plugin layer, not here.
async fn build_event(
    session: &SessionState,
    slot_id: &str,
    multipart: Multipart,
) -> Result<Event, StatusCode> {
    let prompt = session.current_prompt.as_ref().ok_or(StatusCode::CONFLICT)?;

    if let Some(step) = parse_media_slot(slot_id) {
        let Prompt::Media(spec) = prompt else {
            // Client is at a media capture step but the policy is
            // awaiting something else.
            return Err(StatusCode::CONFLICT);
        };
        let total = spec.captures.len() as u32;
        if step >= total {
            // Out-of-range step for the current spec — client is
            // addressing a capture step that doesn't exist in this
            // prompt.
            return Err(StatusCode::CONFLICT);
        }
        let frames = collect_frames(multipart).await?;
        return Ok(Event::Media(MediaResult {
            slot: step,
            clip: Clip { frames },
        }));
    }

    match slot_id {
        "consent" => {
            let Prompt::ConsentDisclosure(_) = prompt else {
                return Err(StatusCode::CONFLICT);
            };
            let accepted = read_consent(multipart).await?;
            Ok(Event::ConsentDisclosure(accepted))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

/// Parse `media-N` slot ids into the step index. Returns `None` for
/// slot ids that don't follow this pattern (consent, future shapes).
fn parse_media_slot(slot_id: &str) -> Option<u32> {
    slot_id.strip_prefix("media-")?.parse().ok()
}

/// Drain a multipart stream into a flat list of byte buffers, one per
/// part. Order is preserved — used for clip frames where the per-
/// part name is irrelevant (HTML's repeated `name="frame"` convention).
async fn collect_frames(mut multipart: Multipart) -> Result<Vec<Vec<u8>>, StatusCode> {
    let mut frames = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let bytes = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
        frames.push(bytes.to_vec());
    }
    Ok(frames)
}

/// Pull a single `accepted=true|false` text part from a consent
/// multipart payload. Anything else is a malformed body.
async fn read_consent(mut multipart: Multipart) -> Result<bool, StatusCode> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        if field.name() == Some("accepted") {
            let text = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            return Ok(matches!(text.as_str(), "true" | "1"));
        }
    }
    Err(StatusCode::BAD_REQUEST)
}
