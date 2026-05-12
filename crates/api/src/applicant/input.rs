use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Multipart, Path};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};

use enclavid_engine::SessionState;
use enclavid_host_bridge::{Clip, MediaRequest, call_event, suspended};

use crate::limits::APPLICANT_INPUT_BODY_LIMIT;
use crate::state::AppState;

use super::shared::SessionRunCtx;
use super::views::SessionProgress;

/// Route factory. Auth attached at router level via
/// `.layer(auth())` — see `applicant::router`.
pub(super) fn post_input() -> MethodRouter<Arc<AppState>> {
    post(input).layer(DefaultBodyLimit::max(APPLICANT_INPUT_BODY_LIMIT))
}

/// POST /session/:id/input/:slot_id — submits applicant media for the
/// suspended step.
///
/// `slot_id` shapes today:
///   * `media-N` — step `N` of the current prompt-media call's
///     `spec.captures` (multipart parts = JPEG frames, in order)
///   * `consent` — text part `accepted=true|false`
///
/// Mismatch between `slot_id` and the kind/shape of the current
/// suspension returns 409 — the desync is surfaced explicitly
/// rather than silently reinterpreting the body, which could trip
/// fraud heuristics downstream.
async fn input(
    Path((_, slot_id)): Path<(String, String)>,
    mut ctx: SessionRunCtx,
    multipart: Multipart,
) -> Result<Json<SessionProgress>, StatusCode> {
    let mut session_state = ctx.session_state.take().ok_or(StatusCode::NOT_FOUND)?;
    apply_input(&mut session_state, &slot_id, multipart).await?;
    Ok(Json(ctx.run(session_state).await?))
}

/// Attach applicant input to the currently-Suspended event's typed
/// data field, dispatched by `slot_id`. Frame counts and per-frame
/// bounds are document-specific and live in the plugin layer, not
/// here.
async fn apply_input(
    session: &mut SessionState,
    slot_id: &str,
    mut multipart: Multipart,
) -> Result<(), StatusCode> {
    let last = session.events.last_mut().ok_or(StatusCode::CONFLICT)?;
    let Some(call_event::Status::Suspended(sus)) = last.status.as_mut() else {
        return Err(StatusCode::CONFLICT);
    };
    let Some(request) = sus.request.as_mut() else {
        return Err(StatusCode::CONFLICT);
    };

    if let Some(step) = parse_media_slot(slot_id) {
        let media = expect_media(request)?;
        let total = media
            .spec
            .as_ref()
            .map(|s| s.captures.len() as u32)
            .unwrap_or(0);
        if step >= total {
            // Out-of-range step for the current spec — client is
            // addressing a slot that doesn't exist in this prompt.
            return Err(StatusCode::CONFLICT);
        }
        let frames = collect_frames(&mut multipart).await?;
        media.clips.insert(step, Clip { frames });
        return Ok(());
    }

    match slot_id {
        "consent" => {
            let suspended::Request::Consent(c) = request else {
                return Err(StatusCode::CONFLICT);
            };
            c.accepted = Some(read_consent(&mut multipart).await?);
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    Ok(())
}

/// Parse `media-N` slot ids into the step index. Returns `None` for
/// slot ids that don't follow this pattern (consent, future shapes).
fn parse_media_slot(slot_id: &str) -> Option<u32> {
    slot_id.strip_prefix("media-")?.parse().ok()
}

/// Extract the `Media` payload from the current suspension. Wrong
/// suspension kind is a 409 — the client thinks it's at a media
/// capture step but the policy is asking for something else.
fn expect_media(
    request: &mut suspended::Request,
) -> Result<&mut MediaRequest, StatusCode> {
    match request {
        suspended::Request::Media(m) => Ok(m),
        _ => Err(StatusCode::CONFLICT),
    }
}

/// Drain a multipart stream into a flat list of byte buffers, one per
/// part. Order is preserved — used for clip frames where the per-
/// part name is irrelevant (HTML's repeated `name="frame"` convention).
async fn collect_frames(
    multipart: &mut Multipart,
) -> Result<Vec<Vec<u8>>, StatusCode> {
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
async fn read_consent(
    multipart: &mut Multipart,
) -> Result<bool, StatusCode> {
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
