use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Multipart, Path};
use axum::http::StatusCode;
use axum::routing::{MethodRouter, post};

use session_types::{
    Clip, Event, MAX_CLIP_BYTES, MAX_CLIP_FRAMES, MediaResult, Prompt, SessionState,
};

use crate::limits::APPLICANT_INPUT_BODY_LIMIT;
use crate::state::AppState;

use super::consent;
use super::round::SessionRunCtx;
use super::views::SessionProgress;

/// Route factory. Auth attached at router level via
/// `.layer(auth())` — see `applicant::router`.
pub(super) fn post_input() -> MethodRouter<Arc<AppState>> {
    post(input).layer(DefaultBodyLimit::max(APPLICANT_INPUT_BODY_LIMIT))
}

/// POST /api/v1/sessions/{id}/input/{slot_id} — submits applicant input for the
/// prompt the session is currently awaiting.
///
/// `slot_id` shapes:
///   * `media-N` — capture-step `N` of the current `Prompt::Media`'s
///     `captures` (multipart parts = JPEG frames, in order); builds an
///     [`Event::Media`].
///   * `consent` — text part `accepted=true|false` plus a `disclosure_hash`
///     (the host-minted digest of the screen the applicant confirmed); builds
///     an [`Event::ConsentDisclosure`]. On accept the digest must match the
///     current disclosure or the round is refused (409) — show == seal.
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
) -> Result<SessionProgress, StatusCode> {
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
        safe_logger::debug!(
            "/input/{slot_id}: session_state missing for {session_id} — \
             /connect either never ran or its persistence step did \
             not commit before this /input arrived",
        );
        StatusCode::CONFLICT
    })?;
    let event = build_event(&session_state, &slot_id, multipart).await?;
    ctx.run(session_state, event).await
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
    let prompt = session
        .current_prompt
        .as_ref()
        .ok_or(StatusCode::CONFLICT)?;

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
            let Prompt::ConsentDisclosure(d) = prompt else {
                return Err(StatusCode::CONFLICT);
            };
            let (accepted, submitted_digest) = read_consent(multipart).await?;
            consent::authorize(d, accepted, submitted_digest.as_deref())?;
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
///
/// The same two bounds the worker's `Clip` decoder enforces, applied here as
/// well, and the duplication is the point rather than an oversight. This side can
/// answer the applicant's browser with a 413; the worker can only refuse the
/// round, which reaches the applicant as a failed session. So the cap belongs
/// where the good error is, and it belongs at the worker too because the worker
/// accepts any attested guest and cannot assume its caller ran this code.
///
/// The COUNT bound is the load-bearing one. `APPLICANT_INPUT_BODY_LIMIT` says
/// almost nothing about it: an empty multipart part costs only its framing, so a
/// body at the cap is hundreds of thousands of frames.
///
/// A body past `APPLICANT_INPUT_BODY_LIMIT` surfaces as a multipart error, and
/// `MultipartError::status` is what keeps it a 413 rather than a 400.
///
/// The aggregate is redundant today, and knowingly. The body limit counts framing
/// too, so the payload bytes it admits are strictly fewer than the body it caps,
/// and `crate::limits` asserts at compile time that the body cap does not exceed
/// the clip budget — together those make the branch below unreachable. It stays
/// because it does not depend on this route keeping its `DefaultBodyLimit` layer,
/// and because the worker's decoder enforces the same pair regardless.
async fn collect_frames(mut multipart: Multipart) -> Result<Vec<Vec<u8>>, StatusCode> {
    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;
    while let Some(field) = multipart.next_field().await.map_err(|e| e.status())? {
        if frames.len() == MAX_CLIP_FRAMES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let bytes = field.bytes().await.map_err(|e| e.status())?;
        total = total.saturating_add(bytes.len());
        if total > MAX_CLIP_BYTES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        frames.push(bytes.to_vec());
    }
    Ok(frames)
}

/// Pull the consent answer from a consent multipart payload: the required
/// `accepted=true|false` flag and the optional `disclosure_hash` — the hex
/// digest of the disclosure screen the applicant confirmed, echoed back so
/// `build_event` can bind an ACCEPT to exactly that screen (show == seal).
/// Returns `(accepted, disclosure_hash)`; a body with no `accepted` part is
/// malformed (400).
async fn read_consent(mut multipart: Multipart) -> Result<(bool, Option<String>), StatusCode> {
    let mut accepted: Option<bool> = None;
    let mut disclosure_hash: Option<String> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        match field.name() {
            Some("accepted") => {
                let text = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                accepted = Some(matches!(text.as_str(), "true" | "1"));
            }
            Some("disclosure_hash") => {
                disclosure_hash = Some(field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            _ => {}
        }
    }
    Ok((accepted.ok_or(StatusCode::BAD_REQUEST)?, disclosure_hash))
}
