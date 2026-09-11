use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Multipart, Path};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};

use hatch_client::{Clip, Event, MediaResult, Prompt, PromptDisclosure, SessionState};

use crate::dto;
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
        safe_logger::debug!(
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
            authorize_consent(d, accepted, submitted_digest.as_deref())?;
            Ok(Event::ConsentDisclosure(accepted))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

/// THE SEAL'S AUTHORIZATION. Not a convenience, not a stale-tab guard — the one
/// thing that ties an applicant to the bytes that reach a consumer. Delete it and
/// api age-seals fields chosen by the process that runs adversary-supplied code,
/// with no applicant involved anywhere in the chain.
///
/// Why it carries that weight: a seal needs `Event::ConsentDisclosure(true)`,
/// that event is constructed at exactly one place in the workspace — the caller
/// below — and reaching it means passing here.
/// [`crate::applicant::shared::consent_for_round`] then derives the fields from
/// this same `current_prompt`, which the execution-worker AUTHORED on the
/// previous round; on its own that proves nothing. What makes it evidence is that
/// the applicant's browser echoed the digest of the screen it rendered, and the
/// only mint site for that digest is `views::consent_view` over the same value.
/// Equal digests ⇒ shown and sealed are the same bytes, by the applicant's own
/// attestation rather than by trusting the worker.
///
/// It also does the job it was first written for: if `current_prompt` advanced (a
/// stale second tab, a concurrent round) the echo no longer matches and we refuse
/// (409). Enforced on ACCEPT only — a decline seals nothing, so a stale decline is
/// harmless.
///
/// Split out of the handler so the rule has a test: it needs a prompt, a bool and
/// a string, where the handler needs a live session and a multipart body.
fn authorize_consent(
    prompt: &PromptDisclosure,
    accepted: bool,
    submitted_digest: Option<&str>,
) -> Result<(), StatusCode> {
    if !accepted {
        return Ok(());
    }
    let expected = dto::consent_disclosure_digest(prompt);
    if submitted_digest != Some(expected.as_str()) {
        return Err(StatusCode::CONFLICT);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::applicant::shared::consent_for_round;
    use crate::applicant::views::{RequestView, consent_view};
    use crate::locale::Locale;
    use hatch_client::DisplayField;

    /// The digest exactly as the applicant's browser receives it — read off the
    /// rendered screen, not recomputed. Taking it from anywhere else would make
    /// these tests compare a function with itself.
    fn digest_the_browser_sees(prompt: &PromptDisclosure) -> String {
        match consent_view(prompt, &Locale::default()) {
            RequestView::Consent {
                disclosure_digest, ..
            } => disclosure_digest,
            _ => panic!("a consent prompt must render a consent view"),
        }
    }

    fn screen(value: &str) -> PromptDisclosure {
        PromptDisclosure {
            fields: vec![DisplayField {
                key: "dob".into(),
                label: Default::default(),
                value: value.into(),
            }],
            ..Default::default()
        }
    }

    /// The whole chain, in one test: the digest the APPLICANT'S SCREEN carried
    /// authorizes the accept, and the accept then seals exactly that screen's
    /// fields. Break either half — stop checking the echo, or stop deriving from
    /// `current_prompt` — and this fails.
    #[test]
    fn the_screen_the_applicant_saw_is_what_authorizes_and_what_seals() {
        let prompt = screen("1990-01-01");
        // Minted the way the browser gets it: off the rendered view, not off the
        // value the check will later recompute over.
        let rendered = digest_the_browser_sees(&prompt);

        authorize_consent(&prompt, true, Some(&rendered))
            .expect("the digest the screen carried must authorize its own accept");

        let sealed = consent_for_round(
            &Event::ConsentDisclosure(true),
            &Some(Prompt::ConsentDisclosure(prompt.clone())),
        )
        .expect("an authorized accept seals");
        assert_eq!(sealed, prompt.fields, "sealed fields must be the screen's");
    }

    /// One character of one value, and the accept is refused — which is what
    /// makes the digest a binding rather than a formality.
    #[test]
    fn a_screen_that_changed_under_the_applicant_is_refused() {
        let shown = screen("1990-01-01");
        let swapped = screen("1990-01-02");
        let rendered = digest_the_browser_sees(&shown);

        assert_eq!(
            authorize_consent(&swapped, true, Some(&rendered)),
            Err(StatusCode::CONFLICT),
        );
    }

    /// No echo at all fails closed, rather than being read as "nothing to check".
    #[test]
    fn an_accept_with_no_digest_is_refused() {
        assert_eq!(
            authorize_consent(&screen("1990-01-01"), true, None),
            Err(StatusCode::CONFLICT),
        );
    }

    /// A decline carries nothing to bind, and seals nothing either way.
    #[test]
    fn a_decline_needs_no_digest_and_seals_nothing() {
        let prompt = screen("1990-01-01");
        authorize_consent(&prompt, false, None).expect("a decline is always allowed");
        assert!(
            consent_for_round(
                &Event::ConsentDisclosure(false),
                &Some(Prompt::ConsentDisclosure(prompt)),
            )
            .is_none()
        );
    }
}
