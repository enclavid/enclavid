use std::sync::Arc;

use axum::extract::multipart::Field;
use axum::extract::{DefaultBodyLimit, Multipart, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, post};

use session_types::{
    Capture, CaptureKind, Event, FrameRange, MAX_MEDIA_BYTES, MediaResult, Prompt, SessionState,
    VideoCapture, VideoGuide,
};

use crate::limits::{APPLICANT_INPUT_BODY_LIMIT, MAX_GUIDES_PART_BYTES};
use crate::state::AppState;

use super::consent;
use super::round::SessionRunCtx;
use super::views::{SessionProgress, prompt_view, remaining_ms};

/// Route factory. Auth attached at router level via
/// `.layer(auth())` — see `applicant::router`.
pub(super) fn post_input() -> MethodRouter<Arc<AppState>> {
    post(input).layer(DefaultBodyLimit::max(APPLICANT_INPUT_BODY_LIMIT))
}

/// POST /api/v1/sessions/{id}/input/{awaiting_seq}/{slot_id} — submits applicant
/// input for the prompt the session is currently awaiting.
///
/// `awaiting_seq` names the wait the answer is for (`SessionState::awaiting_seq`),
/// as the page was given it with the prompt. An answer to another wait than the
/// session's — a second tap that arrived after the first moved the session on, a
/// retry of a round whose reply was lost, another tab — is refused (409) with the
/// wait that is current, before its body is read, so the page shows where the
/// session stands instead of the answer being taken for the next step's.
///
/// `slot_id` shapes:
///   * `media-N` — the capture of step `N` of the current `Prompt::Media`'s
///     `captures` (see [`read_step`]). The steps come one a request, in order:
///     `N` must be the first step not sent yet, or the answer is refused (409)
///     with where the session stands. A step before the last is stored, and
///     the session stays in its wait ([`SessionRunCtx::keep_step`]); the last
///     builds an [`Event::Media`] of every step's capture and runs the round.
///   * `consent` — text part `accepted=true|false` plus a `disclosure_hash`
///     (the host-minted digest of the screen the applicant confirmed); builds
///     an [`Event::ConsentDisclosure`]. On accept the digest must match the
///     current disclosure or the round is refused (409) — show == seal.
///   * `timed-out` — no parts: the page's word that the time of a media
///     prompt with a time limit ran out, or that the applicant gave it up;
///     builds an [`Event::TimedOut`].
///
/// A step of a prompt with a time limit that its steps can no longer meet —
/// one not started, or started more than its limit ago, by this side's clock
/// — runs the round with an [`Event::TimedOut`] instead, its body unread: the
/// page keeps the time, and this side holds it to it.
///
/// The `slot_id` must match the kind/shape of the prompt persisted as
/// `current_prompt`. A mismatch returns 409 (kind/shape desync) or 400
/// (unknown slot id) — the desync is surfaced explicitly rather than
/// silently reinterpreting the body, which could trip fraud heuristics
/// downstream.
async fn input(
    Path((session_id, awaiting_seq, slot_id)): Path<(String, u64, String)>,
    mut ctx: SessionRunCtx,
    multipart: Multipart,
) -> Response {
    let Some(session_state) = ctx.session_state.take() else {
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
        return StatusCode::CONFLICT.into_response();
    };
    if awaiting_seq != session_state.awaiting_seq {
        return moved_on(&session_state, &ctx);
    }
    if let Some(step) = parse_media_slot(&slot_id) {
        if past_limit(&session_state, super::now_ms()) {
            return ctx
                .run(session_state, Event::TimedOut)
                .await
                .into_response();
        }
        return media_step(ctx, session_state, step, multipart).await;
    }
    let event = match slot_id.as_str() {
        "consent" => match consent_event(&session_state, multipart).await {
            Ok(event) => event,
            Err(status) => return status.into_response(),
        },
        "timed-out" => match session_state.current_prompt.as_ref() {
            Some(Prompt::Media(spec)) if spec.time_limit_secs.is_some() => Event::TimedOut,
            _ => return StatusCode::CONFLICT.into_response(),
        },
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    ctx.run(session_state, event).await.into_response()
}

/// Whether the session awaits a media prompt with a time limit that its steps
/// can no longer meet at `now_ms`: one not started, or started more than its
/// limit ago.
fn past_limit(session_state: &SessionState, now_ms: u64) -> bool {
    let Some(Prompt::Media(spec)) = session_state.current_prompt.as_ref() else {
        return false;
    };
    let Some(limit) = spec.time_limit_secs else {
        return false;
    };
    session_state
        .started_at_ms
        .is_none_or(|started| remaining_ms(limit, started, now_ms) == 0)
}

/// The refusal of an answer to where the session no longer is: 409, with the
/// wait it is in now, as `/connect` would answer it.
pub(super) fn moved_on(session_state: &SessionState, ctx: &SessionRunCtx) -> Response {
    let Some(prompt) = session_state.current_prompt.as_ref() else {
        return StatusCode::CONFLICT.into_response();
    };
    let mut response = SessionProgress::AwaitingInput {
        awaiting_seq: session_state.awaiting_seq,
        request: prompt_view(
            prompt,
            &session_state.sent,
            session_state.started_at_ms,
            &ctx.locale,
        ),
    }
    .into_response();
    *response.status_mut() = StatusCode::CONFLICT;
    response
}

/// Parse `media-N` slot ids into the step index. Returns `None` for
/// slot ids that don't follow this pattern.
fn parse_media_slot(slot_id: &str) -> Option<usize> {
    slot_id.strip_prefix("media-")?.parse().ok()
}

/// Step `step` of the media prompt the session awaits: stored when it is not
/// the last, and the round run with every step's capture when it is.
async fn media_step(
    ctx: SessionRunCtx,
    session_state: SessionState,
    step: usize,
    multipart: Multipart,
) -> Response {
    let Some(Prompt::Media(spec)) = session_state.current_prompt.as_ref() else {
        // Client is at a media capture but the policy is awaiting something
        // else.
        return StatusCode::CONFLICT.into_response();
    };
    // The page sends the steps in order, each once: another step than the
    // first not sent is an answer composed for where the session no longer is
    // — a second tap, a page from before a reload.
    if step != session_state.sent.len() || step >= spec.captures.len() {
        return moved_on(&session_state, &ctx);
    }
    let last = step + 1 == spec.captures.len();
    let held: u64 = session_state.sent.iter().map(|sent| sent.len).sum();
    let budget = usize::try_from((MAX_MEDIA_BYTES as u64).saturating_sub(held)).unwrap_or(0);
    let capture = match read_step(&spec.captures[step].kind, multipart, budget).await {
        Ok(capture) => capture,
        Err(status) => return status.into_response(),
    };
    if !last {
        return match ctx.keep_step(session_state, capture).await {
            Ok(progress) => progress.into_response(),
            Err(status) => status.into_response(),
        };
    }
    let mut captures = match ctx.sent_captures(&session_state).await {
        Ok(captures) => captures,
        Err(status) => return status.into_response(),
    };
    captures.push(capture);
    ctx.run(session_state, Event::Media(MediaResult { captures }))
        .await
        .into_response()
}

/// The consent answer, checked against the disclosure the session awaits.
async fn consent_event(session: &SessionState, multipart: Multipart) -> Result<Event, StatusCode> {
    let Some(Prompt::ConsentDisclosure(d)) = session.current_prompt.as_ref() else {
        return Err(StatusCode::CONFLICT);
    };
    let (accepted, submitted_digest) = read_consent(multipart).await?;
    consent::authorize(d, accepted, submitted_digest.as_deref())?;
    Ok(Event::ConsentDisclosure(accepted))
}

/// Read the capture of one step, of the step's kind, from its parts:
///   * `photo` — one JPEG, for a photo step;
///   * `video` — the WebM, for a video step, then a `guides` part: where the
///     page saw each of the step's guides held, as JSON pairs of frame indices
///     `[[first, last], …]`, one for each guide, in the step's order. The
///     guides themselves are the prompt's, copied here: the page names only
///     the frames.
///
/// A part out of place, one missing, or one more is a malformed answer (400).
/// So the COUNT of captures needs no bound of its own here: there is one for
/// each step of a spec the engine held to its step cap.
///
/// The capture may hold at most `budget` bytes: the media budget the worker's
/// `MediaResult` decoder enforces, less what the steps sent already hold.
/// Applied here as well, and the duplication is the point rather than an
/// oversight. This side can answer the applicant's browser with a 413; the
/// worker can only refuse the round, which reaches the applicant as a failed
/// session. So the cap belongs where the good error is, and it belongs at the
/// worker too because the worker accepts any attested guest and cannot assume
/// its caller ran this code.
///
/// A body past `APPLICANT_INPUT_BODY_LIMIT` surfaces as a multipart error, and
/// `MultipartError::status` is what keeps it a 413 rather than a 400.
async fn read_step(
    kind: &CaptureKind,
    mut multipart: Multipart,
    budget: usize,
) -> Result<Capture, StatusCode> {
    let capture = match kind {
        CaptureKind::Photo(_) => Capture::Photo(media_part(&mut multipart, "photo", budget).await?),
        CaptureKind::Video(spec) => {
            let video = media_part(&mut multipart, "video", budget).await?;
            let guides = guides_part(&mut multipart, &spec.guides).await?;
            Capture::Video(VideoCapture { video, guides })
        }
    };
    if multipart
        .next_field()
        .await
        .map_err(|e| e.status())?
        .is_some()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(capture)
}

/// The next part, which must be named `name`.
async fn next_part<'a>(multipart: &'a mut Multipart, name: &str) -> Result<Field<'a>, StatusCode> {
    let field = multipart
        .next_field()
        .await
        .map_err(|e| e.status())?
        .ok_or(StatusCode::BAD_REQUEST)?;
    if field.name() != Some(name) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(field)
}

/// The next part, which must be named `name`: the applicant's bytes, at most
/// `budget` of them.
async fn media_part(
    multipart: &mut Multipart,
    name: &str,
    budget: usize,
) -> Result<Vec<u8>, StatusCode> {
    let bytes = next_part(multipart, name)
        .await?
        .bytes()
        .await
        .map_err(|e| e.status())?;
    if bytes.len() > budget {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok(bytes.to_vec())
}

/// A video step's `guides` part, paired with the step's `guides`: one range
/// for each, its guide the prompt's and its frames the page's. A range must
/// not end before it begins; anything else about the frames is for a check
/// to verify against the video.
async fn guides_part(
    multipart: &mut Multipart,
    guides: &[VideoGuide],
) -> Result<Vec<FrameRange>, StatusCode> {
    let bytes = next_part(multipart, "guides")
        .await?
        .bytes()
        .await
        .map_err(|e| e.status())?;
    if bytes.len() > MAX_GUIDES_PART_BYTES {
        return Err(StatusCode::BAD_REQUEST);
    }
    let pairs: Vec<(u32, u32)> =
        serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    if pairs.len() != guides.len() || pairs.iter().any(|(first, last)| first > last) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(guides
        .iter()
        .zip(pairs)
        .map(|(guide, (first, last))| FrameRange {
            guide: guide.clone(),
            first,
            last,
        })
        .collect())
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
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::Request;
    use session_types::{FaceGuide, HeadTurnGuide, PhotoSpec, VideoSpec};

    use super::*;

    const FACE: VideoGuide = VideoGuide::Face(FaceGuide {
        width: 0.5,
        hold_ms: 1000,
    });
    const TURN: VideoGuide = VideoGuide::HeadTurn(HeadTurnGuide {
        degrees: -30,
        hold_ms: 800,
    });

    fn photo_step() -> CaptureKind {
        CaptureKind::Photo(PhotoSpec::default())
    }

    /// A video step of two guides.
    fn video_step() -> CaptureKind {
        CaptureKind::Video(VideoSpec {
            guides: vec![FACE, TURN],
        })
    }

    /// A multipart body of `parts`, each a name and its bytes, as the page
    /// sends one.
    async fn multipart(parts: &[(&str, &[u8])]) -> Multipart {
        const BOUNDARY: &str = "capture-boundary";
        let mut body = Vec::new();
        for (name, bytes) in parts {
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; \
                     name=\"{name}\"; filename=\"{name}\"\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        let request = Request::builder()
            .header(
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(body))
            .unwrap();
        Multipart::from_request(request, &()).await.unwrap()
    }

    /// A step is read as its kind is: a photo's one JPEG, a video's data with
    /// ranges that take the prompt's guides, the page naming only the frames.
    #[tokio::test]
    async fn a_step_is_read_with_the_prompts_guides() {
        let photo = read_step(
            &photo_step(),
            multipart(&[("photo", b"jpeg")]).await,
            MAX_MEDIA_BYTES,
        )
        .await;
        assert_eq!(photo, Ok(Capture::Photo(b"jpeg".to_vec())));
        let video = read_step(
            &video_step(),
            multipart(&[("video", b"webm"), ("guides", b"[[0, 10], [11, 30]]")]).await,
            MAX_MEDIA_BYTES,
        )
        .await;
        assert_eq!(
            video,
            Ok(Capture::Video(VideoCapture {
                video: b"webm".to_vec(),
                guides: vec![
                    FrameRange {
                        guide: FACE,
                        first: 0,
                        last: 10,
                    },
                    FrameRange {
                        guide: TURN,
                        first: 11,
                        last: 30,
                    },
                ],
            }))
        );
    }

    /// An answer not of the step's shape is malformed: a part of another kind,
    /// one missing, one more, ranges not one for each guide, a range that ends
    /// before it begins, ranges that are not JSON.
    #[tokio::test]
    async fn an_answer_not_of_the_steps_shape_is_refused() {
        let photo: (&str, &[u8]) = ("photo", b"jpeg");
        let video: (&str, &[u8]) = ("video", b"webm");
        let guides: (&str, &[u8]) = ("guides", b"[[0, 10], [11, 30]]");
        let answers: [(CaptureKind, Vec<(&str, &[u8])>); 8] = [
            (photo_step(), vec![video]),
            (photo_step(), vec![photo, photo]),
            (video_step(), vec![video]),
            (video_step(), vec![guides, video]),
            (video_step(), vec![video, guides, photo]),
            (video_step(), vec![video, ("guides", b"[[0, 10]]")]),
            (
                video_step(),
                vec![video, ("guides", b"[[0, 10], [30, 11]]")],
            ),
            (video_step(), vec![video, ("guides", b"zero to ten")]),
        ];
        for (kind, parts) in answers {
            let names: Vec<&str> = parts.iter().map(|(name, _)| *name).collect();
            assert_eq!(
                read_step(&kind, multipart(&parts).await, MAX_MEDIA_BYTES).await,
                Err(StatusCode::BAD_REQUEST),
                "{names:?}"
            );
        }
    }

    /// A capture past what the budget leaves is refused as too large.
    #[tokio::test]
    async fn a_step_past_the_budget_left_is_refused() {
        let parts: [(&str, &[u8]); 1] = [("photo", b"jpeg")];
        assert_eq!(
            read_step(&photo_step(), multipart(&parts).await, 3).await,
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
    }

    /// A prompt with a time limit is past it when not started, or once its
    /// limit has run since the start; one without a limit never is.
    #[test]
    fn a_timed_prompt_is_past_its_limit_unstarted_or_once_run() {
        let waiting = |time_limit_secs, started_at_ms| SessionState {
            current_prompt: Some(Prompt::Media(session_types::MediaSpec {
                time_limit_secs,
                ..Default::default()
            })),
            started_at_ms,
            ..Default::default()
        };
        assert!(past_limit(&waiting(Some(30), None), 5_000));
        assert!(!past_limit(&waiting(Some(30), Some(5_000)), 34_999));
        assert!(past_limit(&waiting(Some(30), Some(5_000)), 35_000));
        assert!(!past_limit(&waiting(None, None), 99_000));
        assert!(!past_limit(&SessionState::default(), 99_000));
    }
}
