//! JSON-serializable view types and converters for the run-triggering
//! handlers (`/connect`, `/input`). Keep purely data-shape — no I/O, no
//! AppState. Everything here is used by both connect.rs and input.rs.
//!
//! Consent-related field shapes (`DisplayField`, `ConsentFieldView`)
//! live in [`crate::dto`] — the persister and the view layer share
//! dto types so the applicant frontend and the consumer SDK see
//! consistent JSON shapes per audience.
//!
//! Locale resolution is **server-side**: every text-ref the policy
//! emits is resolved to a single string for the request's
//! `Accept-Language` preference, with `en` fallback. The frontend
//! never sees a per-locale translation map.

use axum::response::{IntoResponse, Response};
use serde::Serialize;

use engine_types::limits::GUIDE_OVAL_ASPECT;
use session_types::{
    CameraFacing, CaptureKind, CaptureStep, Disclosure as PromptDisclosure, MAX_MEDIA_BYTES,
    MediaSpec, Prompt, SentStep, StaticGuide, VideoGuide,
};
// The run outcome comes back from the execution-worker as the `engine_rpc::RunStatus`
// wire mirror (it wraps the same session_types `Prompt` / `Decision`).
use engine_rpc::RunStatus;

use crate::dto::{self, DecisionView};
use crate::locale::Locale;

/// Response for run-triggering endpoints (`init`, `input`). Internally-tagged
/// enum — the `status` field carries the variant discriminator, other fields
/// carry variant-specific payload.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionProgress {
    Completed {
        decision: DecisionView,
    },
    AwaitingInput {
        /// Which of the session's waits this is (`SessionState::awaiting_seq`).
        /// The page names it in the answer — `/input/{awaiting_seq}/{slot}` — so
        /// an answer to an earlier wait is refused with the one that is current.
        awaiting_seq: u64,
        request: RequestView,
    },
}

/// As JSON, as long whichever the verdict — see
/// [`dto::json_hiding_decision`].
impl IntoResponse for SessionProgress {
    fn into_response(self) -> Response {
        let decision = match &self {
            SessionProgress::Completed { decision } => Some(*decision),
            SessionProgress::AwaitingInput { .. } => None,
        };
        dto::json_hiding_decision(&self, decision)
    }
}

/// JSON-friendly view of the prompt the session is awaiting input for.
/// Mirrors the domain `Prompt` variants but in a shape the frontend can
/// consume directly.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestView {
    /// All capture flows (passport, ID card, driver's license,
    /// selfie / passive liveness, multi-page documents) collapse
    /// into this one variant. UI shape is driven by `captures`; the
    /// frontend walks the steps in order and POSTs each step's capture
    /// to `input/media-<step>` as it is taken. The last one's request
    /// runs the round, which hands the policy every step's capture in
    /// one `event::media`.
    ///
    /// Per-step instructions + icon live on `CaptureStepView` — the
    /// frontend renders an intro screen before each step (gates the
    /// camera permission prompt behind a deliberate "Start" tap
    /// for step 0, and surfaces "now flip / now next page" context
    /// between subsequent steps of a multi-step capture).
    Media {
        label: String,
        captures: Vec<CaptureStepView>,
        /// The step to show: the first whose capture is not sent yet. A
        /// reload carries on from it.
        next_step: usize,
        /// The most bytes the captures of the steps not sent yet may be
        /// together; past it a step's upload is refused with 413. The
        /// frontend fits each capture under its share of this rather than
        /// under a number of its own, so the two cannot drift apart. The
        /// build's media budget, less what the steps sent already hold.
        max_upload_bytes: usize,
        /// The seconds the applicant has for the steps together, from when
        /// the page starts them; none where the prompt has no limit.
        time_limit_secs: Option<u16>,
        /// What is left of that limit since the page started the steps, in
        /// milliseconds by api's clock; none before the start, and where there
        /// is no limit. While a limit is not started, the steps carry no
        /// `kind`: the page starts the prompt to be given them.
        remaining_ms: Option<u64>,
    },
    Consent {
        fields: Vec<dto::ConsentFieldView>,
        reason: String,
        /// Human-readable name of the party that requested this
        /// verification, resolved from the disclosure's `requester`
        /// via the policy's text registry. Surfaced in the consent
        /// screen header so the applicant sees exactly to whom the
        /// disclosure is being made.
        requester: String,
        /// Host-minted digest of THIS exact disclosure screen. The
        /// frontend echoes it back as `disclosure_hash` on the consent
        /// accept; the input handler refuses an accept whose digest no
        /// longer matches `current_prompt` (stale tab / concurrent
        /// round), so the runtime never seals a disclosure the applicant
        /// did not audit (show == seal). See
        /// [`dto::consent_disclosure_digest`].
        disclosure_digest: String,
        /// Covert-channel bandwidth of the `disclosure-fields`
        /// vocabulary — the only embedded kind whose keys reach the
        /// consumer envelope. Frontend renders `total_declared` vs
        /// `used_in_call` so the applicant sees "wide vocabulary, few
        /// shown". Resolved engine-side and sealed into the prompt, so
        /// the read path surfaces it without the policy component.
        disclosure_schema: DisclosureSchema,
    },
}

/// Covert-channel visibility for the composition's `disclosure-fields`
/// vocabulary. The composition can encode at most
/// `log2(total_declared)` bits per `DisplayField.key`, and "wide
/// vocabulary with few shown" (`total_declared >> used_in_call`) is the
/// visual signal of possible synonym-encoding (`country_a / country_b /
/// …`). `total_declared` is the DISTINCT declared-key count of the
/// composition's one list, the policy's, computed and sealed
/// engine-side; the full key list is intentionally NOT surfaced — the
/// bare count is the load-bearing signal.
#[derive(Serialize)]
pub struct DisclosureSchema {
    /// Distinct `disclosure-field` keys the whole composition can
    /// resolve, deduped. Sealed into the prompt engine-side.
    pub total_declared: usize,
    /// How many of those keys this consent-disclosure prompt surfaces.
    /// `used_in_call ≤ MAX_CONSENT_FIELDS`.
    pub used_in_call: usize,
}

#[derive(Serialize)]
pub struct CaptureStepView {
    /// Icon name, one of the host's own (`enclavid:host-icons/icons`)
    /// — the frontend draws it from its bundled SVG library. Icon
    /// names never reach the consumer envelope.
    pub icon: Option<String>,
    /// Pre-capture intro body, paired with `icon` on the intro
    /// screen for this step.
    pub instructions: String,
    /// Short on-camera overlay during capture.
    pub label: String,
    pub camera: CameraFacingView,
    /// What the step records, its `kind` tagged beside the fields above; none
    /// in a prompt with a time limit the page has not started.
    #[serde(flatten)]
    pub kind: Option<CaptureKindView>,
}

/// Mirrors `session_types::CaptureKind`.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureKindView {
    /// One frame, which the applicant keeps or retakes on a review screen.
    Photo {
        /// The shape drawn over the camera, if any.
        guide: Option<StaticGuideView>,
        /// Post-capture review-screen check ("Make sure the MRZ is
        /// sharp, no glare").
        review_hint: String,
    },
    /// A video, recorded while guides are shown.
    Video {
        /// What the video asks, in order.
        guides: Vec<VideoGuideView>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraFacingView {
    Front,
    Rear,
    Any,
}

/// Mirrors `session_types::StaticGuide`. Tagged JSON enum so the frontend can
/// dispatch via the `kind` field.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaticGuideView {
    /// A rectangle at the centre of the frame.
    Rect {
        /// Its width:height aspect (passport ≈ 1.42, ID-1 ≈ 1.59).
        aspect: f32,
    },
    /// An oval at the centre of the frame.
    Oval {
        /// As a fraction of the frame's shorter side.
        width: f32,
        /// As a fraction of the frame's shorter side: the width times the
        /// oval's fixed proportion, worked out here so the page draws it as
        /// it is told.
        height: f32,
    },
}

/// Mirrors `session_types::VideoGuide`, tagged as [`StaticGuideView`] is.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VideoGuideView {
    /// A shape the applicant says with a button they have followed.
    StaticGuide {
        guide: StaticGuideView,
        /// How long it is held after the button, in milliseconds.
        hold_ms: u16,
    },
    /// A face the page finds at the centre of the frame, and draws an oval
    /// for.
    Face {
        /// The oval's width, as a fraction of the frame's shorter side.
        width: f32,
        /// Its height, worked out here as an `oval`'s is.
        height: f32,
        /// How long the face stays there, in milliseconds.
        hold_ms: u16,
    },
    /// A turn of the head the page reads.
    HeadTurn {
        /// How far, negative to the applicant's left.
        degrees: i8,
        /// How long it is held, in milliseconds.
        hold_ms: u16,
    },
    /// A face the page finds in an oval, as for `Face`, then lights with the
    /// screen around the oval, one colour after another.
    FaceFlashes {
        /// The oval's width, as a fraction of the frame's shorter side.
        width: f32,
        /// Its height, worked out here as an `oval`'s is.
        height: f32,
        /// Each as `#rrggbb`, in the order shown.
        colors: Vec<String>,
        /// How long each is shown, in milliseconds.
        flash_ms: u16,
    },
}

/// A round's result as the applicant sees it: the decision, or the wait it
/// ended in — numbered `awaiting_seq`, as the round persisted it.
pub(super) fn progress_from(
    status: RunStatus,
    locale: &Locale,
    awaiting_seq: u64,
) -> SessionProgress {
    match status {
        RunStatus::Completed(decision) => SessionProgress::Completed {
            decision: decision.into(),
        },
        // A round's wait starts with none of its steps sent, nor started.
        RunStatus::AwaitingInput(prompt) => SessionProgress::AwaitingInput {
            awaiting_seq,
            request: prompt_view(&prompt, &[], None, locale),
        },
    }
}

/// The prompt the session awaits, with `sent` the steps of a media prompt the
/// page has sent already, and `started_at_ms` when it started them.
pub(super) fn prompt_view(
    prompt: &Prompt,
    sent: &[SentStep],
    started_at_ms: Option<u64>,
    locale: &Locale,
) -> RequestView {
    match prompt {
        Prompt::Media(spec) => media_view(spec, sent, started_at_ms, locale),
        Prompt::ConsentDisclosure(d) => consent_view(d, locale),
    }
}

pub(super) fn consent_view(d: &PromptDisclosure, locale: &Locale) -> RequestView {
    RequestView::Consent {
        fields: d
            .fields
            .iter()
            .map(|f| dto::consent_field_view_from_proto(f, locale))
            .collect(),
        reason: dto::pick_localized(&d.reason, locale),
        requester: dto::pick_localized(&d.requester, locale),
        disclosure_schema: DisclosureSchema {
            // Distinct declared-key count, resolved + sealed engine-side.
            total_declared: d.total_declared,
            used_in_call: d.fields.len(),
        },
        // Binds this rendered screen to the accept the applicant will send
        // back (show == seal); recomputed + checked in `input::build_event`.
        disclosure_digest: dto::consent_disclosure_digest(d),
    }
}

fn media_view(
    spec: &MediaSpec,
    sent: &[SentStep],
    started_at_ms: Option<u64>,
    locale: &Locale,
) -> RequestView {
    // What the steps ask is given only once a limit's time runs, so it is not
    // known before.
    let shown = spec.time_limit_secs.is_none() || started_at_ms.is_some();
    let captures: Vec<CaptureStepView> = spec
        .captures
        .iter()
        .map(|c| capture_step_view(c, shown, locale))
        .collect();
    let held: u64 = sent.iter().map(|step| step.len).sum();
    let left = (MAX_MEDIA_BYTES as u64).saturating_sub(held);
    RequestView::Media {
        label: dto::pick_localized(&spec.label, locale),
        captures,
        next_step: sent.len(),
        max_upload_bytes: crate::limits::APPLICANT_INPUT_BODY_LIMIT
            .min(usize::try_from(left).unwrap_or(usize::MAX)),
        time_limit_secs: spec.time_limit_secs,
        remaining_ms: spec
            .time_limit_secs
            .zip(started_at_ms)
            .map(|(limit, started)| remaining_ms(limit, started, super::now_ms())),
    }
}

/// What is left at `now_ms` of a limit of `limit_secs` started at
/// `started_at_ms`, in milliseconds.
pub(super) fn remaining_ms(limit_secs: u16, started_at_ms: u64, now_ms: u64) -> u64 {
    (u64::from(limit_secs) * 1000).saturating_sub(now_ms.saturating_sub(started_at_ms))
}

fn capture_step_view(s: &CaptureStep, with_kind: bool, locale: &Locale) -> CaptureStepView {
    CaptureStepView {
        // Already the icon name (engine deref'd the ref); the frontend
        // draws it from its bundled library.
        icon: s.icon.clone(),
        instructions: dto::pick_localized(&s.instructions, locale),
        label: dto::pick_localized(&s.label, locale),
        camera: camera_view(s.camera),
        kind: with_kind.then(|| match &s.kind {
            CaptureKind::Photo(photo) => CaptureKindView::Photo {
                guide: photo.guide.map(static_guide_view),
                review_hint: dto::pick_localized(&photo.review_hint, locale),
            },
            CaptureKind::Video(video) => CaptureKindView::Video {
                guides: video.guides.iter().map(video_guide_view).collect(),
            },
        }),
    }
}

fn camera_view(c: CameraFacing) -> CameraFacingView {
    match c {
        CameraFacing::Front => CameraFacingView::Front,
        CameraFacing::Rear => CameraFacingView::Rear,
        CameraFacing::Unknown | CameraFacing::Any => CameraFacingView::Any,
    }
}

fn static_guide_view(g: StaticGuide) -> StaticGuideView {
    match g {
        StaticGuide::Rect(r) => StaticGuideView::Rect { aspect: r.aspect },
        StaticGuide::Oval(o) => StaticGuideView::Oval {
            width: o.width,
            height: o.width * GUIDE_OVAL_ASPECT,
        },
    }
}

fn video_guide_view(g: &VideoGuide) -> VideoGuideView {
    match g {
        VideoGuide::StaticGuide(s) => VideoGuideView::StaticGuide {
            guide: static_guide_view(s.guide),
            hold_ms: s.hold_ms,
        },
        VideoGuide::Face(f) => VideoGuideView::Face {
            width: f.width,
            height: f.width * GUIDE_OVAL_ASPECT,
            hold_ms: f.hold_ms,
        },
        VideoGuide::HeadTurn(t) => VideoGuideView::HeadTurn {
            degrees: t.degrees,
            hold_ms: t.hold_ms,
        },
        VideoGuide::FaceFlashes(f) => VideoGuideView::FaceFlashes {
            width: f.width,
            height: f.width * GUIDE_OVAL_ASPECT,
            colors: f
                .colors
                .iter()
                .map(|c| format!("#{:02x}{:02x}{:02x}", c.red, c.green, c.blue))
                .collect(),
            flash_ms: f.flash_ms,
        },
    }
}

#[cfg(test)]
mod tests {
    use session_types::{
        FaceFlashesGuide, FaceGuide, HeadTurnGuide, Localized, PhotoSpec, RectGuide, Rgb,
        StaticVideoGuide, VideoSpec,
    };

    use super::*;

    /// The wait's number travels beside the request, not inside it, so any kind
    /// of wait carries one.
    #[test]
    fn a_wait_names_its_number_beside_its_request() {
        let progress = progress_from(
            RunStatus::AwaitingInput(Prompt::Media(MediaSpec::default())),
            &Locale::default(),
            3,
        );
        let json = serde_json::to_value(&progress).unwrap();
        assert_eq!(json["status"], "awaiting_input");
        assert_eq!(json["awaiting_seq"], 3);
        assert_eq!(json["request"]["kind"], "media");
        assert_eq!(json["request"]["next_step"], 0);
    }

    /// A wait whose first steps were sent carries on from the next, with what
    /// those steps hold taken off the budget.
    #[test]
    fn a_media_wait_carries_on_from_the_first_step_not_sent() {
        let sent = [1_000_u64, 2_000].map(|len| SentStep {
            hash: [7; 32],
            len,
            guides: Vec::new(),
        });
        let json = serde_json::to_value(prompt_view(
            &Prompt::Media(MediaSpec::default()),
            &sent,
            None,
            &Locale::default(),
        ))
        .unwrap();
        assert_eq!(json["next_step"], 2);
        assert_eq!(json["max_upload_bytes"], MAX_MEDIA_BYTES - 3_000);
    }

    /// A prompt with a time limit gives its steps' kinds only once started,
    /// then with the time left; one without a limit gives them whole, started
    /// or not.
    #[test]
    fn a_timed_prompt_gives_its_steps_once_started() {
        let step = CaptureStep {
            icon: None,
            instructions: Localized::default(),
            label: Localized::default(),
            camera: CameraFacing::Front,
            kind: CaptureKind::Video(VideoSpec {
                guides: vec![VideoGuide::Face(FaceGuide {
                    width: 0.5,
                    hold_ms: 1000,
                })],
            }),
        };
        let spec = |time_limit_secs| MediaSpec {
            label: Localized::default(),
            captures: vec![step.clone()],
            time_limit_secs,
        };
        let view = |spec, started_at_ms| {
            serde_json::to_value(prompt_view(
                &Prompt::Media(spec),
                &[],
                started_at_ms,
                &Locale::default(),
            ))
            .unwrap()
        };

        let waiting = view(spec(Some(30)), None);
        assert_eq!(waiting["time_limit_secs"], 30);
        assert!(waiting["remaining_ms"].is_null());
        assert!(waiting["captures"][0].get("kind").is_none());
        assert!(waiting["captures"][0].get("guides").is_none());
        assert!(waiting["captures"][0].get("label").is_some());

        let started = view(spec(Some(30)), Some(crate::applicant::now_ms()));
        assert_eq!(started["captures"][0]["kind"], "video");
        let left = started["remaining_ms"].as_u64().unwrap();
        assert!(left <= 30_000 && left > 25_000, "{left}");

        for started_at_ms in [None, Some(1)] {
            let whole = view(spec(None), started_at_ms);
            assert_eq!(whole["captures"][0]["kind"], "video");
            assert!(whole["time_limit_secs"].is_null() && whole["remaining_ms"].is_null());
        }
    }

    /// What is left of a limit runs down from it to nothing, and no further.
    #[test]
    fn the_time_left_runs_down_to_nothing() {
        assert_eq!(remaining_ms(30, 1_000, 1_000), 30_000);
        assert_eq!(remaining_ms(30, 1_000, 11_000), 20_000);
        assert_eq!(remaining_ms(30, 1_000, 31_000), 0);
        assert_eq!(remaining_ms(30, 1_000, 99_000), 0);
        // A clock read before the start, as after a restart, leaves it whole.
        assert_eq!(remaining_ms(30, 5_000, 1_000), 30_000);
    }

    /// A step's kind is tagged beside its other fields, and each guide by its
    /// own kind, as the page reads them.
    #[test]
    fn a_step_is_tagged_by_what_it_records() {
        let step = |kind| CaptureStep {
            icon: None,
            instructions: Localized::default(),
            label: Localized::default(),
            camera: CameraFacing::Front,
            kind,
        };
        let spec = MediaSpec {
            label: Localized::default(),
            captures: vec![
                step(CaptureKind::Photo(PhotoSpec {
                    guide: Some(StaticGuide::Rect(RectGuide { aspect: 1.42 })),
                    review_hint: Localized::default(),
                })),
                step(CaptureKind::Video(VideoSpec {
                    guides: vec![
                        VideoGuide::StaticGuide(StaticVideoGuide {
                            guide: StaticGuide::Rect(RectGuide { aspect: 1.59 }),
                            hold_ms: 2000,
                        }),
                        VideoGuide::Face(FaceGuide {
                            width: 0.5,
                            hold_ms: 1000,
                        }),
                        VideoGuide::HeadTurn(HeadTurnGuide {
                            degrees: -30,
                            hold_ms: 800,
                        }),
                        VideoGuide::FaceFlashes(FaceFlashesGuide {
                            width: 0.5,
                            colors: vec![
                                Rgb {
                                    red: 255,
                                    green: 136,
                                    blue: 0,
                                },
                                Rgb {
                                    red: 0,
                                    green: 10,
                                    blue: 171,
                                },
                            ],
                            flash_ms: 300,
                        }),
                    ],
                })),
            ],
            time_limit_secs: None,
        };
        let text = serde_json::to_string(&prompt_view(
            &Prompt::Media(spec),
            &[],
            None,
            &Locale::default(),
        ))
        .unwrap();
        // A photo's aspect reads as the policy gave it, not as a widened f32.
        assert!(text.contains(r#""aspect":1.42"#), "{text}");
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let [photo, video] = [&json["captures"][0], &json["captures"][1]];
        assert_eq!(photo["kind"], "photo");
        assert_eq!(photo["camera"], "front");
        assert_eq!(photo["guide"]["kind"], "rect");
        assert!(photo.get("review_hint").is_some());
        assert_eq!(video["kind"], "video");
        assert_eq!(video["guides"][0]["kind"], "static_guide");
        assert_eq!(video["guides"][0]["guide"]["kind"], "rect");
        assert_eq!(video["guides"][0]["hold_ms"], 2000);
        assert_eq!(video["guides"][1]["kind"], "face");
        assert_eq!(video["guides"][1]["hold_ms"], 1000);
        assert!(video["guides"][1].get("height").is_some());
        assert_eq!(video["guides"][2]["kind"], "head_turn");
        assert_eq!(video["guides"][2]["degrees"], -30);
        assert_eq!(video["guides"][3]["kind"], "face_flashes");
        assert_eq!(video["guides"][3]["colors"][0], "#ff8800");
        assert_eq!(video["guides"][3]["colors"][1], "#000aab");
        assert_eq!(video["guides"][3]["flash_ms"], 300);
        assert!(video["guides"][3].get("height").is_some());
    }
}
