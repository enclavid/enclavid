//! JSON-serializable view types and converters for the run-triggering
//! handlers (`/connect`, `/input`). Keep purely data-shape — no I/O, no
//! AppState. Everything here is used by both connect.rs and input.rs.
//!
//! Consent-related field shapes (`DisplayField`, `ConsentFieldView`)
//! live in [`crate::dto`] — the persister and the view layer share
//! dto types so the applicant frontend and the consumer SDK see
//! consistent JSON shapes per audience.
//!
//! Locale resolution is **server-side**: every text-ref the polici
//! emits is resolved to a single string for the request's
//! `Accept-Language` preference, with `en` fallback. The frontend
//! never sees a per-locale translation map.

use serde::Serialize;

use enclavid_engine::policy::Decision;
use enclavid_engine::RunStatus;
use enclavid_host_bridge::{
    CameraFacing, CaptureGuide, CaptureStep, MediaSpec, capture_guide, suspended,
};

use crate::dto;
use crate::locale::Locale;
use crate::text_registry::TextRegistry;

/// Response for run-triggering endpoints (`init`, `input`). Internally-tagged
/// enum — the `status` field carries the variant discriminator, other fields
/// carry variant-specific payload.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionProgress {
    Completed { decision: DecisionView },
    AwaitingInput { request: RequestView },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionView {
    Approved,
    Rejected,
    RejectedRetryable,
    Review,
}

/// JSON-friendly view of a pending suspension request. Mirrors the proto
/// `suspended::Request` variants but in a shape the frontend can consume
/// without prost decoding.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestView {
    /// All capture flows (passport, ID card, driver's license,
    /// selfie / passive liveness, multi-page documents) collapse
    /// into this one variant. UI shape is driven by `spec.captures`
    /// and the running `filled` set; `next_slot_id` tells the
    /// frontend where to POST the next input.
    ///
    /// Per-step instructions + icon live on `CaptureStepView` — the
    /// frontend renders an intro screen before each step (gates the
    /// camera permission prompt behind a deliberate "Start" tap
    /// for step 0, and surfaces "now flip / now next page" context
    /// between subsequent steps of a multi-step capture).
    Media {
        label: String,
        captures: Vec<CaptureStepView>,
        filled: Vec<u32>,
        next_slot_id: String,
    },
    Consent {
        fields: Vec<dto::ConsentFieldView>,
        reason: String,
        /// Human-readable name of the party that requested this
        /// verification, resolved from `prompt-disclosure.requester`
        /// via the policy's text registry. Surfaced in the consent
        /// screen header so the applicant sees exactly to whom the
        /// disclosure is being made.
        requester: String,
    },
    VerificationSet {
        alternatives: Vec<Vec<MediaSpecView>>,
    },
}

#[derive(Serialize)]
pub struct CaptureStepView {
    /// Free-form icon name dispatched against the frontend's bundled
    /// SVG library (passport, id-card, drivers-license, selfie).
    /// Unknown names render with no icon (graceful fallback); the
    /// polici declares whatever it wants — frontend version controls
    /// the accepted set.
    pub icon: Option<String>,
    /// Pre-capture intro body, paired with `icon` on the intro
    /// screen for this step.
    pub instructions: String,
    /// Short on-camera overlay during capture.
    pub label: String,
    pub camera: CameraFacingView,
    pub guide: CaptureGuideView,
    /// Post-capture preview-screen check ("Make sure the MRZ is
    /// sharp, no glare").
    pub review_hint: String,
}

#[derive(Serialize)]
pub struct MediaSpecView {
    pub label: String,
    pub captures: Vec<CaptureStepView>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraFacingView {
    Front,
    Rear,
    Any,
}

/// Mirrors `enclavid_host_bridge::CaptureGuide` (proto oneof). Tagged
/// JSON enum so the frontend can dispatch via the `kind` field.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureGuideView {
    None,
    /// Width:height aspect ratio for the rectangular overlay
    /// (passport ≈ 1.42, ID-1 ≈ 1.585).
    Rect { aspect: f32 },
    Oval,
}

pub(super) fn progress_from(
    status: RunStatus,
    texts: &TextRegistry,
    locale: &Locale,
) -> SessionProgress {
    match status {
        RunStatus::Completed(decision) => SessionProgress::Completed {
            decision: decision_view(decision),
        },
        RunStatus::Suspended(req) => SessionProgress::AwaitingInput {
            request: request_view(&req, texts, locale),
        },
    }
}

fn decision_view(d: Decision) -> DecisionView {
    match d {
        Decision::Approved => DecisionView::Approved,
        Decision::Rejected => DecisionView::Rejected,
        Decision::RejectedRetryable => DecisionView::RejectedRetryable,
        Decision::Review => DecisionView::Review,
    }
}

fn request_view(
    req: &suspended::Request,
    texts: &TextRegistry,
    locale: &Locale,
) -> RequestView {
    match req {
        suspended::Request::Media(m) => media_view(m, texts, locale),
        suspended::Request::Consent(c) => RequestView::Consent {
            fields: c
                .fields
                .iter()
                .map(|f| dto::consent_field_view_from_proto(f, texts, locale))
                .collect(),
            reason: texts.resolve_string(&c.reason_ref, locale),
            requester: texts.resolve_string(&c.requester_ref, locale),
        },
        suspended::Request::VerificationSet(vs) => RequestView::VerificationSet {
            alternatives: vs
                .alternatives
                .iter()
                .map(|g| {
                    g.items
                        .iter()
                        .map(|s| media_spec_view(s, texts, locale))
                        .collect()
                })
                .collect(),
        },
    }
}

fn media_view(
    m: &enclavid_host_bridge::MediaRequest,
    texts: &TextRegistry,
    locale: &Locale,
) -> RequestView {
    let spec = m.spec.as_ref();
    let total = spec.map(|s| s.captures.len() as u32).unwrap_or(0);
    let captures: Vec<CaptureStepView> = spec
        .map(|s| {
            s.captures
                .iter()
                .map(|c| capture_step_view(c, texts, locale))
                .collect()
        })
        .unwrap_or_default();
    let filled: Vec<u32> = {
        let mut v: Vec<u32> = m
            .clips
            .iter()
            .filter_map(|(idx, c)| (!c.frames.is_empty()).then_some(*idx))
            .collect();
        v.sort_unstable();
        v
    };
    // First step that hasn't been filled. The whole-prompt-completed
    // case (filled.len() == total) doesn't reach this branch — the
    // engine returns the tuple to policy, not suspends.
    let next_index = (0..total)
        .find(|i| !filled.contains(i))
        .unwrap_or(total);
    let next_slot_id = format!("media-{next_index}");
    RequestView::Media {
        label: spec
            .map(|s| texts.resolve_string(&s.label_ref, locale))
            .unwrap_or_default(),
        captures,
        filled,
        next_slot_id,
    }
}

fn media_spec_view(
    s: &MediaSpec,
    texts: &TextRegistry,
    locale: &Locale,
) -> MediaSpecView {
    MediaSpecView {
        label: texts.resolve_string(&s.label_ref, locale),
        captures: s
            .captures
            .iter()
            .map(|c| capture_step_view(c, texts, locale))
            .collect(),
    }
}

fn capture_step_view(
    s: &CaptureStep,
    texts: &TextRegistry,
    locale: &Locale,
) -> CaptureStepView {
    CaptureStepView {
        // Icon string passes through verbatim — frontend resolves it
        // against its bundled icon library with fallback to no-icon.
        // Not a text-ref; not localised.
        icon: s.icon_ref.clone(),
        instructions: texts.resolve_string(&s.instructions_ref, locale),
        label: texts.resolve_string(&s.label_ref, locale),
        camera: camera_view(s.camera),
        guide: guide_view(s.guide.as_ref()),
        review_hint: texts.resolve_string(&s.review_hint_ref, locale),
    }
}

fn camera_view(c: i32) -> CameraFacingView {
    if c == CameraFacing::Front as i32 {
        CameraFacingView::Front
    } else if c == CameraFacing::Rear as i32 {
        CameraFacingView::Rear
    } else {
        CameraFacingView::Any
    }
}

fn guide_view(g: Option<&CaptureGuide>) -> CaptureGuideView {
    let Some(g) = g else {
        return CaptureGuideView::None;
    };
    match g.kind.as_ref() {
        Some(capture_guide::Kind::Rect(r)) => CaptureGuideView::Rect { aspect: r.aspect },
        Some(capture_guide::Kind::Oval(_)) => CaptureGuideView::Oval,
        Some(capture_guide::Kind::None(_)) | None => CaptureGuideView::None,
    }
}
