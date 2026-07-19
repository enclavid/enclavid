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

use serde::Serialize;

use engine_executor::{Decision, RunStatus};
use broker_client::{
    CameraFacing, CaptureGuide, CaptureStep, MediaSpec, Prompt, PromptDisclosure, capture_guide,
};

use crate::dto;
use crate::locale::Locale;

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

/// JSON-friendly view of the prompt the session is awaiting input for.
/// Mirrors the domain `Prompt` variants but in a shape the frontend can
/// consume directly.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestView {
    /// All capture flows (passport, ID card, driver's license,
    /// selfie / passive liveness, multi-page documents) collapse
    /// into this one variant. UI shape is driven by `captures`;
    /// the frontend captures each step and POSTs it to
    /// `input/media-<step-index>`.
    ///
    /// The prompt carries no running fill state — the policy reducer
    /// receives one `event::media` per round and re-renders until it
    /// advances, so `next_slot_id` is the first capture step
    /// (`media-0`) and the frontend walks the steps in order.
    ///
    /// Per-step instructions + icon live on `CaptureStepView` — the
    /// frontend renders an intro screen before each step (gates the
    /// camera permission prompt behind a deliberate "Start" tap
    /// for step 0, and surfaces "now flip / now next page" context
    /// between subsequent steps of a multi-step capture).
    Media {
        label: String,
        captures: Vec<CaptureStepView>,
        next_slot_id: String,
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
/// …`). `total_declared` is the DISTINCT declared-key count across the
/// whole composition (policy + every plugin), computed and sealed
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
    /// Icon name resolved from the policy's `icons` declarations
    /// (engine-side `enclavid:embedded/icons` ref). Frontend
    /// dispatches against its bundled SVG library; unknown names
    /// render no icon (graceful fallback). Declarations bounded by
    /// `MAX_DECLARED_ICONS` — icon names never reach the consumer
    /// envelope so a tight cap is the right shape.
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
#[serde(rename_all = "snake_case")]
pub enum CameraFacingView {
    Front,
    Rear,
    Any,
}

/// Mirrors `broker_client::CaptureGuide` (proto oneof). Tagged
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

pub(super) fn progress_from(status: RunStatus, locale: &Locale) -> SessionProgress {
    match status {
        RunStatus::Completed(decision) => SessionProgress::Completed {
            decision: decision_view(decision),
        },
        RunStatus::AwaitingInput(prompt) => SessionProgress::AwaitingInput {
            request: prompt_view(&prompt, locale),
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

fn prompt_view(prompt: &Prompt, locale: &Locale) -> RequestView {
    match prompt {
        Prompt::Media(spec) => media_view(spec, locale),
        Prompt::ConsentDisclosure(d) => consent_view(d, locale),
    }
}

fn consent_view(d: &PromptDisclosure, locale: &Locale) -> RequestView {
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
    }
}

fn media_view(spec: &MediaSpec, locale: &Locale) -> RequestView {
    let captures: Vec<CaptureStepView> =
        spec.captures.iter().map(|c| capture_step_view(c, locale)).collect();
    RequestView::Media {
        label: dto::pick_localized(&spec.label, locale),
        captures,
        // The prompt carries no fill state; the frontend walks the
        // capture steps from the first one and POSTs each in order.
        next_slot_id: "media-0".to_string(),
    }
}

fn capture_step_view(s: &CaptureStep, locale: &Locale) -> CaptureStepView {
    CaptureStepView {
        // Already the resolved icon name (engine deref'd the ref); the
        // frontend dispatches against its bundled library, no-icon on
        // unknown names.
        icon: s.icon.clone(),
        instructions: dto::pick_localized(&s.instructions, locale),
        label: dto::pick_localized(&s.label, locale),
        camera: camera_view(s.camera),
        guide: guide_view(s.guide.as_ref()),
        review_hint: dto::pick_localized(&s.review_hint, locale),
    }
}

fn camera_view(c: CameraFacing) -> CameraFacingView {
    match c {
        CameraFacing::Front => CameraFacingView::Front,
        CameraFacing::Rear => CameraFacingView::Rear,
        CameraFacing::Unknown | CameraFacing::Any => CameraFacingView::Any,
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
