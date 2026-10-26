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

use session_types::{
    CameraFacing, CaptureGuide, CaptureStep, Disclosure as PromptDisclosure, MediaSpec, Prompt,
    capture_guide,
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
    Completed { decision: DecisionView },
    AwaitingInput { request: RequestView },
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
    /// into this one variant. UI shape is driven by `captures`;
    /// the frontend captures each step and POSTs it to
    /// `input/media-<step-index>`.
    ///
    /// The prompt carries no running fill state — the policy reducer
    /// receives one `event::media` per round and re-renders until it
    /// advances, so `next_slot_id` is the first capture step
    /// (`<version>.media-0`, see [`slot`]) and the frontend walks the steps
    /// in order.
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
        /// The most bytes one step's upload may be, multipart framing
        /// included; past it the body is refused with 413. The frontend
        /// fits its frames under this rather than under a number of its own,
        /// so the two cannot drift apart. A constant of the build, the same
        /// for every session.
        max_upload_bytes: usize,
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
        /// Where the answer to this screen goes: `<version>.consent`, see
        /// [`slot`].
        slot_id: String,
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

/// Mirrors `session_types::CaptureGuide` (proto oneof). Tagged
/// JSON enum so the frontend can dispatch via the `kind` field.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureGuideView {
    None,
    /// Width:height aspect ratio for the rectangular overlay
    /// (passport ≈ 1.42, ID-1 ≈ 1.585).
    Rect {
        aspect: f32,
    },
    Oval,
}

/// The address an answer to a step goes to: the step's name under the version
/// of the session record it was rendered from.
///
/// Only a round's own write moves a running session's version on — another
/// tab's round, a reset, a reply lost after its write and the input sent again
/// all do — so an answer whose version is not the session's is for a step no
/// longer shown, and `/input` refuses it rather than take it as the answer to
/// whatever step came next.
pub(super) fn slot(version: u64, step: &str) -> String {
    format!("{version}.{step}")
}

/// A slot's version and step, as [`slot`] wrote them; `None` for anything else.
pub(super) fn parse_slot(slot_id: &str) -> Option<(u64, &str)> {
    let (version, step) = slot_id.split_once('.')?;
    Some((version.parse().ok()?, step))
}

/// A round's result as the applicant sees it, its step addressed under
/// `version`, the session record's as the round left it.
pub(super) fn progress_from(status: RunStatus, locale: &Locale, version: u64) -> SessionProgress {
    match status {
        RunStatus::Completed(decision) => SessionProgress::Completed {
            decision: decision.into(),
        },
        RunStatus::AwaitingInput(prompt) => SessionProgress::AwaitingInput {
            request: prompt_view(&prompt, locale, version),
        },
    }
}

/// `prompt` as the applicant sees it, its step addressed under `version`, the
/// session record's it was read from.
pub(super) fn prompt_view(prompt: &Prompt, locale: &Locale, version: u64) -> RequestView {
    match prompt {
        Prompt::Media(spec) => media_view(spec, locale, version),
        Prompt::ConsentDisclosure(d) => consent_view(d, locale, version),
    }
}

pub(super) fn consent_view(d: &PromptDisclosure, locale: &Locale, version: u64) -> RequestView {
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
        slot_id: slot(version, "consent"),
    }
}

fn media_view(spec: &MediaSpec, locale: &Locale, version: u64) -> RequestView {
    let captures: Vec<CaptureStepView> = spec
        .captures
        .iter()
        .map(|c| capture_step_view(c, locale))
        .collect();
    RequestView::Media {
        label: dto::pick_localized(&spec.label, locale),
        captures,
        // The prompt carries no fill state; the frontend walks the
        // capture steps from the first one and POSTs each in order.
        next_slot_id: slot(version, "media-0"),
        max_upload_bytes: crate::limits::APPLICANT_INPUT_BODY_LIMIT,
    }
}

fn capture_step_view(s: &CaptureStep, locale: &Locale) -> CaptureStepView {
    CaptureStepView {
        // Already the icon name (engine deref'd the ref); the frontend
        // draws it from its bundled library.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A step's address reads back as the version and the step it was written
    /// with, which is what `/input` compares against the session's.
    #[test]
    fn a_slot_reads_back_as_written() {
        assert_eq!(slot(7, "media-0"), "7.media-0");
        assert_eq!(parse_slot(&slot(7, "media-0")), Some((7, "media-0")));
        assert_eq!(
            parse_slot(&slot(u64::MAX, "consent")),
            Some((u64::MAX, "consent"))
        );
    }

    /// An address with no version is no address: an answer to a step rendered
    /// without one is refused, not taken for whichever step is current.
    #[test]
    fn a_slot_without_its_version_is_refused() {
        for unversioned in ["media-0", "consent", ".consent", "x.media-0", "-1.consent"] {
            assert_eq!(parse_slot(unversioned), None, "{unversioned}");
        }
    }

    /// Each step a prompt renders carries the version it was read at, so two
    /// renders of the same prompt — a retake — are two steps.
    #[test]
    fn a_rendered_step_is_addressed_under_its_version() {
        let consent = PromptDisclosure::default();
        match consent_view(&consent, &Locale::default(), 3) {
            RequestView::Consent { slot_id, .. } => assert_eq!(slot_id, "3.consent"),
            _ => panic!("a consent prompt renders a consent view"),
        }
        let media = MediaSpec::default();
        let first = media_view(&media, &Locale::default(), 3);
        let again = media_view(&media, &Locale::default(), 4);
        match (first, again) {
            (
                RequestView::Media {
                    next_slot_id: a, ..
                },
                RequestView::Media {
                    next_slot_id: b, ..
                },
            ) => {
                assert_eq!(a, "3.media-0");
                assert_ne!(a, b);
            }
            _ => panic!("a media prompt renders a media view"),
        }
    }
}
