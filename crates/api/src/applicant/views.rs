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

use enclavid_engine::{Decision, EmbeddedRegistry, RunStatus};
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
        /// Surfaces the policy's full `disclosure-fields` vocabulary
        /// — the only embedded section that leaks raw keys into the
        /// consumer envelope. Frontend renders a footnote with
        /// `total_declared` vs `used_in_call` and an expand-toggle
        /// showing `all_keys` for drill-down audit (defends against
        /// suffix-style covert encodings the user could otherwise
        /// miss). Other kinds (`localized`, `icons`) don't reach the
        /// consumer envelope so their bandwidth isn't surfaced here.
        disclosure_schema: DisclosureSchema,
    },
}

/// Schema visibility for the composition's `disclosure-fields`
/// vocabulary. Built per-consent-screen so the applicant can audit
/// covert-channel bandwidth — the composition can only encode
/// `log2(total_declared)` bits per `DisplayField.key` position, and
/// "wide vocabulary with few shown" (`total_declared >>
/// used_in_call`) is the visual signal of possible synonym-encoding
/// (`country_a / country_b / …`).
///
/// Aggregates across the **whole composition** (the policy's catalog +
/// every plugin's) — plugins may legitimately declare DF keys too
/// (well-known auxiliary fields, e.g.). The same raw key declared by
/// multiple catalogs resolves to identical envelope output so we
/// deduplicate by string here: the count and the vocabulary list
/// reflect what the consumer can actually distinguish.
#[derive(Serialize)]
pub struct DisclosureSchema {
    /// Number of distinct `disclosure-field` keys across the
    /// composition after dedup. Engine-side per-component
    /// cardinality cap: [`MAX_DECLARED_DISCLOSURE_FIELDS`](
    /// enclavid_engine::limits::MAX_DECLARED_DISCLOSURE_FIELDS).
    pub total_declared: usize,
    /// How many of those keys this particular consent-disclosure
    /// prompt surfaces. `used_in_call ≤ MAX_CONSENT_FIELDS`.
    pub used_in_call: usize,
    /// Full deduplicated vocabulary, sorted alphabetically for
    /// stable display across rounds. Drill-down view on the consent
    /// screen — user can scroll and spot suffix patterns
    /// (`tier_001 .. tier_256`) that bare counts wouldn't catch.
    pub all_keys: Vec<String>,
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

pub(super) fn progress_from(
    status: RunStatus,
    embedded: &EmbeddedRegistry,
    locale: &Locale,
) -> SessionProgress {
    match status {
        RunStatus::Completed(decision) => SessionProgress::Completed {
            decision: decision_view(decision),
        },
        RunStatus::AwaitingInput(prompt) => SessionProgress::AwaitingInput {
            request: prompt_view(&prompt, embedded, locale),
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

fn prompt_view(
    prompt: &Prompt,
    embedded: &EmbeddedRegistry,
    locale: &Locale,
) -> RequestView {
    match prompt {
        Prompt::Media(spec) => media_view(spec, embedded, locale),
        Prompt::ConsentDisclosure(d) => consent_view(d, embedded, locale),
    }
}

fn consent_view(
    d: &PromptDisclosure,
    embedded: &EmbeddedRegistry,
    locale: &Locale,
) -> RequestView {
    let used_in_call = d.fields.len();
    // Aggregate disclosure-field keys across the whole composition (the
    // policy's catalog + every plugin's). The same raw key declared by
    // multiple catalogs resolves to the same envelope value — the
    // consumer can't tell which catalog resolved it — so we dedupe by
    // string for the audit view. `BTreeSet` gives the dedup AND the
    // canonical alphabetical ordering for stable display.
    let unique_keys: std::collections::BTreeSet<String> =
        embedded.disclosure_fields.declared().cloned().collect();
    let total_declared = unique_keys.len();
    let all_keys: Vec<String> = unique_keys.into_iter().collect();
    RequestView::Consent {
        fields: d
            .fields
            .iter()
            .map(|f| dto::consent_field_view_from_proto(f, embedded, locale))
            .collect(),
        reason: dto::resolve_localized(embedded, &d.reason_ref, locale),
        requester: dto::resolve_localized(embedded, &d.requester_ref, locale),
        disclosure_schema: DisclosureSchema {
            total_declared,
            used_in_call,
            all_keys,
        },
    }
}

fn media_view(
    spec: &MediaSpec,
    embedded: &EmbeddedRegistry,
    locale: &Locale,
) -> RequestView {
    let captures: Vec<CaptureStepView> = spec
        .captures
        .iter()
        .map(|c| capture_step_view(c, embedded, locale))
        .collect();
    RequestView::Media {
        label: dto::resolve_localized(embedded, &spec.label_ref, locale),
        captures,
        // The prompt carries no fill state; the frontend walks the
        // capture steps from the first one and POSTs each in order.
        next_slot_id: "media-0".to_string(),
    }
}

fn capture_step_view(
    s: &CaptureStep,
    embedded: &EmbeddedRegistry,
    locale: &Locale,
) -> CaptureStepView {
    CaptureStepView {
        // Icon-ref reverse-lookup → declared icon name. Frontend
        // dispatches against its bundled icon library and falls back
        // to no-icon on unknown names. Unresolvable tokens (engine
        // would have trapped on use-site validation already, but
        // graceful degrade) pass through verbatim.
        icon: s
            .icon_ref
            .as_deref()
            .and_then(|t| embedded.icons.lookup(t).cloned().or_else(|| Some(t.to_string()))),
        instructions: dto::resolve_localized(embedded,&s.instructions_ref, locale),
        label: dto::resolve_localized(embedded,&s.label_ref, locale),
        camera: camera_view(s.camera),
        guide: guide_view(s.guide.as_ref()),
        review_hint: dto::resolve_localized(embedded,&s.review_hint_ref, locale),
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
