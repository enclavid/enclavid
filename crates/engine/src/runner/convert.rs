//! WIT ⇄ sealed-domain conversions for the reducer boundary, plus the
//! embedded-ref validation applied to every rendered prompt.
//!
//! Direction map:
//!   * inbound  — domain [`Event`] → WIT `event` (fed to `handle`).
//!   * outbound — WIT `prompt` → domain [`Prompt`] (persisted +
//!     rendered), WIT `decision` → domain [`Decision`].
//!
//! Every embedded ref a rendered prompt carries (consent field
//! key/label, reason / requester, media labels / instructions / icons)
//! is validated against the composition's frozen [`EmbeddedRegistry`]
//! here, before the prompt is persisted as `current_prompt` or returned to
//! the runtime — the same gate the pre-reducer host fns enforced, just
//! relocated to the action-handling seam.

use broker_client::{
    CameraFacing as DCameraFacing, CaptureGuide as DCaptureGuide, CaptureStep as DCaptureStep,
    Decision as DDecision, DisplayField as DDisplayField, Event, GuideNone, GuideOval, GuideRect,
    MediaSpec as DMediaSpec, Prompt, PromptDisclosure as DDisclosure, capture_guide,
};

use crate::embedded::EmbeddedRegistry;
use crate::enclavid::policy::types as wit_policy;
use crate::enclavid::shared_types::capture as wit_capture;
use crate::enclavid::shared_types::disclosure as wit_disclosure;
use crate::sanitize;

// ---------------------------------------------------------------------
// Inbound: domain Event → WIT event
// ---------------------------------------------------------------------

/// Lower a domain [`Event`] into the WIT `event` the policy's `handle`
/// consumes. Media clips ride through verbatim — they are opaque JPEG
/// frames, no refs to validate.
pub fn event_to_wit(
    event: Event,
    _embedded: &EmbeddedRegistry,
) -> wasmtime::Result<wit_policy::Event> {
    Ok(match event {
        Event::Start => wit_policy::Event::Start,
        Event::ConsentDisclosure(accepted) => wit_policy::Event::ConsentDisclosure(accepted),
        Event::Media(result) => wit_policy::Event::Media(wit_policy::MediaResult {
            slot: result.slot,
            clip: result.clip.frames,
        }),
    })
}

// ---------------------------------------------------------------------
// Outbound: WIT prompt → domain Prompt (validated)
// ---------------------------------------------------------------------

/// Lift a rendered WIT `prompt` into the domain [`Prompt`] persisted as
/// `current_prompt`, validating + sanitising every embedded ref it carries.
pub fn prompt_to_domain(
    prompt: wit_policy::Prompt,
    embedded: &EmbeddedRegistry,
) -> wasmtime::Result<Prompt> {
    match prompt {
        wit_policy::Prompt::Media(spec) => {
            validate_media_spec(&spec, embedded)?;
            Ok(Prompt::Media(media_spec_to_domain(spec)))
        }
        wit_policy::Prompt::ConsentDisclosure(disclosure) => {
            Ok(Prompt::ConsentDisclosure(disclosure_to_domain(disclosure, embedded)?))
        }
    }
}

pub fn decision_to_domain(d: wit_policy::Decision) -> DDecision {
    match d {
        wit_policy::Decision::Approved => DDecision::Approved,
        wit_policy::Decision::Rejected => DDecision::Rejected,
        wit_policy::Decision::RejectedRetryable => DDecision::RejectedRetryable,
        wit_policy::Decision::Review => DDecision::Review,
    }
}

// ---------------------------------------------------------------------
// Consent disclosure — validate + sanitise + lower
// ---------------------------------------------------------------------

/// Validate refs on a consent-disclosure render and lower it to the
/// domain record. `fields` keys/labels go through `validate_fields`
/// (the single bandwidth gate to the consumer); `reason` / `requester`
/// are localized refs resolved through the composition's registry.
fn disclosure_to_domain(
    d: wit_policy::Disclosure,
    embedded: &EmbeddedRegistry,
) -> wasmtime::Result<DDisclosure> {
    // `validate_fields` operates on the bindgen `DisplayField` type —
    // it is the same gate the old `prompt_disclosure` host fn applied.
    sanitize::validate_fields(&d.fields, embedded)?;
    sanitize::ensure_localized(
        &d.reason,
        &embedded.localized,
        "consent-disclosure reason",
    )?;
    sanitize::ensure_localized(
        &d.requester,
        &embedded.localized,
        "consent-disclosure requester",
    )?;
    let fields = sanitize::sanitize_fields(d.fields)
        .into_iter()
        .map(display_field_to_domain)
        .collect();
    Ok(DDisclosure {
        fields,
        reason_ref: d.reason,
        requester_ref: d.requester,
    })
}

fn display_field_to_domain(f: wit_disclosure::DisplayField) -> DDisplayField {
    DDisplayField {
        key: f.key,
        label: f.label,
        value: f.value,
    }
}

// ---------------------------------------------------------------------
// Media spec — validate + lower
// ---------------------------------------------------------------------

/// Format + registration check for every embedded ref inside a
/// `media-spec`. Every ref must be in the composition's frozen
/// `EmbeddedRegistry`, blocking runtime-crafted refs encoded with
/// per-session user info and cross-component forgery. Relocated here
/// from the deleted `host/media.rs` `validate_media_spec`.
fn validate_media_spec(
    spec: &wit_capture::MediaSpec,
    embedded: &EmbeddedRegistry,
) -> wasmtime::Result<()> {
    if spec.captures.is_empty() {
        return Err(wasmtime::Error::msg(
            "media render spec has no capture steps",
        ));
    }
    sanitize::ensure_localized(&spec.label, &embedded.localized, "media spec label")?;
    for step in &spec.captures {
        if let Some(icon) = &step.icon {
            sanitize::ensure_icon(icon, &embedded.icons, "media capture-step icon")?;
        }
        sanitize::ensure_localized(
            &step.instructions,
            &embedded.localized,
            "media capture-step instructions",
        )?;
        sanitize::ensure_localized(
            &step.label,
            &embedded.localized,
            "media capture-step label",
        )?;
        sanitize::ensure_localized(
            &step.review_hint,
            &embedded.localized,
            "media capture-step review-hint",
        )?;
    }
    Ok(())
}

fn media_spec_to_domain(s: wit_capture::MediaSpec) -> DMediaSpec {
    DMediaSpec {
        label_ref: s.label,
        captures: s.captures.into_iter().map(capture_step_to_domain).collect(),
    }
}

fn capture_step_to_domain(s: wit_capture::CaptureStep) -> DCaptureStep {
    DCaptureStep {
        icon_ref: s.icon,
        instructions_ref: s.instructions,
        label_ref: s.label,
        camera: camera_to_domain(s.camera),
        guide: Some(guide_to_domain(s.guide)),
        review_hint_ref: s.review_hint,
    }
}

fn camera_to_domain(c: wit_capture::CameraFacing) -> DCameraFacing {
    match c {
        wit_capture::CameraFacing::Front => DCameraFacing::Front,
        wit_capture::CameraFacing::Rear => DCameraFacing::Rear,
        wit_capture::CameraFacing::Any => DCameraFacing::Any,
    }
}

fn guide_to_domain(g: wit_capture::CaptureGuide) -> DCaptureGuide {
    let kind = match g {
        wit_capture::CaptureGuide::None => capture_guide::Kind::None(GuideNone {}),
        wit_capture::CaptureGuide::Rect(aspect) => {
            capture_guide::Kind::Rect(GuideRect { aspect })
        }
        wit_capture::CaptureGuide::Oval => capture_guide::Kind::Oval(GuideOval {}),
    };
    DCaptureGuide { kind: Some(kind) }
}
