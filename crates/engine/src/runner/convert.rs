//! WIT ⇄ sealed-domain conversions for the reducer boundary.
//!
//! Direction map:
//!   * inbound  — domain [`Event`] → WIT `event` (fed to `handle`).
//!   * outbound — WIT `prompt` → domain [`Prompt`], WIT `decision` →
//!     domain [`Decision`].
//!
//! Every embedded ref a rendered prompt carries (consent field
//! key/label, reason / requester, media labels / instructions / icons)
//! is an unforgeable WIT `resource` handle into the run's
//! [`ResourceTable`]. The policy can't fabricate one, so there is
//! nothing to validate here — instead the engine DEREFERENCES each
//! handle to the resolved data the host minted (translations / icon
//! name / DF key) and builds the self-contained sealed [`Prompt`]. The
//! store-bound handles can't cross the engine→api seam, so this deref is
//! the single point resolution happens; the api later only picks a
//! locale from the carried translation sets. Disclosure field-count and
//! value-length limits are enforced here, at the build seam.

use std::sync::Arc;

use wasmtime::component::{Resource, ResourceTable};

use broker_client::{
    CameraFacing as DCameraFacing, CaptureGuide as DCaptureGuide, CaptureStep as DCaptureStep,
    Decision as DDecision, DisplayField as DDisplayField, Event, GuideNone, GuideOval, GuideRect,
    Localized as DLocalized, MediaSpec as DMediaSpec, Prompt, PromptDisclosure as DDisclosure,
    Translation as DTranslation, capture_guide,
};

use crate::embedded::{DisclosureFieldRef, EmbeddedRegistry, IconRef, LocalizedRef};
use crate::enclavid::policy::types as wit_policy;
use crate::enclavid::shared_types::capture as wit_capture;
use crate::limits::{MAX_CONSENT_FIELDS, MAX_VALUE_LENGTH};
use crate::listener::CapturedMedia;
use crate::sanitize;

// ---------------------------------------------------------------------
// Inbound: domain Event → WIT event (no refs)
// ---------------------------------------------------------------------

/// Lower a domain [`Event`] into the WIT `event` the policy's `handle`
/// consumes, plus the [`CapturedMedia`] to seal this round (media events
/// only). The captured pixels don't cross into the policy's linear memory —
/// each frame is content-addressed (BLAKE3) and pushed into the run's
/// [`ResourceTable`] host-side as an unforgeable `frame` handle; the policy
/// receives a `clip` record bundling the handles and forwards one to a
/// plugin. The same `(hash, bytes)` set is returned as [`CapturedMedia`] so
/// the runner hands it to the listener for atomic sealing into the blob
/// store. Minting handles needs `&mut table`, so this runs before the
/// `handle` call while the store is otherwise idle.
pub fn event_to_wit(
    table: &mut ResourceTable,
    event: Event,
) -> wasmtime::Result<(wit_policy::Event, Option<CapturedMedia>)> {
    Ok(match event {
        Event::Start => (wit_policy::Event::Start, None),
        Event::ConsentDisclosure(accepted) => {
            (wit_policy::Event::ConsentDisclosure(accepted), None)
        }
        Event::Media(result) => {
            let mut frames = Vec::with_capacity(result.clip.frames.len());
            let mut blobs = Vec::with_capacity(result.clip.frames.len());
            for frame_bytes in result.clip.frames {
                let hash: [u8; 32] = blake3::hash(&frame_bytes).into();
                let arc = Arc::new(frame_bytes);
                // Ingest blob: bytes are in hand from `/input`, so it's minted
                // "warm" (`Some`) — no lazy pull needed. Only rehydrated
                // (`from-blob-ref`) blobs start cold.
                let handle = table.push(crate::media::BlobRep {
                    bytes: Some(arc.clone()),
                    content_hash: hash,
                })?;
                frames.push(handle);
                blobs.push((hash, arc));
            }
            let clip = wit_policy::Clip { frames };
            let event = wit_policy::Event::Media(wit_policy::MediaResult {
                slot: result.slot,
                clip,
            });
            (event, Some(CapturedMedia { blobs }))
        }
    })
}

// ---------------------------------------------------------------------
// Ref-resource deref helpers
// ---------------------------------------------------------------------

/// Read a `localized-ref` handle into the resolved translation set.
fn localized(table: &ResourceTable, r: &Resource<LocalizedRef>) -> wasmtime::Result<DLocalized> {
    let reps = &table.get(r)?.0;
    Ok(DLocalized {
        translations: reps
            .iter()
            .map(|t| DTranslation {
                language: t.language.clone(),
                text: t.text.clone(),
            })
            .collect(),
    })
}

/// Read an `icon-ref` handle into the resolved icon name.
fn icon_name(table: &ResourceTable, r: &Resource<IconRef>) -> wasmtime::Result<String> {
    Ok(table.get(r)?.0.clone())
}

/// Read a `disclosure-field-ref` handle into the resolved machine key.
fn df_key(table: &ResourceTable, r: &Resource<DisclosureFieldRef>) -> wasmtime::Result<String> {
    Ok(table.get(r)?.0.clone())
}

// ---------------------------------------------------------------------
// Outbound: WIT prompt → domain Prompt (resolved)
// ---------------------------------------------------------------------

/// Lift a rendered WIT `prompt` into the domain [`Prompt`] persisted as
/// `current_prompt`, resolving every ref handle it carries. `embedded`
/// is consulted only for the disclosure's `total_declared` count.
pub fn prompt_to_domain(
    prompt: wit_policy::Prompt,
    table: &ResourceTable,
    embedded: &EmbeddedRegistry,
) -> wasmtime::Result<Prompt> {
    match prompt {
        wit_policy::Prompt::Media(spec) => Ok(Prompt::Media(media_spec_to_domain(spec, table)?)),
        wit_policy::Prompt::ConsentDisclosure(d) => {
            Ok(Prompt::ConsentDisclosure(disclosure_to_domain(d, table, embedded)?))
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
// Consent disclosure — resolve + sanitise + lower
// ---------------------------------------------------------------------

/// Resolve refs on a consent-disclosure render and lower it. Enforces the
/// field-count and value-length limits (a breach is a covert-channel
/// attempt or a policy bug, not user input, so it traps). `value` is
/// sanitised; `key` / `label` / `reason` / `requester` are resolved from
/// their ref handles.
fn disclosure_to_domain(
    d: wit_policy::Disclosure,
    table: &ResourceTable,
    embedded: &EmbeddedRegistry,
) -> wasmtime::Result<DDisclosure> {
    if d.fields.len() > MAX_CONSENT_FIELDS {
        return Err(wasmtime::Error::msg(format!(
            "consent-disclosure exceeds {MAX_CONSENT_FIELDS} fields"
        )));
    }
    let mut fields = Vec::with_capacity(d.fields.len());
    for f in d.fields {
        if f.value.len() > MAX_VALUE_LENGTH {
            return Err(wasmtime::Error::msg(format!(
                "consent-disclosure value exceeds {MAX_VALUE_LENGTH} bytes"
            )));
        }
        fields.push(DDisplayField {
            key: df_key(table, &f.key)?,
            label: localized(table, &f.label)?,
            value: sanitize::sanitize_string(&f.value),
        });
    }
    Ok(DDisclosure {
        fields,
        reason: localized(table, &d.reason)?,
        requester: localized(table, &d.requester)?,
        total_declared: embedded.disclosure_fields.distinct_declared_count(),
    })
}

// ---------------------------------------------------------------------
// Media spec — resolve + lower
// ---------------------------------------------------------------------

fn media_spec_to_domain(
    spec: wit_capture::MediaSpec,
    table: &ResourceTable,
) -> wasmtime::Result<DMediaSpec> {
    if spec.captures.is_empty() {
        return Err(wasmtime::Error::msg("media render spec has no capture steps"));
    }
    let label = localized(table, &spec.label)?;
    let captures = spec
        .captures
        .into_iter()
        .map(|c| capture_step_to_domain(c, table))
        .collect::<wasmtime::Result<Vec<_>>>()?;
    Ok(DMediaSpec { label, captures })
}

fn capture_step_to_domain(
    s: wit_capture::CaptureStep,
    table: &ResourceTable,
) -> wasmtime::Result<DCaptureStep> {
    let icon = match &s.icon {
        Some(r) => Some(icon_name(table, r)?),
        None => None,
    };
    Ok(DCaptureStep {
        icon,
        instructions: localized(table, &s.instructions)?,
        label: localized(table, &s.label)?,
        camera: camera_to_domain(s.camera),
        guide: Some(guide_to_domain(s.guide)),
        review_hint: localized(table, &s.review_hint)?,
    })
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
        wit_capture::CaptureGuide::Rect(aspect) => capture_guide::Kind::Rect(GuideRect { aspect }),
        wit_capture::CaptureGuide::Oval => capture_guide::Kind::Oval(GuideOval {}),
    };
    DCaptureGuide { kind: Some(kind) }
}
