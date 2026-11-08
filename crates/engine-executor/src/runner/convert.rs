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

use wasmtime::component::{Resource, ResourceTable};

use session_types::{
    CameraFacing as DCameraFacing, Capture, CaptureKind as DCaptureKind,
    CaptureStep as DCaptureStep, Decision as DDecision, Disclosure as DDisclosure,
    DisplayField as DDisplayField, Event, FaceSpec as DFaceSpec, FrameRange,
    HeadTurnSpec as DHeadTurnSpec, Localized as DLocalized, MediaSpec as DMediaSpec,
    OvalSpec as DOvalSpec, PhotoSpec as DPhotoSpec, Prompt, RectSpec as DRectSpec,
    StaticGuide as DStaticGuide, StaticSpec as DStaticSpec, VideoGuide as DVideoGuide,
    VideoSpec as DVideoSpec,
};

use crate::embedded::{DisclosureFieldRef, EmbeddedRegistry, IconRef, LocalizedRef};
use crate::enclavid::host_capture::capture as wit_capture;
use crate::enclavid::policy::types as wit_policy;
use crate::limits::{
    GUIDE_ASPECT_MAX, GUIDE_ASPECT_MIN, GUIDE_FACE_WIDTH_MAX, GUIDE_FACE_WIDTH_MIN,
    GUIDE_HEAD_TURN_DEGREES_MAX, GUIDE_HOLD_MS_MAX, GUIDE_OVAL_WIDTH_MAX, GUIDE_OVAL_WIDTH_MIN,
    GUIDE_STEPS_PER_UNIT, MAX_CAPTURE_STEPS, MAX_CONSENT_FIELDS, MAX_VALUE_LENGTH,
    MAX_VIDEO_GUIDES,
};
use crate::media::{PhotoRep, VideoRep};
use crate::sanitize;

// ---------------------------------------------------------------------
// Inbound: domain Event → WIT event (no refs)
// ---------------------------------------------------------------------

/// Lower a domain [`Event`] into the WIT `event` the policy's `handle`
/// consumes. The captured bytes don't cross into the policy's linear memory —
/// each capture is content-addressed (BLAKE3) and pushed into the run's
/// [`ResourceTable`] host-side as an unforgeable `photo` or `video` handle,
/// minted "warm": the bytes are in hand from `/input`, so no lazy pull is
/// needed. The policy receives one capture per step and forwards it to a
/// plugin. Minting handles needs `&mut table`, so this runs before the `handle`
/// call while the store is otherwise idle.
///
/// The `(hash, bytes)` pairs are NOT reported back. The orchestrator sent these
/// very bytes in this very event and derives the same BLAKE3 over them, so what
/// it would be receiving is a copy of what it already holds — from the process
/// it has the least reason to take copies from.
pub fn event_to_wit(
    table: &mut ResourceTable,
    event: Event,
) -> wasmtime::Result<wit_policy::Event> {
    Ok(match event {
        Event::Start => wit_policy::Event::Start,
        Event::ConsentDisclosure(accepted) => wit_policy::Event::ConsentDisclosure(accepted),
        Event::Media(result) => {
            let mut captures = Vec::with_capacity(result.captures.len());
            for capture in result.captures {
                captures.push(match capture {
                    Capture::Photo(jpeg) => {
                        wit_policy::Capture::Photo(table.push(PhotoRep::warm(jpeg))?)
                    }
                    Capture::Video(capture) => {
                        wit_policy::Capture::Video(wit_policy::VideoCapture {
                            video: table.push(VideoRep::warm(capture.video))?,
                            guides: capture.guides.into_iter().map(frame_range_to_wit).collect(),
                        })
                    }
                });
            }
            wit_policy::Event::Media(wit_policy::MediaResult { captures })
        }
        Event::TimedOut => wit_policy::Event::TimedOut,
    })
}

fn frame_range_to_wit(range: FrameRange) -> wit_policy::FrameRange {
    wit_policy::FrameRange {
        guide: video_guide_to_wit(range.guide),
        first: range.first,
        last: range.last,
    }
}

fn video_guide_to_wit(guide: DVideoGuide) -> wit_capture::VideoGuide {
    match guide {
        DVideoGuide::StaticGuide(s) => {
            wit_capture::VideoGuide::StaticGuide(wit_capture::StaticSpec {
                guide: static_guide_to_wit(s.guide),
                hold_ms: s.hold_ms,
            })
        }
        DVideoGuide::Face(f) => wit_capture::VideoGuide::Face(wit_capture::FaceSpec {
            width: f.width,
            hold_ms: f.hold_ms,
        }),
        DVideoGuide::HeadTurn(t) => wit_capture::VideoGuide::HeadTurn(wit_capture::HeadTurnSpec {
            degrees: t.degrees,
            hold_ms: t.hold_ms,
        }),
    }
}

fn static_guide_to_wit(guide: DStaticGuide) -> wit_capture::StaticGuide {
    match guide {
        DStaticGuide::Rect(r) => {
            wit_capture::StaticGuide::Rect(wit_capture::RectSpec { aspect: r.aspect })
        }
        DStaticGuide::Oval(o) => {
            wit_capture::StaticGuide::Oval(wit_capture::OvalSpec { width: o.width })
        }
    }
}

// ---------------------------------------------------------------------
// Ref-resource deref helpers
// ---------------------------------------------------------------------

/// Read a `localized-ref` handle into the text it resolved to.
fn localized(table: &ResourceTable, r: &Resource<LocalizedRef>) -> wasmtime::Result<DLocalized> {
    Ok(table.get(r)?.0.clone())
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
        wit_policy::Prompt::ConsentDisclosure(d) => Ok(Prompt::ConsentDisclosure(
            disclosure_to_domain(d, table, embedded)?,
        )),
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

/// Resolve refs on a media render and lower it. A spec of no steps, or of
/// more than [`MAX_CAPTURE_STEPS`], a time limit of no seconds, and a video
/// step of no guides, or of more than [`MAX_VIDEO_GUIDES`], trap: none is an
/// applicant's doing.
fn media_spec_to_domain(
    spec: wit_capture::MediaSpec,
    table: &ResourceTable,
) -> wasmtime::Result<DMediaSpec> {
    if spec.captures.is_empty() {
        return Err(wasmtime::Error::msg(
            "media render spec has no capture steps",
        ));
    }
    if spec.captures.len() > MAX_CAPTURE_STEPS {
        return Err(wasmtime::Error::msg(format!(
            "media render spec exceeds {MAX_CAPTURE_STEPS} capture steps"
        )));
    }
    if spec.time_limit_secs == Some(0) {
        return Err(wasmtime::Error::msg(
            "media render spec has a time limit of no seconds",
        ));
    }
    let label = localized(table, &spec.label)?;
    let captures = spec
        .captures
        .into_iter()
        .map(|c| capture_step_to_domain(c, table))
        .collect::<wasmtime::Result<Vec<_>>>()?;
    Ok(DMediaSpec {
        label,
        captures,
        time_limit_secs: spec.time_limit_secs,
    })
}

fn capture_step_to_domain(
    s: wit_capture::CaptureStep,
    table: &ResourceTable,
) -> wasmtime::Result<DCaptureStep> {
    let icon = match &s.icon {
        Some(r) => Some(icon_name(table, r)?),
        None => None,
    };
    let kind = match s.kind {
        wit_capture::CaptureKind::Photo(photo) => DCaptureKind::Photo(DPhotoSpec {
            guide: photo.guide.map(static_guide_to_domain),
            review_hint: localized(table, &photo.review_hint)?,
        }),
        wit_capture::CaptureKind::Video(video) => {
            if video.guides.is_empty() {
                return Err(wasmtime::Error::msg("a video capture step has no guides"));
            }
            if video.guides.len() > MAX_VIDEO_GUIDES {
                return Err(wasmtime::Error::msg(format!(
                    "a video capture step exceeds {MAX_VIDEO_GUIDES} guides"
                )));
            }
            DCaptureKind::Video(DVideoSpec {
                guides: video
                    .guides
                    .into_iter()
                    .map(video_guide_to_domain)
                    .collect(),
            })
        }
    };
    Ok(DCaptureStep {
        icon,
        instructions: localized(table, &s.instructions)?,
        label: localized(table, &s.label)?,
        camera: camera_to_domain(s.camera),
        kind,
    })
}

fn camera_to_domain(c: wit_capture::CameraFacing) -> DCameraFacing {
    match c {
        wit_capture::CameraFacing::Front => DCameraFacing::Front,
        wit_capture::CameraFacing::Rear => DCameraFacing::Rear,
        wit_capture::CameraFacing::Any => DCameraFacing::Any,
    }
}

/// A shape as it is drawn: its number held to its range and rounded, as the
/// WIT `static-guide` says of every guide.
fn static_guide_to_domain(g: wit_capture::StaticGuide) -> DStaticGuide {
    match g {
        wit_capture::StaticGuide::Rect(r) => DStaticGuide::Rect(DRectSpec {
            aspect: drawn_aspect(r.aspect),
        }),
        wit_capture::StaticGuide::Oval(o) => DStaticGuide::Oval(DOvalSpec {
            width: drawn(o.width, GUIDE_OVAL_WIDTH_MIN, GUIDE_OVAL_WIDTH_MAX, 0.5),
        }),
    }
}

/// A video's guide as it is shown: each of its numbers held to its range and
/// its fractions rounded.
fn video_guide_to_domain(g: wit_capture::VideoGuide) -> DVideoGuide {
    match g {
        wit_capture::VideoGuide::StaticGuide(s) => DVideoGuide::StaticGuide(DStaticSpec {
            guide: static_guide_to_domain(s.guide),
            hold_ms: s.hold_ms.min(GUIDE_HOLD_MS_MAX),
        }),
        wit_capture::VideoGuide::Face(f) => DVideoGuide::Face(DFaceSpec {
            width: drawn(f.width, GUIDE_FACE_WIDTH_MIN, GUIDE_FACE_WIDTH_MAX, 0.5),
            hold_ms: f.hold_ms.min(GUIDE_HOLD_MS_MAX),
        }),
        wit_capture::VideoGuide::HeadTurn(t) => DVideoGuide::HeadTurn(DHeadTurnSpec {
            degrees: t
                .degrees
                .clamp(-GUIDE_HEAD_TURN_DEGREES_MAX, GUIDE_HEAD_TURN_DEGREES_MAX),
            hold_ms: t.hold_ms.min(GUIDE_HOLD_MS_MAX),
        }),
    }
}

/// The aspect a `rect` guide is drawn at: the policy's, held to
/// [`GUIDE_ASPECT_MIN`]..=[`GUIDE_ASPECT_MAX`] and rounded; a square for
/// NaN, which has no place in the range.
fn drawn_aspect(aspect: f32) -> f32 {
    drawn(aspect, GUIDE_ASPECT_MIN, GUIDE_ASPECT_MAX, 1.0)
}

/// `value` held to `min..=max` and rounded to the step
/// [`GUIDE_STEPS_PER_UNIT`] sets; `nan` for NaN, which has no place in the
/// range.
fn drawn(value: f32, min: f32, max: f32, nan: f32) -> f32 {
    if value.is_nan() {
        return nan;
    }
    (value.clamp(min, max) * GUIDE_STEPS_PER_UNIT).round() / GUIDE_STEPS_PER_UNIT
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shape is drawn within its range, to hundredths. In a video every
    /// guide is held no longer than the longest hold, a face asked for at a
    /// size the page finds, and a head turned no further than a face in
    /// profile.
    #[test]
    fn a_guide_is_drawn_within_its_ranges() {
        let frame = video_guide_to_domain(wit_capture::VideoGuide::StaticGuide(
            wit_capture::StaticSpec {
                guide: wit_capture::StaticGuide::Rect(wit_capture::RectSpec { aspect: 1.42 }),
                hold_ms: u16::MAX,
            },
        ));
        assert_eq!(
            frame,
            DVideoGuide::StaticGuide(DStaticSpec {
                guide: DStaticGuide::Rect(DRectSpec { aspect: 1.42 }),
                hold_ms: GUIDE_HOLD_MS_MAX,
            })
        );
        for (given, drawn) in [
            (0.01, GUIDE_OVAL_WIDTH_MIN),
            (0.456_78, 0.46),
            (0.9, GUIDE_OVAL_WIDTH_MAX),
            (f32::NAN, 0.5),
        ] {
            let oval =
                static_guide_to_domain(wit_capture::StaticGuide::Oval(wit_capture::OvalSpec {
                    width: given,
                }));
            assert_eq!(
                oval,
                DStaticGuide::Oval(DOvalSpec { width: drawn }),
                "{given}"
            );
        }
        for (given, drawn) in [
            (0.1, GUIDE_FACE_WIDTH_MIN),
            (0.456_78, 0.46),
            (0.9, GUIDE_FACE_WIDTH_MAX),
            (f32::NAN, 0.5),
        ] {
            let face =
                video_guide_to_domain(wit_capture::VideoGuide::Face(wit_capture::FaceSpec {
                    width: given,
                    hold_ms: u16::MAX,
                }));
            assert_eq!(
                face,
                DVideoGuide::Face(DFaceSpec {
                    width: drawn,
                    hold_ms: GUIDE_HOLD_MS_MAX,
                }),
                "{given}"
            );
        }
        for (given, drawn) in [
            (i8::MIN, -GUIDE_HEAD_TURN_DEGREES_MAX),
            (30, 30),
            (i8::MAX, GUIDE_HEAD_TURN_DEGREES_MAX),
        ] {
            let turn = video_guide_to_domain(wit_capture::VideoGuide::HeadTurn(
                wit_capture::HeadTurnSpec {
                    degrees: given,
                    hold_ms: 700,
                },
            ));
            assert_eq!(
                turn,
                DVideoGuide::HeadTurn(DHeadTurnSpec {
                    degrees: drawn,
                    hold_ms: 700
                }),
                "{given}"
            );
        }
    }

    /// Inside the range an aspect is drawn to hundredths, and written out as
    /// no more than that: the digits past them carry nothing to the page.
    #[test]
    fn an_aspect_is_drawn_to_hundredths() {
        for (given, drawn) in [
            (1.42_f32, "1.42"),
            (1.419_999_9, "1.42"),
            (1.585, "1.59"),
            (1.234_567_8, "1.23"),
            (1.0, "1"),
        ] {
            assert_eq!(drawn_aspect(given).to_string(), drawn, "{given}");
        }
    }

    /// Past either end an aspect is drawn at that end, and NaN, which is
    /// neither, as a square.
    #[test]
    fn an_aspect_past_the_range_is_drawn_at_its_end() {
        for (given, drawn) in [
            (0.1_f32, GUIDE_ASPECT_MIN),
            (f32::NEG_INFINITY, GUIDE_ASPECT_MIN),
            (-3.0, GUIDE_ASPECT_MIN),
            (40_000.0, GUIDE_ASPECT_MAX),
            (f32::INFINITY, GUIDE_ASPECT_MAX),
            (f32::NAN, 1.0),
        ] {
            assert_eq!(drawn_aspect(given), drawn, "{given}");
        }
    }
}
