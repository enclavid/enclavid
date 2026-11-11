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
    DisplayField as DDisplayField, Event, FaceFlashesGuide as DFaceFlashesGuide,
    FaceGuide as DFaceGuide, FrameRange, HeadTurnGuide as DHeadTurnGuide, Localized as DLocalized,
    MediaSpec as DMediaSpec, OvalGuide as DOvalGuide, PhotoSpec as DPhotoSpec, Prompt,
    RectGuide as DRectGuide, Rgb as DRgb, StaticGuide as DStaticGuide,
    StaticVideoGuide as DStaticVideoGuide, VideoGuide as DVideoGuide, VideoSpec as DVideoSpec,
};

use crate::embedded::{DisclosureFieldRef, EmbeddedRegistry, IconRef, LocalizedRef};
use crate::enclavid::host_capture::{
    capture as wit_capture, photo as wit_photo, video as wit_video,
};
use crate::enclavid::policy::types as wit_policy;
use crate::limits::{
    GUIDE_ASPECT_MAX, GUIDE_ASPECT_MIN, GUIDE_FACE_WIDTH_MAX, GUIDE_FACE_WIDTH_MIN,
    GUIDE_FLASH_MS_MAX, GUIDE_FLASH_MS_MIN, GUIDE_GRACE_MS_MAX, GUIDE_HEAD_TURN_DEGREES_MAX,
    GUIDE_HOLD_MS_MAX, GUIDE_OVAL_WIDTH_MAX, GUIDE_OVAL_WIDTH_MIN, MAX_CAPTURE_STEPS,
    MAX_CONSENT_FIELDS, MAX_FLASH_COLORS, MAX_VALUE_LENGTH, MAX_VIDEO_GUIDES,
};
use crate::media::{PhotoRep, VideoRep};
use crate::sanitize;

// ---------------------------------------------------------------------
// Inbound: domain Event → WIT event (a static guide's text minted anew)
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
                        let video = table.push(VideoRep::warm(capture.video))?;
                        let guides = capture
                            .guides
                            .into_iter()
                            .map(|range| frame_range_to_wit(range, table))
                            .collect::<wasmtime::Result<_>>()?;
                        wit_policy::Capture::Video(wit_policy::VideoCapture { video, guides })
                    }
                });
            }
            wit_policy::Event::Media(Ok(captures))
        }
        Event::TimedOut => wit_policy::Event::Media(Err(wit_policy::MediaError::TimedOut)),
    })
}

/// A range as the policy gets it back: its guide's texts minted anew as the
/// handles they were asked with.
fn frame_range_to_wit(
    range: FrameRange,
    table: &mut ResourceTable,
) -> wasmtime::Result<wit_policy::FrameRange> {
    Ok(wit_policy::FrameRange {
        guide: video_guide_to_wit(range.guide, table)?,
        first: range.first,
        last: range.last,
    })
}

fn video_guide_to_wit(
    guide: DVideoGuide,
    table: &mut ResourceTable,
) -> wasmtime::Result<wit_video::VideoGuide> {
    Ok(match guide {
        DVideoGuide::StaticGuide(s) => {
            wit_video::VideoGuide::StaticGuide(wit_video::StaticVideoGuide {
                guide: static_guide_to_wit(s.guide),
                label: table.push(LocalizedRef(s.label))?,
                hold_ms: s.hold_ms,
            })
        }
        DVideoGuide::Face(f) => wit_video::VideoGuide::Face(wit_video::FaceGuide {
            width: f.width,
            hold_ms: f.hold_ms,
            grace_ms: f.grace_ms,
        }),
        DVideoGuide::HeadTurn(t) => wit_video::VideoGuide::HeadTurn(wit_video::HeadTurnGuide {
            degrees: t.degrees,
            hold_ms: t.hold_ms,
            grace_ms: t.grace_ms,
        }),
        DVideoGuide::FaceFlashes(f) => {
            wit_video::VideoGuide::FaceFlashes(wit_video::FaceFlashesGuide {
                width: f.width,
                colors: f
                    .colors
                    .into_iter()
                    .map(|c| wit_video::Rgb {
                        red: c.red,
                        green: c.green,
                        blue: c.blue,
                    })
                    .collect(),
                flash_ms: f.flash_ms,
                grace_ms: f.grace_ms,
            })
        }
    })
}

fn static_guide_to_wit(guide: DStaticGuide) -> wit_photo::StaticGuide {
    match guide {
        DStaticGuide::Rect(r) => {
            wit_photo::StaticGuide::Rect(wit_photo::RectGuide { aspect: r.aspect })
        }
        DStaticGuide::Oval(o) => {
            wit_photo::StaticGuide::Oval(wit_photo::OvalGuide { width: o.width })
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
/// more than [`MAX_CAPTURE_STEPS`], a time limit of no seconds, a video step
/// of no guides, or of more than [`MAX_VIDEO_GUIDES`], and flashes of no
/// colours, or of more than [`MAX_FLASH_COLORS`], trap: none is an applicant's
/// doing.
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
                    .map(|guide| video_guide_to_domain(guide, table))
                    .collect::<wasmtime::Result<Vec<_>>>()?,
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

/// A shape as it is drawn: its number held to its range, as the WIT
/// `static-guide` says of every guide.
fn static_guide_to_domain(g: wit_photo::StaticGuide) -> DStaticGuide {
    match g {
        wit_photo::StaticGuide::Rect(r) => DStaticGuide::Rect(DRectGuide {
            aspect: drawn_aspect(r.aspect),
        }),
        wit_photo::StaticGuide::Oval(o) => DStaticGuide::Oval(DOvalGuide {
            width: drawn(o.width, GUIDE_OVAL_WIDTH_MIN, GUIDE_OVAL_WIDTH_MAX, 0.5),
        }),
    }
}

/// A video's guide as it is shown: each of its numbers held to its range.
fn video_guide_to_domain(
    g: wit_video::VideoGuide,
    table: &ResourceTable,
) -> wasmtime::Result<DVideoGuide> {
    Ok(match g {
        wit_video::VideoGuide::StaticGuide(s) => DVideoGuide::StaticGuide(DStaticVideoGuide {
            guide: static_guide_to_domain(s.guide),
            label: localized(table, &s.label)?,
            hold_ms: s.hold_ms.min(GUIDE_HOLD_MS_MAX),
        }),
        wit_video::VideoGuide::Face(f) => DVideoGuide::Face(DFaceGuide {
            width: drawn(f.width, GUIDE_FACE_WIDTH_MIN, GUIDE_FACE_WIDTH_MAX, 0.5),
            hold_ms: f.hold_ms.min(GUIDE_HOLD_MS_MAX),
            grace_ms: f.grace_ms.min(GUIDE_GRACE_MS_MAX),
        }),
        wit_video::VideoGuide::HeadTurn(t) => {
            if t.degrees == 0 {
                return Err(wasmtime::Error::msg("a head-turn guide turns no degrees"));
            }
            DVideoGuide::HeadTurn(DHeadTurnGuide {
                degrees: t
                    .degrees
                    .clamp(-GUIDE_HEAD_TURN_DEGREES_MAX, GUIDE_HEAD_TURN_DEGREES_MAX),
                hold_ms: t.hold_ms.min(GUIDE_HOLD_MS_MAX),
                grace_ms: t.grace_ms.min(GUIDE_GRACE_MS_MAX),
            })
        }
        wit_video::VideoGuide::FaceFlashes(f) => {
            if f.colors.is_empty() {
                return Err(wasmtime::Error::msg("a face-flashes guide has no colours"));
            }
            if f.colors.len() > MAX_FLASH_COLORS {
                return Err(wasmtime::Error::msg(format!(
                    "a face-flashes guide exceeds {MAX_FLASH_COLORS} colours"
                )));
            }
            DVideoGuide::FaceFlashes(DFaceFlashesGuide {
                width: drawn(f.width, GUIDE_FACE_WIDTH_MIN, GUIDE_FACE_WIDTH_MAX, 0.5),
                colors: f
                    .colors
                    .into_iter()
                    .map(|c| DRgb {
                        red: c.red,
                        green: c.green,
                        blue: c.blue,
                    })
                    .collect(),
                flash_ms: f.flash_ms.clamp(GUIDE_FLASH_MS_MIN, GUIDE_FLASH_MS_MAX),
                grace_ms: f.grace_ms.min(GUIDE_GRACE_MS_MAX),
            })
        }
    })
}

/// The aspect a `rect` guide is drawn at: the policy's, held to
/// [`GUIDE_ASPECT_MIN`]..=[`GUIDE_ASPECT_MAX`]; a square for NaN, which has no
/// place in the range.
fn drawn_aspect(aspect: f32) -> f32 {
    drawn(aspect, GUIDE_ASPECT_MIN, GUIDE_ASPECT_MAX, 1.0)
}

/// `value` held to `min..=max`; `nan` for NaN, which has no place in the
/// range.
fn drawn(value: f32, min: f32, max: f32, nan: f32) -> f32 {
    if value.is_nan() {
        return nan;
    }
    value.clamp(min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A text as a catalog has it, in one language.
    fn text(words: &str) -> DLocalized {
        DLocalized {
            translations: vec![session_types::Translation {
                language: "en".into(),
                text: words.into(),
            }],
        }
    }

    /// A shape is drawn within its range. In a video every guide is held no
    /// longer than the longest hold, a face asked for at a size the page
    /// finds, and a head turned no further than a face in profile.
    #[test]
    fn a_guide_is_drawn_within_its_ranges() {
        let mut table = ResourceTable::new();
        let label = table.push(LocalizedRef(text("Your card"))).unwrap();
        let frame = video_guide_to_domain(
            wit_video::VideoGuide::StaticGuide(wit_video::StaticVideoGuide {
                guide: wit_photo::StaticGuide::Rect(wit_photo::RectGuide { aspect: 1.42 }),
                label,
                hold_ms: u16::MAX,
            }),
            &table,
        )
        .unwrap();
        assert_eq!(
            frame,
            DVideoGuide::StaticGuide(DStaticVideoGuide {
                guide: DStaticGuide::Rect(DRectGuide { aspect: 1.42 }),
                label: text("Your card"),
                hold_ms: GUIDE_HOLD_MS_MAX,
            })
        );
        for (given, drawn) in [
            (0.01, GUIDE_OVAL_WIDTH_MIN),
            (0.456_78, 0.456_78),
            (0.9, GUIDE_OVAL_WIDTH_MAX),
            (f32::NAN, 0.5),
        ] {
            let oval = static_guide_to_domain(wit_photo::StaticGuide::Oval(wit_photo::OvalGuide {
                width: given,
            }));
            assert_eq!(
                oval,
                DStaticGuide::Oval(DOvalGuide { width: drawn }),
                "{given}"
            );
        }
        for (given, drawn) in [
            (0.1, GUIDE_FACE_WIDTH_MIN),
            (0.456_78, 0.456_78),
            (0.9, GUIDE_FACE_WIDTH_MAX),
            (f32::NAN, 0.5),
        ] {
            let face = video_guide_to_domain(
                wit_video::VideoGuide::Face(wit_video::FaceGuide {
                    width: given,
                    hold_ms: u16::MAX,
                    grace_ms: u16::MAX,
                }),
                &table,
            )
            .unwrap();
            assert_eq!(
                face,
                DVideoGuide::Face(DFaceGuide {
                    width: drawn,
                    hold_ms: GUIDE_HOLD_MS_MAX,
                    grace_ms: GUIDE_GRACE_MS_MAX,
                }),
                "{given}"
            );
        }
        for (given, drawn) in [
            (i8::MIN, -GUIDE_HEAD_TURN_DEGREES_MAX),
            (30, 30),
            (i8::MAX, GUIDE_HEAD_TURN_DEGREES_MAX),
        ] {
            let turn = video_guide_to_domain(
                wit_video::VideoGuide::HeadTurn(wit_video::HeadTurnGuide {
                    degrees: given,
                    hold_ms: 700,
                    grace_ms: 300,
                }),
                &table,
            )
            .unwrap();
            assert_eq!(
                turn,
                DVideoGuide::HeadTurn(DHeadTurnGuide {
                    degrees: drawn,
                    hold_ms: 700,
                    grace_ms: 300,
                }),
                "{given}"
            );
        }
    }

    /// A turn of no degrees asks nothing of the head: the policy's error.
    #[test]
    fn a_turn_of_no_degrees_traps() {
        let turn = video_guide_to_domain(
            wit_video::VideoGuide::HeadTurn(wit_video::HeadTurnGuide {
                degrees: 0,
                hold_ms: 700,
                grace_ms: 300,
            }),
            &ResourceTable::new(),
        );
        assert!(turn.is_err());
    }

    /// Flashes are of a face at a size the page finds, each colour shown as the
    /// policy gave it, for no shorter and no longer than a flash may be.
    #[test]
    fn flashes_are_shown_within_their_ranges() {
        let colors = [(0, 0, 0), (255, 136, 0), (17, 34, 51)];
        let flashes = |width, flash_ms| {
            video_guide_to_domain(
                wit_video::VideoGuide::FaceFlashes(wit_video::FaceFlashesGuide {
                    width,
                    colors: colors
                        .iter()
                        .map(|&(red, green, blue)| wit_video::Rgb { red, green, blue })
                        .collect(),
                    flash_ms,
                    grace_ms: u16::MAX,
                }),
                &ResourceTable::new(),
            )
            .unwrap()
        };
        for (given, drawn) in [
            ((0.1, 0), (GUIDE_FACE_WIDTH_MIN, GUIDE_FLASH_MS_MIN)),
            ((0.456_78, 300), (0.456_78, 300)),
            ((f32::NAN, u16::MAX), (0.5, GUIDE_FLASH_MS_MAX)),
        ] {
            assert_eq!(
                flashes(given.0, given.1),
                DVideoGuide::FaceFlashes(DFaceFlashesGuide {
                    width: drawn.0,
                    colors: colors
                        .iter()
                        .map(|&(red, green, blue)| DRgb { red, green, blue })
                        .collect(),
                    flash_ms: drawn.1,
                    grace_ms: GUIDE_GRACE_MS_MAX,
                }),
                "{given:?}"
            );
        }
    }

    /// Flashes of no colours, or of more than a guide may show, are the
    /// policy's error, not the applicant's.
    #[test]
    fn flashes_of_no_colours_or_too_many_trap() {
        let flashes = |count| {
            video_guide_to_domain(
                wit_video::VideoGuide::FaceFlashes(wit_video::FaceFlashesGuide {
                    width: 0.5,
                    colors: vec![
                        wit_video::Rgb {
                            red: 255,
                            green: 255,
                            blue: 255,
                        };
                        count
                    ],
                    flash_ms: 300,
                    grace_ms: 300,
                }),
                &ResourceTable::new(),
            )
        };
        assert!(flashes(0).is_err());
        assert!(flashes(1).is_ok());
        assert!(flashes(MAX_FLASH_COLORS).is_ok());
        assert!(flashes(MAX_FLASH_COLORS + 1).is_err());
    }

    /// A range reaches the policy with the guide the prompt had, flashes with
    /// their colours.
    #[test]
    fn a_range_reaches_the_policy_with_its_guide() {
        let mut table = ResourceTable::new();
        let range = frame_range_to_wit(
            FrameRange {
                guide: DVideoGuide::FaceFlashes(DFaceFlashesGuide {
                    width: 0.5,
                    colors: vec![
                        DRgb {
                            red: 255,
                            green: 136,
                            blue: 0,
                        },
                        DRgb {
                            red: 0,
                            green: 10,
                            blue: 171,
                        },
                    ],
                    flash_ms: 300,
                    grace_ms: 250,
                }),
                first: 3,
                last: 9,
            },
            &mut table,
        )
        .unwrap();
        assert_eq!((range.first, range.last), (3, 9));
        let wit_video::VideoGuide::FaceFlashes(flashes) = range.guide else {
            panic!("the guide is not the prompt's");
        };
        assert_eq!(
            (flashes.width, flashes.flash_ms, flashes.grace_ms),
            (0.5, 300, 250)
        );
        let colors: Vec<_> = flashes
            .colors
            .iter()
            .map(|c| (c.red, c.green, c.blue))
            .collect();
        assert_eq!(colors, [(255, 136, 0), (0, 10, 171)]);
    }

    /// A static guide reaches the policy with its text, as a handle of its
    /// own to the text the prompt had.
    #[test]
    fn a_static_guide_reaches_the_policy_with_its_text() {
        let mut table = ResourceTable::new();
        let range = frame_range_to_wit(
            FrameRange {
                guide: DVideoGuide::StaticGuide(DStaticVideoGuide {
                    guide: DStaticGuide::Rect(DRectGuide { aspect: 1.585 }),
                    label: text("Your card"),
                    hold_ms: 500,
                }),
                first: 0,
                last: 7,
            },
            &mut table,
        )
        .unwrap();
        let wit_video::VideoGuide::StaticGuide(still) = range.guide else {
            panic!("the guide is not the prompt's");
        };
        assert_eq!(still.hold_ms, 500);
        assert_eq!(localized(&table, &still.label).unwrap(), text("Your card"));
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
