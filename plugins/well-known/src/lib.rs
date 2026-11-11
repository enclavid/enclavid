//! `enclavid:well-known` — canonical KYC field labels, standard guides and
//! pre-baked captures. Drop-in helpers so policy authors don't hand-roll
//! text-refs for standard data shapes.
//!
//! Every ref this plugin hands back (localized label, icon) is minted by
//! the host, which a component cannot do for itself: a text is a case of
//! the `key` of this plugin's slot, `enclavid-ext:well-known/i18n`, which
//! its catalog has a text for, and an icon is one of the host's own, one
//! function each in `enclavid:host-icons/icons`. A field's key is the
//! policy's, minted from its own list, which the helpers take.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:well-known/well-known@0.1.0",
    generate_all,
});

mod sets;

use enclavid::host::refs::{DisclosureFieldRef, IconRef};
use enclavid::host_capture::capture::{CameraFacing, CaptureKind, CaptureStep, MediaSpec};
use enclavid::host_capture::photo::{OvalGuide, PhotoSpec, RectGuide, StaticGuide};
use enclavid::host_capture::video::{
    FaceFlashesGuide, FaceGuide, HeadTurnGuide, Rgb, VideoGuide, VideoSpec,
};
use enclavid::host_disclosure::disclosure::DisplayField;
use enclavid::host_icons::icons;
use enclavid_ext::well_known::i18n::{Key, localized};
use exports::enclavid::well_known::disclosure_fields::Guest as DisclosureFieldsGuest;
use exports::enclavid::well_known::photo::Guest as PhotoGuest;
use exports::enclavid::well_known::static_guides::Guest as StaticGuidesGuest;
use exports::enclavid::well_known::video::Guest as VideoGuest;
use exports::enclavid::well_known::video_guides::Guest as VideoGuidesGuest;

struct WellKnown;

// ─── disclosure-fields ────────────────────────────────────────────

/// A `DisplayField` of the policy's `field`, shown by the text `label`.
fn labelled(field: DisclosureFieldRef, label: Key, value: String) -> DisplayField {
    DisplayField {
        key: field,
        label: localized(label),
        value,
    }
}

impl DisclosureFieldsGuest for WellKnown {
    // Document identifiers
    fn passport_number(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::PassportNumberLabel, value)
    }
    fn id_card_number(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::IdCardNumberLabel, value)
    }
    fn drivers_license_number(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DriversLicenseNumberLabel, value)
    }
    fn document_issuing_country(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DocumentIssuingCountryLabel, value)
    }
    fn document_expiry(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DocumentExpiryLabel, value)
    }
    fn document_issued(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DocumentIssuedLabel, value)
    }

    // Identity
    fn given_name(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::GivenNameLabel, value)
    }
    fn family_name(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::FamilyNameLabel, value)
    }
    fn full_name(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::FullNameLabel, value)
    }
    fn date_of_birth(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DateOfBirthLabel, value)
    }
    fn sex(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::SexLabel, value)
    }
    fn nationality(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::NationalityLabel, value)
    }

    // Contact / location
    fn residence_country(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::ResidenceCountryLabel, value)
    }
    fn address(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::AddressLabel, value)
    }
    fn email(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::EmailLabel, value)
    }
    fn phone(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::PhoneLabel, value)
    }

    // Other
    fn tax_id(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::TaxIdLabel, value)
    }
}

// ─── static-guides ────────────────────────────────────────────────

/// The frame of an ICAO TD3 passport photo page (125x88mm → ~1.42).
const PASSPORT_FRAME: StaticGuide = StaticGuide::Rect(RectGuide { aspect: 1.42 });
/// The frame of an ICAO TD1 ID-1 card (85.6x54mm → ~1.585).
const CARD_FRAME: StaticGuide = StaticGuide::Rect(RectGuide { aspect: 1.585 });
/// A selfie's face oval: half the frame's shorter side wide.
const SELFIE_OVAL: StaticGuide = StaticGuide::Oval(OvalGuide { width: 0.5 });

impl StaticGuidesGuest for WellKnown {
    fn passport_frame() -> StaticGuide {
        PASSPORT_FRAME
    }
    fn card_frame() -> StaticGuide {
        CARD_FRAME
    }
    fn selfie_oval() -> StaticGuide {
        SELFIE_OVAL
    }
}

// ─── video-guides ─────────────────────────────────────────────────

/// How long the face is held in its oval, in milliseconds.
const FACE_HOLD_MS: u16 = 800;
/// How long each colour is flashed, in milliseconds.
const FLASH_MS: u16 = 300;
/// How long a turn of the head is held, in milliseconds.
const TURN_HOLD_MS: u16 = 500;
/// The longest break in a guide's hold the page forgives, in milliseconds.
const GRACE_MS: u16 = 300;

impl VideoGuidesGuest for WellKnown {
    fn liveness_turns(seed: u32) -> Vec<VideoGuide> {
        let sets::Turns { width, turns } = sets::turns(seed);
        let mut guides = vec![face(width)];
        guides.extend(turns.map(|degrees| {
            VideoGuide::HeadTurn(HeadTurnGuide {
                degrees,
                hold_ms: TURN_HOLD_MS,
                grace_ms: GRACE_MS,
            })
        }));
        guides
    }

    fn liveness_colors(seed: u32) -> Vec<VideoGuide> {
        let sets::Colors { width, colors } = sets::colors(seed);
        let colors = colors
            .into_iter()
            .map(|(red, green, blue)| Rgb { red, green, blue })
            .collect();
        vec![
            face(width),
            VideoGuide::FaceFlashes(FaceFlashesGuide {
                width,
                colors,
                flash_ms: FLASH_MS,
                grace_ms: GRACE_MS,
            }),
        ]
    }
}

/// The face held in an oval `width` of the frame's shorter side wide.
fn face(width: f32) -> VideoGuide {
    VideoGuide::Face(FaceGuide {
        width,
        hold_ms: FACE_HOLD_MS,
        grace_ms: GRACE_MS,
    })
}

// ─── video ────────────────────────────────────────────────────────

/// The seconds a liveness video's guides are given together.
const LIVENESS_TIME_LIMIT_SECS: u16 = 60;

impl VideoGuest for WellKnown {
    fn liveness(guides: Vec<VideoGuide>) -> MediaSpec {
        MediaSpec {
            label: localized(Key::LivenessTitle),
            captures: vec![CaptureStep {
                icon: Some(icons::selfie()),
                instructions: localized(Key::LivenessInstructions),
                label: localized(Key::LivenessStep),
                camera: CameraFacing::Front,
                kind: CaptureKind::Video(VideoSpec { guides }),
            }],
            time_limit_secs: Some(LIVENESS_TIME_LIMIT_SECS),
        }
    }
}

// ─── photo ────────────────────────────────────────────────────────

/// The three texts of a capture step.
struct StepTexts {
    instructions: Key,
    label: Key,
    review_hint: Key,
}

/// Build a photo step, minting its texts through the host.
fn step(
    texts: StepTexts,
    icon: Option<IconRef>,
    camera: CameraFacing,
    guide: StaticGuide,
) -> CaptureStep {
    CaptureStep {
        icon,
        instructions: localized(texts.instructions),
        label: localized(texts.label),
        camera,
        kind: CaptureKind::Photo(PhotoSpec {
            guide: Some(guide),
            review_hint: localized(texts.review_hint),
        }),
    }
}

fn passport_step() -> CaptureStep {
    step(
        StepTexts {
            instructions: Key::PassportInstructions,
            label: Key::PassportStep,
            review_hint: Key::PassportReviewHint,
        },
        Some(icons::passport()),
        CameraFacing::Rear,
        PASSPORT_FRAME,
    )
}

fn id_card_front_step_inner() -> CaptureStep {
    step(
        StepTexts {
            instructions: Key::IdCardFrontInstructions,
            label: Key::IdCardFrontStep,
            review_hint: Key::IdCardFrontReviewHint,
        },
        Some(icons::id_card()),
        CameraFacing::Rear,
        CARD_FRAME,
    )
}

fn id_card_back_step_inner() -> CaptureStep {
    step(
        StepTexts {
            instructions: Key::IdCardBackInstructions,
            label: Key::IdCardBackStep,
            review_hint: Key::IdCardBackReviewHint,
        },
        Some(icons::id_card()),
        CameraFacing::Rear,
        CARD_FRAME,
    )
}

fn drivers_license_front_step_inner() -> CaptureStep {
    step(
        StepTexts {
            instructions: Key::DriversLicenseFrontInstructions,
            label: Key::DriversLicenseFrontStep,
            review_hint: Key::DriversLicenseFrontReviewHint,
        },
        Some(icons::drivers_license()),
        CameraFacing::Rear,
        CARD_FRAME,
    )
}

fn drivers_license_back_step_inner() -> CaptureStep {
    step(
        StepTexts {
            instructions: Key::DriversLicenseBackInstructions,
            label: Key::DriversLicenseBackStep,
            review_hint: Key::DriversLicenseBackReviewHint,
        },
        Some(icons::drivers_license()),
        CameraFacing::Rear,
        CARD_FRAME,
    )
}

fn selfie_step_inner() -> CaptureStep {
    step(
        StepTexts {
            instructions: Key::SelfieInstructions,
            label: Key::SelfieStep,
            review_hint: Key::SelfieReviewHint,
        },
        Some(icons::selfie()),
        CameraFacing::Front,
        SELFIE_OVAL,
    )
}

impl PhotoGuest for WellKnown {
    fn passport() -> MediaSpec {
        MediaSpec {
            label: localized(Key::PassportTitle),
            captures: vec![passport_step()],
            time_limit_secs: None,
        }
    }

    fn id_card() -> MediaSpec {
        MediaSpec {
            label: localized(Key::IdCardTitle),
            captures: vec![id_card_front_step_inner(), id_card_back_step_inner()],
            time_limit_secs: None,
        }
    }

    fn drivers_license() -> MediaSpec {
        MediaSpec {
            label: localized(Key::DriversLicenseTitle),
            captures: vec![
                drivers_license_front_step_inner(),
                drivers_license_back_step_inner(),
            ],
            time_limit_secs: None,
        }
    }

    fn selfie() -> MediaSpec {
        MediaSpec {
            label: localized(Key::SelfieTitle),
            captures: vec![selfie_step_inner()],
            time_limit_secs: None,
        }
    }

    fn id_card_front_step() -> CaptureStep {
        id_card_front_step_inner()
    }
    fn id_card_back_step() -> CaptureStep {
        id_card_back_step_inner()
    }
    fn drivers_license_front_step() -> CaptureStep {
        drivers_license_front_step_inner()
    }
    fn drivers_license_back_step() -> CaptureStep {
        drivers_license_back_step_inner()
    }
}

export!(WellKnown);
