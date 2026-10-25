//! `enclavid:well-known` — canonical KYC field labels and pre-baked
//! capture flows. Drop-in helpers so policy authors don't hand-roll
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

use enclavid::host::types::{DisclosureFieldRef, IconRef};
use enclavid::host_icons::icons;
use enclavid::shared_types::capture::{CameraFacing, CaptureGuide, CaptureStep, MediaSpec};
use enclavid::shared_types::disclosure::DisplayField;
use enclavid_ext::well_known::i18n::{Key, localized};
use exports::enclavid::well_known::capture::Guest as CaptureGuest;
use exports::enclavid::well_known::disclosure_fields::Guest as DisclosureFieldsGuest;

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

// ─── capture ──────────────────────────────────────────────────────

/// ICAO TD3 passport photo-page aspect (125x88mm → ~1.42).
const PASSPORT_ASPECT: f32 = 1.42;
/// ICAO TD1 ID-1 card aspect (85.6x54mm → ~1.585).
const ID1_ASPECT: f32 = 1.585;

/// The three texts of a capture step.
struct StepTexts {
    instructions: Key,
    label: Key,
    review_hint: Key,
}

/// Build a CaptureStep, minting its texts through the host.
fn step(
    texts: StepTexts,
    icon: Option<IconRef>,
    camera: CameraFacing,
    guide: CaptureGuide,
) -> CaptureStep {
    CaptureStep {
        icon,
        instructions: localized(texts.instructions),
        label: localized(texts.label),
        camera,
        guide,
        review_hint: localized(texts.review_hint),
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
        CaptureGuide::Rect(PASSPORT_ASPECT),
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
        CaptureGuide::Rect(ID1_ASPECT),
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
        CaptureGuide::Rect(ID1_ASPECT),
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
        CaptureGuide::Rect(ID1_ASPECT),
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
        CaptureGuide::Rect(ID1_ASPECT),
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
        CaptureGuide::Oval,
    )
}

impl CaptureGuest for WellKnown {
    fn passport() -> MediaSpec {
        MediaSpec {
            label: localized(Key::PassportTitle),
            captures: vec![passport_step()],
        }
    }

    fn id_card() -> MediaSpec {
        MediaSpec {
            label: localized(Key::IdCardTitle),
            captures: vec![id_card_front_step_inner(), id_card_back_step_inner()],
        }
    }

    fn drivers_license() -> MediaSpec {
        MediaSpec {
            label: localized(Key::DriversLicenseTitle),
            captures: vec![
                drivers_license_front_step_inner(),
                drivers_license_back_step_inner(),
            ],
        }
    }

    fn selfie() -> MediaSpec {
        MediaSpec {
            label: localized(Key::SelfieTitle),
            captures: vec![selfie_step_inner()],
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
