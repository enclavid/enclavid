//! `enclavid:well-known` — canonical KYC field strings and pre-baked
//! capture flows. Drop-in helpers so policy authors don't hand-roll
//! text-refs for standard data shapes.
//!
//! Every ref this plugin hands back (disclosure-field key, localized
//! label, icon) is minted by the host, which a component cannot do for
//! itself. A disclosure-field key resolves against the composition's
//! lists — a key none declares traps at use — and a text is a case of
//! this plugin's own `i18n` key, which its catalog has a text for. An
//! icon is one of the host's own, one function each in
//! `enclavid:host-icons/icons`.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:well-known/well-known@0.1.0",
    generate_all,
});

use enclavid::host::embedded_disclosure_fields::disclosure_field as resolve_disclosure_field;
use enclavid::host::types::IconRef;
use enclavid::host_icons::icons;
use enclavid::shared_types::capture::{CameraFacing, CaptureGuide, CaptureStep, MediaSpec};
use enclavid::shared_types::disclosure::DisplayField;
use enclavid::well_known::i18n::{Key, localized};
use exports::enclavid::well_known::capture::Guest as CaptureGuest;
use exports::enclavid::well_known::disclosure_fields::Guest as DisclosureFieldsGuest;

struct WellKnown;

// ─── disclosure-fields ────────────────────────────────────────────

/// Build a `DisplayField` for a well-known field: `key` is its canonical
/// name, which the host holds to the POLICY's disclosure fields (the
/// bandwidth gate), and `label` the text it is shown by.
fn field(key: &str, label: Key, value: String) -> DisplayField {
    DisplayField {
        key: resolve_disclosure_field(key),
        label: localized(label),
        value,
    }
}

impl DisclosureFieldsGuest for WellKnown {
    // Document identifiers
    fn passport_number(value: String) -> DisplayField {
        field("passport-number", Key::PassportNumberLabel, value)
    }
    fn id_card_number(value: String) -> DisplayField {
        field("id-card-number", Key::IdCardNumberLabel, value)
    }
    fn drivers_license_number(value: String) -> DisplayField {
        field(
            "drivers-license-number",
            Key::DriversLicenseNumberLabel,
            value,
        )
    }
    fn document_issuing_country(value: String) -> DisplayField {
        field(
            "document-issuing-country",
            Key::DocumentIssuingCountryLabel,
            value,
        )
    }
    fn document_expiry(value: String) -> DisplayField {
        field("document-expiry", Key::DocumentExpiryLabel, value)
    }
    fn document_issued(value: String) -> DisplayField {
        field("document-issued", Key::DocumentIssuedLabel, value)
    }

    // Identity
    fn given_name(value: String) -> DisplayField {
        field("given-name", Key::GivenNameLabel, value)
    }
    fn family_name(value: String) -> DisplayField {
        field("family-name", Key::FamilyNameLabel, value)
    }
    fn full_name(value: String) -> DisplayField {
        field("full-name", Key::FullNameLabel, value)
    }
    fn date_of_birth(value: String) -> DisplayField {
        field("date-of-birth", Key::DateOfBirthLabel, value)
    }
    fn sex(value: String) -> DisplayField {
        field("sex", Key::SexLabel, value)
    }
    fn nationality(value: String) -> DisplayField {
        field("nationality", Key::NationalityLabel, value)
    }

    // Contact / location
    fn residence_country(value: String) -> DisplayField {
        field("residence-country", Key::ResidenceCountryLabel, value)
    }
    fn address(value: String) -> DisplayField {
        field("address", Key::AddressLabel, value)
    }
    fn email(value: String) -> DisplayField {
        field("email", Key::EmailLabel, value)
    }
    fn phone(value: String) -> DisplayField {
        field("phone", Key::PhoneLabel, value)
    }

    // Other
    fn tax_id(value: String) -> DisplayField {
        field("tax-id", Key::TaxIdLabel, value)
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
