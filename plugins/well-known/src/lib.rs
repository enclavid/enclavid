//! `enclavid:well-known` — canonical KYC field strings, icons, and
//! pre-baked capture flows. Drop-in helpers so policy authors don't
//! hand-roll text-refs for standard data shapes.
//!
//! All text-refs returned by `disclosure-fields` and `capture` helpers
//! must be registered in the consuming policy's `policy.json` (see
//! plugin README for a drop-in JSON snippet). Without registration,
//! the host text-ref membership check traps at use site.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:well-known/well-known@0.1.0",
    generate_all,
});

use enclavid::disclosure::types::DisplayField;
use enclavid::form::types::{CameraFacing, CaptureGuide, CaptureStep, MediaSpec};
use exports::enclavid::well_known::capture::Guest as CaptureGuest;
use exports::enclavid::well_known::disclosure_fields::Guest as DisclosureFieldsGuest;
use exports::enclavid::well_known::icons::Guest as IconsGuest;

struct WellKnown;

// ─── icons ────────────────────────────────────────────────────────

impl IconsGuest for WellKnown {
    fn passport() -> String {
        "passport".into()
    }
    fn id_card() -> String {
        "id-card".into()
    }
    fn drivers_license() -> String {
        "drivers-license".into()
    }
    fn selfie() -> String {
        "selfie".into()
    }
}

// ─── disclosure-fields ────────────────────────────────────────────

/// Build a `DisplayField` for a well-known field. The label text-ref
/// is `<key>-label` by convention — tenants register that key in their
/// policy.json's `localized` map with the actual translated text.
fn field(key: &str, value: String) -> DisplayField {
    DisplayField {
        key: key.into(),
        label: format!("{key}-label"),
        value,
    }
}

impl DisclosureFieldsGuest for WellKnown {
    // Document identifiers
    fn passport_number(value: String) -> DisplayField {
        field("passport-number", value)
    }
    fn id_card_number(value: String) -> DisplayField {
        field("id-card-number", value)
    }
    fn drivers_license_number(value: String) -> DisplayField {
        field("drivers-license-number", value)
    }
    fn document_issuing_country(value: String) -> DisplayField {
        field("document-issuing-country", value)
    }
    fn document_expiry(value: String) -> DisplayField {
        field("document-expiry", value)
    }
    fn document_issued(value: String) -> DisplayField {
        field("document-issued", value)
    }

    // Identity
    fn given_name(value: String) -> DisplayField {
        field("given-name", value)
    }
    fn family_name(value: String) -> DisplayField {
        field("family-name", value)
    }
    fn full_name(value: String) -> DisplayField {
        field("full-name", value)
    }
    fn date_of_birth(value: String) -> DisplayField {
        field("date-of-birth", value)
    }
    fn sex(value: String) -> DisplayField {
        field("sex", value)
    }
    fn nationality(value: String) -> DisplayField {
        field("nationality", value)
    }

    // Contact / location
    fn residence_country(value: String) -> DisplayField {
        field("residence-country", value)
    }
    fn address(value: String) -> DisplayField {
        field("address", value)
    }
    fn email(value: String) -> DisplayField {
        field("email", value)
    }
    fn phone(value: String) -> DisplayField {
        field("phone", value)
    }

    // Other
    fn tax_id(value: String) -> DisplayField {
        field("tax-id", value)
    }
}

// ─── capture ──────────────────────────────────────────────────────

/// ICAO TD3 passport photo-page aspect (125x88mm → ~1.42).
const PASSPORT_ASPECT: f32 = 1.42;
/// ICAO TD1 ID-1 card aspect (85.6x54mm → ~1.585).
const ID1_ASPECT: f32 = 1.585;

/// Build a CaptureStep with the canonical text-ref names. `prefix` is
/// the per-step namespace (`passport`, `id-card-front`, etc.). Tenants
/// register `<prefix>-instructions`, `<prefix>-step`, `<prefix>-review-hint`
/// in policy.json's `localized` map.
fn step(
    prefix: &str,
    icon: Option<&str>,
    camera: CameraFacing,
    guide: CaptureGuide,
) -> CaptureStep {
    CaptureStep {
        icon: icon.map(|s| s.into()),
        instructions: format!("{prefix}-instructions"),
        label: format!("{prefix}-step"),
        camera,
        guide,
        review_hint: format!("{prefix}-review-hint"),
    }
}

fn passport_step() -> CaptureStep {
    step(
        "passport",
        Some("passport"),
        CameraFacing::Rear,
        CaptureGuide::Rect(PASSPORT_ASPECT),
    )
}

fn id_card_front_step_inner() -> CaptureStep {
    step(
        "id-card-front",
        Some("id-card"),
        CameraFacing::Rear,
        CaptureGuide::Rect(ID1_ASPECT),
    )
}

fn id_card_back_step_inner() -> CaptureStep {
    step(
        "id-card-back",
        Some("id-card"),
        CameraFacing::Rear,
        CaptureGuide::Rect(ID1_ASPECT),
    )
}

fn drivers_license_front_step_inner() -> CaptureStep {
    step(
        "drivers-license-front",
        Some("drivers-license"),
        CameraFacing::Rear,
        CaptureGuide::Rect(ID1_ASPECT),
    )
}

fn drivers_license_back_step_inner() -> CaptureStep {
    step(
        "drivers-license-back",
        Some("drivers-license"),
        CameraFacing::Rear,
        CaptureGuide::Rect(ID1_ASPECT),
    )
}

fn selfie_step_inner() -> CaptureStep {
    step(
        "selfie",
        Some("selfie"),
        CameraFacing::Front,
        CaptureGuide::Oval,
    )
}

impl CaptureGuest for WellKnown {
    fn passport() -> MediaSpec {
        MediaSpec {
            label: "passport-title".into(),
            captures: vec![passport_step()],
        }
    }

    fn id_card() -> MediaSpec {
        MediaSpec {
            label: "id-card-title".into(),
            captures: vec![id_card_front_step_inner(), id_card_back_step_inner()],
        }
    }

    fn drivers_license() -> MediaSpec {
        MediaSpec {
            label: "drivers-license-title".into(),
            captures: vec![
                drivers_license_front_step_inner(),
                drivers_license_back_step_inner(),
            ],
        }
    }

    fn selfie() -> MediaSpec {
        MediaSpec {
            label: "selfie-title".into(),
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
