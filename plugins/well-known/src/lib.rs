//! `enclavid:well-known` — canonical KYC field strings, icons, and
//! pre-baked capture flows. Drop-in helpers so policy authors don't
//! hand-roll text-refs for standard data shapes.
//!
//! Every ref this plugin hands back (disclosure-field key, localized
//! label, icon name) is resolved through the corresponding
//! `enclavid:host/*` embedded host import — the host hashes
//! `(slot, kind, key)` under a TEE-only key and returns the opaque
//! token. The plugin's own `enclavid:embedded.*.v1` custom sections
//! (`disclosure-fields.json`, `i18n.json`, `icons.json`) declare the
//! full set of keys the host will accept; anything passed to one of
//! the embedded imports that isn't in the matching section traps at
//! load time.
//!
//! Raw string construction wouldn't work: under Phase B BLAKE3-keyed
//! tokens the engine reverse-index never sees a string the host
//! itself didn't issue, so any hand-built `"passport-number"` would
//! fail the use-site membership check.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:well-known/well-known@0.1.0",
    generate_all,
});

use enclavid::host::embedded_disclosure_fields::disclosure_field as resolve_disclosure_field;
use enclavid::host::embedded_i18n::localized as resolve_localized;
use enclavid::host::embedded_icons::icon as resolve_icon;
use enclavid::shared_types::capture::{CameraFacing, CaptureGuide, CaptureStep, MediaSpec};
use enclavid::shared_types::disclosure::DisplayField;
use exports::enclavid::well_known::capture::Guest as CaptureGuest;
use exports::enclavid::well_known::disclosure_fields::Guest as DisclosureFieldsGuest;
use exports::enclavid::well_known::icons::Guest as IconsGuest;

struct WellKnown;

// ─── icons ────────────────────────────────────────────────────────

impl IconsGuest for WellKnown {
    fn passport() -> String {
        resolve_icon("passport")
    }
    fn id_card() -> String {
        resolve_icon("id_card")
    }
    fn drivers_license() -> String {
        resolve_icon("drivers_license")
    }
    fn selfie() -> String {
        resolve_icon("selfie")
    }
}

// ─── disclosure-fields ────────────────────────────────────────────

/// Build a `DisplayField` for a well-known field. `key` is the
/// snake_case canonical name (WIT-kebab → snake mapping); the host
/// validates it against the POLICY's `disclosure-fields.json` (slot
/// 0 — bandwidth gate). `label` is `<key>_label` resolved from THIS
/// PLUGIN's `i18n.json`.
fn field(key: &str, value: String) -> DisplayField {
    DisplayField {
        key: resolve_disclosure_field(key),
        label: resolve_localized(&format!("{key}_label")),
        value,
    }
}

impl DisclosureFieldsGuest for WellKnown {
    // Document identifiers
    fn passport_number(value: String) -> DisplayField {
        field("passport_number", value)
    }
    fn id_card_number(value: String) -> DisplayField {
        field("id_card_number", value)
    }
    fn drivers_license_number(value: String) -> DisplayField {
        field("drivers_license_number", value)
    }
    fn document_issuing_country(value: String) -> DisplayField {
        field("document_issuing_country", value)
    }
    fn document_expiry(value: String) -> DisplayField {
        field("document_expiry", value)
    }
    fn document_issued(value: String) -> DisplayField {
        field("document_issued", value)
    }

    // Identity
    fn given_name(value: String) -> DisplayField {
        field("given_name", value)
    }
    fn family_name(value: String) -> DisplayField {
        field("family_name", value)
    }
    fn full_name(value: String) -> DisplayField {
        field("full_name", value)
    }
    fn date_of_birth(value: String) -> DisplayField {
        field("date_of_birth", value)
    }
    fn sex(value: String) -> DisplayField {
        field("sex", value)
    }
    fn nationality(value: String) -> DisplayField {
        field("nationality", value)
    }

    // Contact / location
    fn residence_country(value: String) -> DisplayField {
        field("residence_country", value)
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
        field("tax_id", value)
    }
}

// ─── capture ──────────────────────────────────────────────────────

/// ICAO TD3 passport photo-page aspect (125x88mm → ~1.42).
const PASSPORT_ASPECT: f32 = 1.42;
/// ICAO TD1 ID-1 card aspect (85.6x54mm → ~1.585).
const ID1_ASPECT: f32 = 1.585;

/// Build a CaptureStep, resolving every ref through the embedded
/// host imports. `prefix` is the snake_case per-step namespace
/// (`passport`, `id_card_front`, ...); the three localized refs
/// follow `<prefix>_{instructions,step,review_hint}`, which
/// `i18n.json` declares verbatim.
fn step(
    prefix: &str,
    icon_name: Option<&str>,
    camera: CameraFacing,
    guide: CaptureGuide,
) -> CaptureStep {
    CaptureStep {
        icon: icon_name.map(resolve_icon),
        instructions: resolve_localized(&format!("{prefix}_instructions")),
        label: resolve_localized(&format!("{prefix}_step")),
        camera,
        guide,
        review_hint: resolve_localized(&format!("{prefix}_review_hint")),
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
        "id_card_front",
        Some("id_card"),
        CameraFacing::Rear,
        CaptureGuide::Rect(ID1_ASPECT),
    )
}

fn id_card_back_step_inner() -> CaptureStep {
    step(
        "id_card_back",
        Some("id_card"),
        CameraFacing::Rear,
        CaptureGuide::Rect(ID1_ASPECT),
    )
}

fn drivers_license_front_step_inner() -> CaptureStep {
    step(
        "drivers_license_front",
        Some("drivers_license"),
        CameraFacing::Rear,
        CaptureGuide::Rect(ID1_ASPECT),
    )
}

fn drivers_license_back_step_inner() -> CaptureStep {
    step(
        "drivers_license_back",
        Some("drivers_license"),
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
            label: resolve_localized("passport_title"),
            captures: vec![passport_step()],
        }
    }

    fn id_card() -> MediaSpec {
        MediaSpec {
            label: resolve_localized("id_card_title"),
            captures: vec![id_card_front_step_inner(), id_card_back_step_inner()],
        }
    }

    fn drivers_license() -> MediaSpec {
        MediaSpec {
            label: resolve_localized("drivers_license_title"),
            captures: vec![
                drivers_license_front_step_inner(),
                drivers_license_back_step_inner(),
            ],
        }
    }

    fn selfie() -> MediaSpec {
        MediaSpec {
            label: resolve_localized("selfie_title"),
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
