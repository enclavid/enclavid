wit_bindgen::generate!({
    path: [
        "../../../../../wit/embedded",
        "../../../../../wit/disclosure",
        "../../../../../wit/form",
        "../../../../../wit/policy",
        "wit",
    ],
    world: "enclavid:test-policy/policy@0.1.0",
    generate_all,
});

use enclavid::disclosure::disclosure::prompt_disclosure;
use enclavid::disclosure::types::DisplayField;
use enclavid::embedded::disclosure_fields::disclosure_field as df;
use enclavid::embedded::i18n::localized as l10n;
use enclavid::form::media::prompt_media;
use enclavid::form::types::{CameraFacing, CaptureGuide, CaptureStep, MediaSpec};
use exports::enclavid::policy::policy::{Decision, EvalArgs, Guest};

struct TestPolicy;

// Embedded-ref keys used in evaluate. Declarations live next to
// `Cargo.toml` in `disclosure-fields.json` (machine keys) and
// `i18n.json` (translatable UI strings). Refs are minted at
// evaluate time through the `enclavid:embedded/*` host fns, which
// trap if a key isn't declared in the corresponding section.
//
// Disclosure fields (machine keys, no translations):
const KEY_PASSPORT_NUMBER: &str = "passport_number";
const KEY_RISK_CATEGORY: &str = "risk_category";
const KEY_ADDRESS: &str = "address";

// Localized refs (translatable UI strings):
const KEY_PASSPORT_TITLE: &str = "passport_title";
const KEY_PASSPORT_INSTRUCTIONS: &str = "passport_instructions";
const KEY_PASSPORT_STEP: &str = "passport_step";
const KEY_PASSPORT_REVIEW_HINT: &str = "passport_review_hint";
const KEY_CONSENT_REASON: &str = "consent_reason";
const KEY_CONSENT_REQUESTER: &str = "consent_requester";
const KEY_PASSPORT_NUMBER_LABEL: &str = "passport_number_label";
const KEY_RISK_CATEGORY_LABEL: &str = "risk_category_label";
const KEY_ADDRESS_LABEL: &str = "address_label";

// Icon name — plain string, dispatched by frontend against its
// bundled SVG library (closed set: passport, id_card, drivers_license,
// selfie). Not a text-ref; unknown names render as no icon.
const ICON_PASSPORT: &str = "passport";

impl Guest for TestPolicy {
    fn evaluate(_args: Vec<(String, EvalArgs)>) -> Decision {
        // Single-shot passport capture: one step, rear camera,
        // ICAO TD3 aspect for the on-screen frame guide.
        let _clips = prompt_media(&MediaSpec {
            label: l10n(KEY_PASSPORT_TITLE),
            captures: vec![CaptureStep {
                icon: Some(ICON_PASSPORT.into()),
                instructions: l10n(KEY_PASSPORT_INSTRUCTIONS),
                label: l10n(KEY_PASSPORT_STEP),
                camera: CameraFacing::Rear,
                guide: CaptureGuide::Rect(1.42),
                review_hint: l10n(KEY_PASSPORT_REVIEW_HINT),
            }],
        });
        let consented = prompt_disclosure(
            &[
                DisplayField {
                    key: df(KEY_PASSPORT_NUMBER),
                    label: l10n(KEY_PASSPORT_NUMBER_LABEL),
                    value: "123456".into(),
                },
                DisplayField {
                    key: df(KEY_RISK_CATEGORY),
                    label: l10n(KEY_RISK_CATEGORY_LABEL),
                    value: "tier-3".into(),
                },
                DisplayField {
                    key: df(KEY_ADDRESS),
                    label: l10n(KEY_ADDRESS_LABEL),
                    // ~500 chars — well past the consent screen's
                    // 200-char collapse threshold. Exercises the
                    // "Show full (+N chars)" toggle.
                    value: "Block C-42, Phase III, Sapphire Heights Apartments, Plot No. 1284/B (the building with the blue gate next to the old banyan tree), Old Industrial Estate Road, Bandra-Kurla Complex Extension, Mumbai Suburban District, Maharashtra State 400051, India. c/o The Front Desk Manager, 4th Floor, between the elevator lobby and the staircase facing east. Cross street: Junction of MG Road and Linking Road, opposite the Sai Baba Temple. Landmark: behind the Big Bazaar supermarket.".into(),
                },
            ],
            &l10n(KEY_CONSENT_REASON),
            &l10n(KEY_CONSENT_REQUESTER),
        );
        if consented {
            Decision::Approved
        } else {
            Decision::Rejected
        }
    }
}

export!(TestPolicy);
