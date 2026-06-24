wit_bindgen::generate!({
    // wkg vendors the full dependency tree (embedded / disclosure / form /
    // policy / well-known) under `wit/deps`, so the local package dir is the
    // single resolution root — listing the canonical `../wit/*` dirs too
    // would re-add the same packages and fail the resolve.
    path: "wit",
    world: "enclavid:test-policy/policy@0.1.0",
    generate_all,
});

use enclavid::disclosure::disclosure::prompt_disclosure;
use enclavid::embedded::i18n::localized as l10n;
use enclavid::form::media::prompt_media;
// The well-known plugin (linked at /connect) supplies the capture specs
// and the canonical KYC `display-field` helpers.
use enclavid::well_known::capture;
use enclavid::well_known::disclosure_fields as wk;
use exports::enclavid::policy::policy::{Decision, EvalArgs, Guest};

struct TestPolicy;

// The ONLY refs this policy authors itself: the consent screen's reason +
// requester (both in `i18n.json`). Every field label, capture instruction,
// guide and icon is owned by the well-known plugin's embedded sections.
const KEY_CONSENT_REASON: &str = "consent_reason";
const KEY_CONSENT_REQUESTER: &str = "consent_requester";

// ~500-char value (held by the well-known `address` helper) — well past the
// consent screen's 200-char collapse threshold, exercising the
// "Show full (+N chars)" toggle.
const LONG_ADDRESS: &str = "Block C-42, Phase III, Sapphire Heights Apartments, Plot No. 1284/B (the building with the blue gate next to the old banyan tree), Old Industrial Estate Road, Bandra-Kurla Complex Extension, Mumbai Suburban District, Maharashtra State 400051, India. c/o The Front Desk Manager, 4th Floor, between the elevator lobby and the staircase facing east. Cross street: Junction of MG Road and Linking Road, opposite the Sai Baba Temple. Landmark: behind the Big Bazaar supermarket.";

impl Guest for TestPolicy {
    fn evaluate(_args: Vec<(String, EvalArgs)>) -> Decision {
        // Pre-baked capture flows straight from the plugin: the full
        // passport photo-page spec, then a selfie. The plugin owns every
        // label / instruction / guide / icon inside these specs (resolved
        // against its own i18n + icons sections).
        let _passport = prompt_media(&capture::passport());
        let _selfie = prompt_media(&capture::selfie());

        // Canonical KYC fields built by the plugin: labels resolve from the
        // plugin's i18n; the snake_case keys (full_name, date_of_birth, …)
        // are validated against THIS policy's `disclosure-fields.json` — the
        // single bandwidth gate for what reaches the consumer.
        let consented = prompt_disclosure(
            &[
                wk::full_name("Jane Q. Citizen"),
                wk::date_of_birth("1990-04-12"),
                wk::nationality("Utopia"),
                wk::passport_number("X1234567"),
                wk::document_expiry("2030-01-01"),
                wk::address(LONG_ADDRESS),
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
