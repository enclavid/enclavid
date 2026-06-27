//! Test policy — pure reducer (`enclavid:policy/policy.handle`).
//!
//! Drives a minimal KYC walk, composed with the `enclavid:well-known`
//! plugin (linked at slot 1):
//!
//!   start                       → render media(passport spec)
//!   media(passport result)      → render media(selfie spec)
//!   media(selfie result)        → render consent-disclosure{...}
//!   consent-disclosure(true)    → finish(approved)
//!   consent-disclosure(false)   → finish(rejected)
//!
//! The reducer is stateless across calls except for the opaque `state`
//! blob the runtime threads back in. We encode the current step as a
//! single tag byte — no serde/bincode dependency needed for a 4-state
//! machine. An empty `state` (genesis) is treated as `Start` so the very
//! first `handle(&[], event::start)` works without a prior write.
//!
//! Every capture spec + canonical `display-field` comes from the
//! well-known plugin (its own i18n / icons / disclosure-field sections);
//! the policy authors only its consent reason + requester refs against
//! its own `i18n.json`.

wit_bindgen::generate!({
    // wkg vendors the full dependency tree (embedded / shared-types /
    // policy / well-known) under `wit/deps`, so the local package dir is
    // the single resolution root.
    path: "wit",
    world: "enclavid:test-policy/policy@0.1.0",
    generate_all,
});

use enclavid::embedded::i18n::localized as l10n;
use enclavid::policy::types::{Action, Decision, Disclosure, Event, Prompt};
// The well-known plugin (linked at /connect) supplies the capture specs
// and the canonical KYC `display-field` helpers.
use enclavid::well_known::capture;
use enclavid::well_known::disclosure_fields as wk;
use exports::enclavid::policy::policy::Guest;

struct TestPolicy;

// The ONLY refs this policy authors itself: the consent screen's reason +
// requester (both in `i18n.json`). Every field label, capture
// instruction, guide and icon is owned by the well-known plugin's
// embedded sections.
const KEY_CONSENT_REASON: &str = "consent_reason";
const KEY_CONSENT_REQUESTER: &str = "consent_requester";

// ~500-char value (held by the well-known `address` helper) — well past
// the consent screen's 200-char collapse threshold, exercising the
// "Show full (+N chars)" toggle.
const LONG_ADDRESS: &str = "Block C-42, Phase III, Sapphire Heights Apartments, Plot No. 1284/B (the building with the blue gate next to the old banyan tree), Old Industrial Estate Road, Bandra-Kurla Complex Extension, Mumbai Suburban District, Maharashtra State 400051, India. c/o The Front Desk Manager, 4th Floor, between the elevator lobby and the staircase facing east. Cross street: Junction of MG Road and Linking Road, opposite the Sai Baba Temple. Landmark: behind the Big Bazaar supermarket.";

// --- Opaque state: a single tag byte ---

const STEP_START: u8 = 0;
const STEP_AWAIT_PASSPORT: u8 = 1;
const STEP_AWAIT_SELFIE: u8 = 2;
const STEP_AWAIT_CONSENT: u8 = 3;

/// Decode the step from the opaque state blob. Genesis (empty) ⇒ Start.
fn step_of(state: &[u8]) -> u8 {
    match state.first() {
        None => STEP_START,
        Some(&b) => b,
    }
}

fn state_at(step: u8) -> Vec<u8> {
    vec![step]
}

fn build_consent() -> Disclosure {
    Disclosure {
        // Canonical KYC fields built by the plugin: labels resolve from
        // the plugin's i18n; the snake_case keys (full_name,
        // date_of_birth, …) are validated against THIS policy's
        // `disclosure-fields.json` — the single bandwidth gate for what
        // reaches the consumer.
        fields: vec![
            wk::full_name("Jane Q. Citizen"),
            wk::date_of_birth("1990-04-12"),
            wk::nationality("Utopia"),
            wk::passport_number("X1234567"),
            wk::document_expiry("2030-01-01"),
            wk::address(LONG_ADDRESS),
        ],
        reason: l10n(KEY_CONSENT_REASON),
        requester: l10n(KEY_CONSENT_REQUESTER),
    }
}

impl Guest for TestPolicy {
    fn handle(state: Vec<u8>, event: Event) -> (Vec<u8>, Action) {
        match (step_of(&state), event) {
            // Genesis → ask for the passport photo page.
            (STEP_START, Event::Start) => (
                state_at(STEP_AWAIT_PASSPORT),
                Action::Render(Prompt::Media(capture::passport())),
            ),

            // Passport captured → ask for the selfie.
            (STEP_AWAIT_PASSPORT, Event::Media(_)) => (
                state_at(STEP_AWAIT_SELFIE),
                Action::Render(Prompt::Media(capture::selfie())),
            ),

            // Selfie captured → consent-to-disclose screen.
            (STEP_AWAIT_SELFIE, Event::Media(_)) => (
                state_at(STEP_AWAIT_CONSENT),
                Action::Render(Prompt::ConsentDisclosure(build_consent())),
            ),

            // Consent reply → terminal decision. The runtime already
            // sealed (or didn't seal) the disclosure based on this same
            // boolean; the policy just maps it to a decision.
            (STEP_AWAIT_CONSENT, Event::ConsentDisclosure(accepted)) => {
                let decision = if accepted {
                    Decision::Approved
                } else {
                    Decision::Rejected
                };
                (state_at(STEP_AWAIT_CONSENT), Action::Finish(decision))
            }

            // Any other (step, event) pairing is a runtime/replay bug —
            // fail loud with a finish(rejected) rather than silently
            // looping. (The harness never drives this path.)
            (_, _) => (state, Action::Finish(Decision::Rejected)),
        }
    }
}

export!(TestPolicy);
