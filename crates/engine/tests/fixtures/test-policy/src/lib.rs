//! Test policy — pure actor (`enclavid:policy/policy.handle`).
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
//! State is the policy's private `enclavid:host/storage` key/value map:
//! one `step` key holding a single tag byte — no serde/bincode needed for a
//! 4-state machine. An unset `step` (genesis) reads as `Start`, so the very
//! first `handle(event::start)` works without a prior write. Advancing a
//! step is a `storage::set`; a retryable round simply leaves the key
//! untouched (skippable write). The runtime commits the map atomically with
//! the round on a clean return.
//!
//! Every capture spec + canonical `display-field` comes from the well-known
//! plugin (its own i18n / icons / disclosure-field sections); the policy
//! authors only its consent reason + requester refs against its own
//! `i18n.json`.

wit_bindgen::generate!({
    // wkg vendors the full dependency tree (embedded / shared-types /
    // policy / well-known) under `wit/deps`, so the local package dir is
    // the single resolution root.
    path: "wit",
    world: "enclavid:test-policy/policy@0.1.0",
    generate_all,
});

use enclavid::host::embedded_i18n::localized as l10n;
use enclavid::host::storage;
use enclavid::policy::types::{Action, Decision, Disclosure, Event, Prompt};
// The well-known plugin (linked at /connect) supplies the capture specs
// and the canonical KYC `display-field` helpers.
use enclavid::well_known::capture;
use enclavid::well_known::disclosure_fields as wk;
// Second plugin (linked at runtime in the hybrid test): its `get()`
// resolves `extra_tag` from the extra plugin's own i18n catalog.
use enclavid::extra::tag;
// The vision substrate, threaded across the fused boundary: preprocess
// decodes the selfie clip into a plugin-owned `decoded-frame`, face-detect
// locates the `face` in it, face-age reads its crop and estimates.
use enclavid::face_age::check as face_age;
use enclavid::face_detect::detect as face_detect;
use enclavid::preprocess::decode as preprocess;
use exports::enclavid::policy::policy::Guest;

struct TestPolicy;

// The consent screen's reason ref, authored in this policy's `i18n.json`.
// The requester ref comes from the extra plugin (see `build_consent`).
// Every field label, capture instruction, guide and icon is owned by the
// well-known plugin's embedded sections.
const KEY_CONSENT_REASON: &str = "consent_reason";

// ~500-char value (held by the well-known `address` helper) — well past
// the consent screen's 200-char collapse threshold, exercising the
// "Show full (+N chars)" toggle.
const LONG_ADDRESS: &str = "Block C-42, Phase III, Sapphire Heights Apartments, Plot No. 1284/B (the building with the blue gate next to the old banyan tree), Old Industrial Estate Road, Bandra-Kurla Complex Extension, Mumbai Suburban District, Maharashtra State 400051, India. c/o The Front Desk Manager, 4th Floor, between the elevator lobby and the staircase facing east. Cross street: Junction of MG Road and Linking Road, opposite the Sai Baba Temple. Landmark: behind the Big Bazaar supermarket.";

// --- State: a single `step` key holding one tag byte ---

const STEP_KEY: &str = "step";
const STEP_START: u8 = 0;
const STEP_AWAIT_PASSPORT: u8 = 1;
const STEP_AWAIT_SELFIE: u8 = 2;
const STEP_AWAIT_CONSENT: u8 = 3;

/// Read the current step from `storage`. An unset (or empty) `step` key —
/// genesis — reads as `Start`.
fn current_step() -> u8 {
    match storage::get(STEP_KEY) {
        Some(b) if !b.is_empty() => b[0],
        _ => STEP_START,
    }
}

/// Advance the machine by staging `step = tag` for this round's commit.
fn set_step(step: u8) {
    storage::set(STEP_KEY, &[step]);
}

/// Read the optional `state_bloat = N` value from the consumer config
/// (`context.props`). Present only when the harness drives the engine's
/// `POLICY_MAX_STATE_BYTES` cap; absent on every real flow.
fn bloat_bytes() -> Option<usize> {
    use enclavid::host::types::Prop;
    enclavid::host::session_context::props()
        .into_iter()
        .find(|(k, _)| k == "state_bloat")
        .and_then(|(_, v)| match v {
            Prop::Int(n) if n >= 0 => Some(n as usize),
            _ => None,
        })
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
        // Requester ref comes from the EXTRA plugin (`tag::get()` →
        // `extra_tag`), resolved against the extra plugin's own catalog.
        // Both this policy and the extra plugin declare `extra_tag` with
        // different text, so a correct (strict) routing yields the
        // plugin's value here — first-match would leak the policy's.
        requester: tag::get(),
    }
}

impl Guest for TestPolicy {
    fn handle(event: Event) -> Action {
        match (current_step(), event) {
            // Genesis → ask for the passport photo page. When the consumer
            // config carries `state_bloat = N` the policy stages an N-byte
            // value instead of the 1-byte step, so the harness can exercise
            // the engine's POLICY_MAX_STATE_BYTES cap (which the runner
            // checks on the serialized storage map after `handle` returns);
            // absent the flag this is the normal 1-byte step.
            (STEP_START, Event::Start) => {
                match bloat_bytes() {
                    Some(n) => storage::set(STEP_KEY, &vec![0u8; n]),
                    None => set_step(STEP_AWAIT_PASSPORT),
                }
                Action::Render(Prompt::Media(capture::passport()))
            }

            // Passport captured → validate the capture, then ask for the
            // selfie. Exercises the host-owned `clip` resource: the frames
            // live host-side, so the policy pulls the count (and the first
            // frame's bytes) across the boundary on demand — the pixels
            // only materialise where asked. An empty capture finishes the
            // round with the terminal `RejectedRetryable` decision (the
            // platform surfaces a retake hint); it is not an in-actor loop.
            (STEP_AWAIT_PASSPORT, Event::Media(result)) => {
                if result.clip.frame_count() == 0 || result.clip.frame(0).is_none() {
                    Action::Finish(Decision::RejectedRetryable)
                } else {
                    set_step(STEP_AWAIT_SELFIE);
                    Action::Render(Prompt::Media(capture::selfie()))
                }
            }

            // Selfie captured → the full vision substrate across the fused
            // boundary: preprocess decodes the clip into a plugin-owned
            // `decoded-frame` (pixels stay in the preprocess sandbox),
            // face-detect locates the `face`, face-age pulls its crop via
            // `region` and estimates. The policy just threads the handles.
            // `none` at any step (undecodable / no face / model failure) →
            // terminal `RejectedRetryable` finish (platform surfaces a retake
            // hint). The age threshold is the
            // policy's call (buffer + document escalation) and lands with
            // the real flow; here the decode → detect → estimate plugin
            // chain is what's exercised.
            (STEP_AWAIT_SELFIE, Event::Media(result)) => {
                let age = preprocess::decode(&result.clip, 0, preprocess::Scale::Eighth)
                    .and_then(|frame| {
                        face_detect::detect(&frame)
                            .and_then(|face| face_age::estimate(&frame, &face))
                    });
                match age {
                    Some(_) => {
                        set_step(STEP_AWAIT_CONSENT);
                        Action::Render(Prompt::ConsentDisclosure(build_consent()))
                    }
                    None => Action::Finish(Decision::RejectedRetryable),
                }
            }

            // Consent reply → terminal decision. The runtime already
            // sealed (or didn't seal) the disclosure based on this same
            // boolean; the policy just maps it to a decision.
            (STEP_AWAIT_CONSENT, Event::ConsentDisclosure(accepted)) => {
                let decision = if accepted {
                    Decision::Approved
                } else {
                    Decision::Rejected
                };
                Action::Finish(decision)
            }

            // Any other (step, event) pairing is a runtime/replay bug —
            // fail loud with a finish(rejected) rather than silently
            // looping. (The harness never drives this path.)
            (_, _) => Action::Finish(Decision::Rejected),
        }
    }
}

export!(TestPolicy);
