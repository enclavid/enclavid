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

use enclavid::host::embedded_i18n::localized as l10n;
// The host `blob` resource + its content ref: on the passport round we stash
// the frame blob's `blob-ref` in `state`, then rehydrate it on the selfie round
// via `Blob::from_blob_ref` — proving cross-round reload from the host store.
use enclavid::host::types::{BlobRef, Blob};
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
    fn handle(state: Vec<u8>, event: Event) -> (Vec<u8>, Action) {
        match (step_of(&state), event) {
            // Genesis → ask for the passport photo page. When the consumer
            // config carries `state_bloat = N` the policy returns an N-byte
            // blob instead of the 1-byte step, so the harness can exercise
            // the engine's POLICY_MAX_STATE_BYTES cap; absent the flag this
            // is the normal 1-byte step.
            (STEP_START, Event::Start) => {
                let state = match bloat_bytes() {
                    Some(n) => vec![0u8; n],
                    None => state_at(STEP_AWAIT_PASSPORT),
                };
                (state, Action::Render(Prompt::Media(capture::passport())))
            }

            // Passport captured → validate the capture, then ask for the
            // selfie. Exercises the host-owned `frame` resource: the pixels
            // live host-side, so the policy is a pure router. We stash the
            // first frame's `blob-ref` (32 bytes) in `state` — the host has
            // already sealed the frame into its blob store — to rehydrate it on
            // the selfie round. Only the ref lives in state; the pixels never
            // do. An empty capture is retryable.
            (STEP_AWAIT_PASSPORT, Event::Media(result)) => match result.clip.frames.first() {
                None => (
                    state_at(STEP_AWAIT_PASSPORT),
                    Action::Finish(Decision::RejectedRetryable),
                ),
                Some(frame) => {
                    let mut next = vec![STEP_AWAIT_SELFIE];
                    next.extend_from_slice(&frame.blob_ref().hash);
                    (next, Action::Render(Prompt::Media(capture::selfie())))
                }
            },

            // Selfie captured → the full vision substrate across the fused
            // boundary: preprocess decodes the clip into a plugin-owned
            // `decoded-frame` (pixels stay in the preprocess sandbox),
            // face-detect locates the `face`, face-age pulls its crop via
            // `region` and estimates. The policy just threads the handles.
            // `none` at any step (undecodable / no face / model failure) →
            // retake. The age threshold is the policy's call (buffer +
            // document escalation) and lands with the real flow; here the
            // decode → detect → estimate plugin chain is what's exercised.
            (STEP_AWAIT_SELFIE, Event::Media(result)) => {
                // Rehydrate the passport frame stashed last round from its
                // `blob-ref` (the 32 bytes after the step tag) — proving a
                // cross-round reload from the host blob store. A miss (empty /
                // unknown ref) is retryable.
                let passport = Blob::from_blob_ref(&BlobRef {
                    hash: state[1..].to_vec(),
                });
                // Vision DAG on the SELFIE frame: preprocess decodes it into a
                // plugin-owned `decoded-frame`, face-detect locates the `face`,
                // face-age reads its crop and estimates. The policy threads the
                // handles.
                let age = result.clip.frames.first().and_then(|frame| {
                    preprocess::decode(frame, preprocess::Scale::Eighth).and_then(|df| {
                        face_detect::detect(&df).and_then(|face| face_age::estimate(&df, &face))
                    })
                });
                match (passport, age) {
                    (Ok(_), Some(_)) => (
                        state_at(STEP_AWAIT_CONSENT),
                        Action::Render(Prompt::ConsentDisclosure(build_consent())),
                    ),
                    _ => (
                        state_at(STEP_AWAIT_SELFIE),
                        Action::Finish(Decision::RejectedRetryable),
                    ),
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
