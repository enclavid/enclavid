//! Test policy — pure reducer (`enclavid:policy/policy.handle`).
//!
//! Drives a minimal KYC walk, composed with the `enclavid:well-known`
//! plugin:
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
//! well-known plugin (its own texts, the host's icons), of the fields the
//! policy hands it; the policy authors only its consent reason and its
//! face-age field, as its own texts and disclosure fields, and labels one
//! field with the plugin's text, imported by the plugin's slot.

wit_bindgen::generate!({
    // wkg vendors the full dependency tree (embedded / shared-types /
    // policy / well-known) under `wit/deps`, so the local package dir is
    // the single resolution root.
    path: "wit",
    world: "enclavid:test-policy/policy@0.1.0",
    generate_all,
});

// Mints the policy's `disclosure-field-ref`s, each a case of its own list:
// those it hands the well-known helpers, and its own face-age estimate.
use enclavid::shared_types::disclosure::DisplayField;
use enclavid_ext::policy::disclosure_fields::{Key as Field, disclosure_field};
// The policy's own texts.
use enclavid_ext::policy::i18n::{Key as Text, localized};
// The well-known plugin's texts, by its slot.
use enclavid_ext::well_known::i18n::{Key as WellKnownText, localized as well_known_text};
// The host `blob` resource + its content ref: on the passport round we stash
// the frame blob's `blob-ref` (a hex string) in `state`, then rehydrate it on
// the selfie round via `Blob::from_blob_ref` — proving cross-round reload.
use enclavid::host::types::Blob;
use enclavid::policy::types::{Action, Decision, Disclosure, Event, Prompt};
// The well-known plugin (linked at /connect) supplies the capture specs
// and the canonical KYC `display-field` helpers.
use enclavid::well_known::capture;
use enclavid::well_known::disclosure_fields as wk;
// Second plugin (linked at runtime in the hybrid test): its `get()` is
// `extra-tag`, one of the extra plugin's own texts.
use enclavid::extra::tag;
// The vision substrate, threaded across the fused boundary: preprocess
// decodes the selfie clip into a plugin-owned `decoded-frame`, face-detect
// locates the `face` in it, face-age reads its crop and estimates.
use enclavid::face_age::check as face_age;
use enclavid::face_detect::detect as face_detect;
use enclavid::preprocess::decode as preprocess;
use exports::enclavid::policy::policy::Guest;

struct TestPolicy;

// The consent screen's reason is one of this policy's own texts; the
// requester comes from the extra plugin (see `build_consent`). Every field
// label, capture instruction, guide and icon is owned by the well-known
// plugin.

/// The name the consent fields are of.
const HOLDER: &str = "Jane Q. Citizen";

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

/// The optional `state-bloat = N` prop. Present only when the harness drives
/// the engine's `POLICY_MAX_STATE_BYTES` cap; absent on every real flow.
fn bloat_bytes() -> Option<usize> {
    enclavid_ext::policy::props::get()
        .state_bloat
        .map(|n| n as usize)
}

/// The optional `skip-passport-read` prop. When set, the selfie round
/// rehydrates the passport handle but does NOT read its `bytes()`, so a
/// counting media store can prove `from-blob-ref` alone triggers no load (the
/// pull is lazy, on `bytes()`). Absent on every real flow.
fn skip_passport_read() -> bool {
    enclavid_ext::policy::props::get()
        .skip_passport_read
        .unwrap_or(false)
}

/// The optional `wasi-probe` prop. When set, genesis returns what the round's
/// WASI clocks and randomness read instead of the step. Absent on every real
/// flow.
fn wasi_probe() -> bool {
    enclavid_ext::policy::props::get()
        .wasi_probe
        .unwrap_or(false)
}

/// What the round's WASI imports read, as a state: the wall clock's second,
/// the monotonic clock before and after it (8 bytes each, big endian), asking
/// whether a deadline one nanosecond ahead is ready, then waiting a second, and
/// what that ask and a second one after the wait answered (a byte each), and 16
/// random bytes.
fn probe_state() -> Vec<u8> {
    use wasip2::clocks::{monotonic_clock, wall_clock};

    let wall = wall_clock::now().seconds;
    let before = monotonic_clock::now();
    let ahead = monotonic_clock::subscribe_duration(1);
    let ready_before = ahead.ready();
    monotonic_clock::subscribe_duration(1_000_000_000).block();
    let after = monotonic_clock::now();
    let ready_after = ahead.ready();

    let mut state = Vec::new();
    for n in [wall, before, after] {
        state.extend_from_slice(&n.to_be_bytes());
    }
    state.extend([u8::from(ready_before), u8::from(ready_after)]);
    state.extend(wasip2::random::random::get_random_bytes(16));
    state
}

fn build_consent(age_years: i32) -> Disclosure {
    // Canonical KYC fields built by the plugin: labels are the plugin's own
    // texts; the keys (full-name, date-of-birth, …) are THIS policy's
    // disclosure fields, minted from its own list — the single bandwidth gate
    // for what reaches the consumer.
    let mut fields = vec![
        wk::full_name(disclosure_field(Field::FullName), HOLDER),
        wk::date_of_birth(disclosure_field(Field::DateOfBirth), "1990-04-12"),
        // Built by the policy itself, labelled with the plugin's text for the
        // field: one import of the plugin's slot, the policy's and the
        // plugin's, served from the plugin's catalog.
        DisplayField {
            key: disclosure_field(Field::Nationality),
            label: well_known_text(WellKnownText::NationalityLabel),
            value: "Utopia".into(),
        },
        wk::passport_number(disclosure_field(Field::PassportNumber), "X1234567"),
        wk::document_expiry(disclosure_field(Field::DocumentExpiry), "2030-01-01"),
        wk::address(disclosure_field(Field::Address), LONG_ADDRESS),
    ];
    // The face-age estimate, disclosed as a POLICY-owned field. Its key isn't
    // a well-known helper, so the policy mints the `disclosure-field-ref`
    // itself, a case of its own list, plus its own label. Shown on the consent
    // screen and sealed only on accept (show == seal) — the sanctioned path
    // for a plugin-computed value to reach the consumer (never auto-shared).
    fields.push(DisplayField {
        key: disclosure_field(Field::EstimatedAge),
        label: localized(Text::EstimatedAgeLabel),
        value: age_years.to_string(),
    });
    let reason = localized(Text::ConsentReason);
    Disclosure {
        fields,
        reason,
        // The requester comes from the EXTRA plugin (`tag::get()` →
        // `extra-tag`), one of the extra plugin's own texts. This policy has
        // an `extra-tag` too, with a text of its own, so the plugin's slot,
        // served from the plugin's catalog, yields the plugin's text here —
        // a first match across catalogs would leak the policy's.
        requester: tag::get(),
    }
}

impl Guest for TestPolicy {
    fn handle(state: Vec<u8>, event: Event) -> (Vec<u8>, Action) {
        match (step_of(&state), event) {
            // Genesis → ask for the passport photo page. When the props
            // carry `state-bloat = N` the policy returns an N-byte blob
            // instead of the 1-byte step, so the harness can exercise the
            // engine's POLICY_MAX_STATE_BYTES cap; with `wasi-probe` it is
            // what the round's clocks and randomness read; absent both this is
            // the normal 1-byte step.
            (STEP_START, Event::Start) => {
                let state = match bloat_bytes() {
                    Some(n) => vec![0u8; n],
                    None if wasi_probe() => probe_state(),
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
                    // Stash the frame's content `hash` (a hex string) after the
                    // step tag. Only the opaque token lives in state — never pixels.
                    let mut next = vec![STEP_AWAIT_SELFIE];
                    next.extend_from_slice(frame.hash().as_bytes());
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
                // `blob-ref` (the 32 bytes after the step tag). `from-blob-ref`
                // returns a COLD handle (no load yet); reading `bytes()` is what
                // triggers the LAZY pull — proving the cross-round reload — and a
                // miss traps THERE. A legitimately-stashed ref always resolves,
                // so there's no miss branch to handle.
                let passport_hash = core::str::from_utf8(&state[1..]).unwrap_or_default();
                let passport = Blob::new(passport_hash);
                if !skip_passport_read() {
                    let _passport_bytes = passport.bytes();
                }
                // Vision DAG on the SELFIE frame: preprocess decodes it into a
                // plugin-owned `decoded-frame`, face-detect locates the `face`,
                // face-age reads its crop and estimates. The policy threads the
                // handles.
                let age = result.clip.frames.first().and_then(|frame| {
                    preprocess::decode(frame, preprocess::Scale::Eighth).and_then(|df| {
                        face_detect::detect(&df).and_then(|face| face_age::estimate(&df, &face))
                    })
                });
                match age {
                    Some(est) => (
                        state_at(STEP_AWAIT_CONSENT),
                        Action::Render(Prompt::ConsentDisclosure(build_consent(
                            est.age.round() as i32
                        ))),
                    ),
                    None => (
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
