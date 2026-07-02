//! End-to-end: runs a test policy — composed with the `enclavid:well-known`
//! plugin — through the PURE-REDUCER engine, threading the opaque `state`
//! blob + building a per-round `event` and asserting the returned action.
//!
//! The policy is `handle(state, event) -> (state, action)`.
//! The harness owns the mailbox: each round it inspects the previous
//! round's `current_prompt`, fabricates the matching applicant input
//! (a fake clip for a media prompt, an accept/reject bool for a consent
//! prompt), and calls `run` again.
//!
//! Two flows are driven:
//!   * REJECT  — passport → selfie → consent-disclosure(false) → Rejected.
//!               Asserts the CONSENT GATE: zero disclosures sealed.
//!   * APPROVE — passport → selfie → consent-disclosure(true)  → Approved.
//!               Asserts the disclosure WAS sealed (exactly one, with the
//!               six canonical fields the policy rendered).
//!
//! The policy and the plugin wasm are compiled on-demand (first test
//! invocation) rather than via a build.rs — this keeps normal engine
//! builds free of wasm tooling dependencies and nightly requirements.

use std::future::Future;
use std::pin::Pin;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use broker_client::{Clip, Decision, Event, MediaResult, Prompt, SessionState as Session};
use enclavid_engine::{
    ConsentDisclosure, EmbeddedRegistry, PluginInstance, Prop, RunInputs, RunStatus, Runner,
    SessionChange, SessionListener,
};
use wit_component::ComponentEncoder;

/// WIT package id the policy imports its capture / disclosure-field
/// helpers from; used as the plugin descriptor label at compose time.
const WELL_KNOWN_PACKAGE: &str = "enclavid:well-known@0.1.0";

/// Recording listener: captures every sealed disclosure the runtime
/// fires, so the test can assert the consent gate (reject seals nothing,
/// accept seals exactly what was shown).
#[derive(Default)]
struct RecordingListener {
    sealed: Mutex<Vec<Vec<broker_client::DisplayField>>>,
}

impl SessionListener for RecordingListener {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>> {
        let rounds: Vec<Vec<broker_client::DisplayField>> = change
            .disclosures
            .iter()
            .map(|d: &ConsentDisclosure| d.fields.clone())
            .collect();
        Box::pin(async move {
            let mut sealed = self.sealed.lock().unwrap();
            sealed.extend(rounds);
            Ok(())
        })
    }
}

#[tokio::test]
async fn passport_selfie_consent_reject_seals_nothing() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());

    let session = h.drive_to_consent(&listener).await;

    // Reject the consent screen → Completed(Rejected), NOTHING sealed.
    let (status, _session) = h
        .run(session, Event::ConsentDisclosure(false), &listener)
        .await;
    match status {
        RunStatus::Completed(Decision::Rejected) => {}
        _ => panic!("reject round expected Completed(Rejected)"),
    }

    let sealed = listener.sealed.lock().unwrap();
    assert!(
        sealed.is_empty(),
        "CONSENT GATE: reject path must seal zero disclosures, got {}",
        sealed.len(),
    );
}

#[tokio::test]
async fn passport_selfie_consent_accept_seals_disclosure() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());

    let session = h.drive_to_consent(&listener).await;

    // Accept the consent screen → Completed(Approved), disclosure sealed.
    let (status, _session) = h
        .run(session, Event::ConsentDisclosure(true), &listener)
        .await;
    match status {
        RunStatus::Completed(Decision::Approved) => {}
        _ => panic!("accept round expected Completed(Approved)"),
    }

    let sealed = listener.sealed.lock().unwrap();
    assert_eq!(
        sealed.len(),
        1,
        "CONSENT GATE: accept path must seal exactly one disclosure",
    );
    // The six canonical KYC fields the policy rendered on the consent
    // screen — show == seal.
    assert_eq!(
        sealed[0].len(),
        6,
        "sealed disclosure must carry all six rendered fields",
    );
    // Values survive verbatim (the long address triggers the runtime's
    // sanitise path but is plain ASCII, so it round-trips unchanged).
    assert!(
        sealed[0].iter().any(|f| f.value == "Jane Q. Citizen"),
        "sealed fields must include the rendered full_name value",
    );
}

#[tokio::test]
async fn media_rounds_keep_state_minimal() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());

    // genesis → render media(passport)
    let (_s0, after_genesis) = h.run(Session::default(), Event::Start, &listener).await;
    let baseline = after_genesis.state.len();

    // passport clip → render media(selfie)
    let (_s1, after_passport) = h
        .run(after_genesis, Event::Media(fake_capture()), &listener)
        .await;
    let after_passport_len = after_passport.state.len();

    // selfie clip → render consent-disclosure
    let (_s2, after_selfie) = h
        .run(after_passport, Event::Media(fake_capture()), &listener)
        .await;
    let after_selfie_len = after_selfie.state.len();

    // The clips are dropped the round they arrive — the policy keeps only
    // its step bookkeeping, so the sealed state must NOT grow as media
    // rounds accumulate (the data-minimization invariant).
    assert!(baseline <= 8, "policy step state should be tiny, got {baseline}");
    assert_eq!(
        after_passport_len, baseline,
        "passport media round must not grow sealed state",
    );
    assert_eq!(
        after_selfie_len, baseline,
        "selfie media round must not grow sealed state",
    );
}

#[tokio::test]
async fn oversized_state_traps() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());

    // Drive genesis with a consumer config that makes the policy return a
    // blob one byte over the cap — the runtime must trap the round rather
    // than seal an over-cap (clip-smuggling) state.
    let over = enclavid_engine::limits::POLICY_MAX_STATE_BYTES as i64 + 1;
    let props = vec![("state_bloat".to_string(), Prop::Int(over))];

    let result = h
        .runner
        .run(
            &h.policy,
            &h.embedded_imports,
            Session::default(),
            Event::Start,
            props,
            h.inputs(&listener),
        )
        .await;

    assert!(
        result.is_err(),
        "a state blob over POLICY_MAX_STATE_BYTES must trap the round",
    );

    // Nothing sealed on a trapped round.
    assert!(
        listener.sealed.lock().unwrap().is_empty(),
        "a trapped over-cap round must seal nothing",
    );
}

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

struct Harness {
    runner: Runner,
    /// The fused policy+well-known component (wac single-store fusion),
    /// compiled once and driven through every reducer round.
    policy: wasmtime::component::Component,
    /// Distinct per-catalog i18n/icons imports the fusion produced —
    /// handed to `run` so the host Linker registers them.
    embedded_imports: Vec<enclavid_engine::EmbeddedImport>,
    embedded: Arc<EmbeddedRegistry>,
}

impl Harness {
    fn new() -> Self {
        let runner = Runner::new().unwrap();
        // Fuse the test policy with the well-known plugin into one
        // component (the same path `Runner::compose` takes in prod).
        // The fixtures carry their embedded sections (embedded verbatim
        // from the author JSON), so `compose` derives each catalog's
        // content-hash from the same bytes the registry keys on.
        let plugins = vec![PluginInstance {
            package: WELL_KNOWN_PACKAGE.to_string(),
            wasm: well_known_component().to_vec(),
        }];
        let composition = runner.compose(test_policy_component(), &plugins).unwrap();

        // Composition-wide `EmbeddedRegistry`, keyed by each component's
        // catalog content-hash — policy first, then well-known, the same
        // order as the fused plugins. Both decls and hash come straight
        // from the sealed wasm (`load_embedded`), so they match exactly
        // what `compose` routed the imports under. The `ref_key` is a
        // fixed test value; production derives it per-policy from
        // `tee_seal_key + policy_ref`.
        let mut builder = EmbeddedRegistry::builder([7u8; 32]);
        for wasm in [test_policy_component(), well_known_component()] {
            let cat = enclavid_engine::load_embedded(wasm).expect("load embedded");
            builder.add_component(cat.hash, cat.decls);
        }
        let embedded = Arc::new(builder.build());

        Self {
            runner,
            policy: composition.component,
            embedded_imports: composition.embedded_imports,
            embedded,
        }
    }

    fn inputs(&self, listener: &Arc<RecordingListener>) -> RunInputs {
        RunInputs {
            listener: listener.clone(),
            embedded: self.embedded.clone(),
        }
    }

    /// One reducer round.
    async fn run(
        &self,
        session: Session,
        event: Event,
        listener: &Arc<RecordingListener>,
    ) -> (RunStatus, Session) {
        self.runner
            .run(
                &self.policy,
                &self.embedded_imports,
                session,
                event,
                vec![],
                self.inputs(listener),
            )
            .await
            .expect("reducer round")
    }

    /// Drive the common prefix: start → passport → selfie, leaving the
    /// session sitting on the consent-disclosure prompt.
    async fn drive_to_consent(&self, listener: &Arc<RecordingListener>) -> Session {
        // Round 1: start → render media(passport).
        let (status, session) = self.run(Session::default(), Event::Start, listener).await;
        assert_media(&status, "round 1 (passport)");

        // Round 2: media(passport) → render media(selfie).
        let (status, session) = self
            .run(session, Event::Media(fake_capture()), listener)
            .await;
        assert_media(&status, "round 2 (selfie)");

        // Round 3: media(selfie) → render consent-disclosure.
        let (status, session) = self
            .run(session, Event::Media(fake_capture()), listener)
            .await;
        match &status {
            RunStatus::AwaitingInput(Prompt::ConsentDisclosure(_)) => {}
            _ => panic!("round 3 expected AwaitingInput(ConsentDisclosure)"),
        }
        // The runtime must have persisted the consent prompt as
        // `current_prompt` — that's what gates the seal on the next round.
        assert!(
            matches!(session.current_prompt, Some(Prompt::ConsentDisclosure(_))),
            "consent prompt must be persisted as current_prompt",
        );
        session
    }
}

fn assert_media(status: &RunStatus, ctx: &str) {
    match status {
        RunStatus::AwaitingInput(Prompt::Media(_)) => {}
        _ => panic!("{ctx} expected AwaitingInput(Media)"),
    }
}

/// A single-step fake capture result (both passport and selfie specs are
/// single-shot, so the clip fills step index 0).
fn fake_capture() -> MediaResult {
    MediaResult {
        slot: 0,
        clip: Clip {
            frames: vec![vec![0xFF, 0xD8, 0xFF, 0xE0]],
        },
    }
}

// ---------------------------------------------------------------------
// Component build + embedded-section loading
// ---------------------------------------------------------------------

fn policy_dir() -> String {
    format!("{}/tests/fixtures/test-policy", env!("CARGO_MANIFEST_DIR"))
}

fn well_known_dir() -> String {
    format!("{}/../../plugins/well-known", env!("CARGO_MANIFEST_DIR"))
}

/// Build the `test-policy` fixture (cached), componentize it, and embed
/// its author JSON as `enclavid:embedded.*` custom sections — a sealed
/// component, exactly the shape the engine sees in production.
fn test_policy_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = policy_dir();
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/test_policy.wasm");
            embed_sections(build_componentized(&dir, &module), &dir)
        })
        .as_slice()
}

/// Build the `enclavid:well-known` plugin (cached), componentize it, and
/// embed its author JSON as custom sections.
fn well_known_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = well_known_dir();
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/well_known.wasm");
            embed_sections(build_componentized(&dir, &module), &dir)
        })
        .as_slice()
}

/// `cargo build --release` a wasm crate, then componentize its module.
/// Cargo's own build lock serializes concurrent test invocations safely.
fn build_componentized(crate_dir: &str, module_path: &str) -> Vec<u8> {
    let status = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(crate_dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke cargo for {crate_dir}: {e}"));
    assert!(status.success(), "build failed: {crate_dir}");

    let module = std::fs::read(module_path).expect("read wasm module");
    ComponentEncoder::default()
        .module(&module)
        .expect("module missing wit-bindgen custom section")
        .validate(true)
        .encode()
        .expect("componentize")
}

/// Append the fixture's embedded sections (author JSON, byte-for-byte)
/// to a componentized wasm — exactly what `enclavid embed` does. A
/// missing file produces no section (well-known ships no
/// disclosure-fields.json, for instance).
fn embed_sections(mut wasm: Vec<u8>, dir: &str) -> Vec<u8> {
    use enclavid_embedded::{SECTION_DISCLOSURE_FIELDS, SECTION_I18N, SECTION_ICONS};
    use wasm_encoder::{ComponentSection, CustomSection};
    let read = |name: &str| std::fs::read(format!("{dir}/{name}")).ok();
    for (name, data) in [
        (SECTION_DISCLOSURE_FIELDS, read("disclosure-fields.json")),
        (SECTION_I18N, read("i18n.json")),
        (SECTION_ICONS, read("icons.json")),
    ] {
        if let Some(bytes) = data {
            CustomSection {
                name: name.into(),
                data: bytes.into(),
            }
            .append_to_component(&mut wasm);
        }
    }
    wasm
}
