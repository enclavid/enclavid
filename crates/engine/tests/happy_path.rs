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

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use broker_client::{Clip, Decision, Event, MediaResult, Prompt, SessionState as Session};
use enclavid_engine::{
    ComponentDecls, ConsentDisclosure, EmbeddedRegistry, PluginInstance, Prop, RunInputs, RunStatus,
    Runner, SessionChange, SessionListener, Translation,
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
            &h.plugins,
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
    policy: wasmtime::component::Component,
    plugins: Vec<PluginInstance>,
    embedded: Arc<EmbeddedRegistry>,
}

impl Harness {
    fn new() -> Self {
        let runner = Runner::new().unwrap();
        let policy = runner.compile(test_policy_component()).unwrap();
        let plugin = PluginInstance {
            package: WELL_KNOWN_PACKAGE.to_string(),
            component: Arc::new(runner.compile(well_known_component()).unwrap()),
        };

        // Composition-wide `EmbeddedRegistry`: slot 0 = policy, slot 1 =
        // well-known — the SAME order as `plugins`, which the engine relies
        // on to align slot indices. The `ref_key` is a fixed test value;
        // production derives it per-policy from `tee_seal_key + policy_ref`.
        let mut builder = EmbeddedRegistry::builder([7u8; 32]);
        builder.add_component(load_test_policy_decls());
        builder.add_component(load_well_known_decls());
        let embedded = Arc::new(builder.build());

        Self {
            runner,
            policy,
            plugins: vec![plugin],
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
                &self.plugins,
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

/// Build the `test-policy` fixture (cached) and componentize it.
fn test_policy_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = format!("{}/tests/fixtures/test-policy", env!("CARGO_MANIFEST_DIR"));
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/test_policy.wasm");
            build_componentized(&dir, &module)
        })
        .as_slice()
}

/// Build the `enclavid:well-known` plugin (cached) and componentize it.
fn well_known_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = format!("{}/../../plugins/well-known", env!("CARGO_MANIFEST_DIR"));
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/well_known.wasm");
            build_componentized(&dir, &module)
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

/// Load the test-policy's embedded sections (slot 0) straight from the
/// on-disk source files. We bypass `load_embedded(wasm_bytes)` here
/// because the test fixture isn't sealed — it's a raw componentized wasm
/// without the embedded custom sections.
fn load_test_policy_decls() -> ComponentDecls {
    use enclavid_embedded::read_disclosure_fields;
    let dir = format!("{}/tests/fixtures/test-policy", env!("CARGO_MANIFEST_DIR"));
    let disclosure_fields =
        read_disclosure_fields(Path::new(&format!("{dir}/disclosure-fields.json")))
            .expect("read disclosure-fields.json")
            .map(|s| s.fields.into_iter().collect())
            .unwrap_or_default();
    ComponentDecls {
        disclosure_fields,
        localized: read_localized(&dir),
        icons: read_icon_names(&dir),
    }
}

/// Load the well-known plugin's embedded sections (slot 1). The plugin
/// ships no disclosure-fields — the policy is the single source of truth
/// for what's disclosable — so only i18n + icons are present.
fn load_well_known_decls() -> ComponentDecls {
    let dir = format!("{}/../../plugins/well-known", env!("CARGO_MANIFEST_DIR"));
    ComponentDecls {
        disclosure_fields: HashSet::new(),
        localized: read_localized(&dir),
        icons: read_icon_names(&dir),
    }
}

fn read_localized(dir: &str) -> HashMap<String, Vec<Translation>> {
    use enclavid_embedded::read_i18n;
    read_i18n(Path::new(&format!("{dir}/i18n.json")))
        .expect("read i18n.json")
        .map(|s| s.entries)
        .unwrap_or_default()
        .into_iter()
        .map(|(key, translations)| {
            let rows = translations
                .into_iter()
                .map(|(language, text)| Translation { language, text })
                .collect();
            (key, rows)
        })
        .collect()
}

fn read_icon_names(dir: &str) -> HashSet<String> {
    use enclavid_embedded::read_icons;
    read_icons(Path::new(&format!("{dir}/icons.json")))
        .expect("read icons.json")
        .map(|s| s.names.into_iter().collect())
        .unwrap_or_default()
}
