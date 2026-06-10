//! End-to-end: runs a test policy through the engine, simulating user inputs
//! between rounds by attaching typed response data to the Suspended request.
//!
//! The test policy wasm is compiled on-demand (first test invocation) rather
//! than via a build.rs — this keeps normal engine builds free of wasm tooling
//! dependencies and nightly toolchain requirements.

use std::collections::HashSet;
use std::process::Command;
use std::sync::OnceLock;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use enclavid_engine::{
    Decision, RunInputs, RunStatus, Runner, SessionChange, SessionListener, SessionState,
};
use enclavid_host_bridge::{
    Clip, SessionState as SessionStateProto, call_event, suspended,
};
use wit_component::ComponentEncoder;

/// Test listener: drops every committed change silently. The happy-path
/// test only inspects the final `SessionState` returned from `run`, so
/// we don't need to assert on per-event hook calls here.
struct NoopListener;

impl SessionListener for NoopListener {
    fn on_session_change<'a>(
        &'a self,
        _change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn passport_then_consent_rejected() {
    // Exercises the full suspend/resume loop without going through
    // consent=true — which would require a live DisclosureStore. The
    // rejection path validates replay of the passport cache hit + the
    // consent → typed response transition without external side effects.
    let component_bytes = test_policy_component();
    let runner = Runner::new().unwrap();
    let component = runner.compile(component_bytes).unwrap();

    // Load the policy manifest from the fixture's `manifest.json` —
    // single declarative file whose bytes ARE the wire format
    // (no assembly). Engine resolves the registered text-ref set
    // from it via `load_manifest`. Same path the api crate takes
    // in `lookup_policy`.
    let registered: Arc<HashSet<String>> = Arc::new(load_test_text_refs());

    let session = SessionState::default();

    // Round 1: evaluate → prompt-passport → Suspended.
    let (status, mut session) = runner
        .run(&component, &[], session, vec![], test_run_inputs(&registered))
        .await
        .unwrap();
    assert_suspended(&status, 1);

    // Simulate user submitting passport image.
    attach_passport(&mut session, fake_image());

    // Round 2: replays passport → prompt-disclosure → Suspended.
    let (status, mut session) = runner
        .run(&component, &[], session, vec![], test_run_inputs(&registered))
        .await
        .unwrap();
    assert_suspended(&status, 2);

    // Simulate user rejecting consent — side-effect-free path.
    attach_consent(&mut session, false);

    // Round 3: replays both → Completed(Rejected).
    let (status, _) = runner
        .run(&component, &[], session, vec![], test_run_inputs(&registered))
        .await
        .unwrap();
    match status {
        RunStatus::Completed(Decision::Rejected) => {}
        _ => panic!("round 3 expected Completed(Rejected)"),
    }
}

/// Builds the test policy on first call, caches the componentized wasm bytes
/// for subsequent calls. Cargo's own build lock serializes concurrent test
/// invocations safely.
fn test_policy_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let manifest = env!("CARGO_MANIFEST_DIR");
            let policy_dir = format!("{manifest}/tests/fixtures/test-policy");

            let status = Command::new("cargo")
                .args(["build", "--release"])
                .current_dir(&policy_dir)
                .status()
                .expect("failed to invoke cargo for test-policy");
            assert!(status.success(), "test-policy build failed");

            let module_path = format!(
                "{policy_dir}/target/wasm32-unknown-unknown/release/test_policy.wasm"
            );
            let module = std::fs::read(&module_path).expect("read test-policy module");

            ComponentEncoder::default()
                .module(&module)
                .expect("module missing wit-bindgen custom section")
                .validate(true)
                .encode()
                .expect("componentize test-policy")
        })
        .as_slice()
}

/// Load the test-policy's embedded text-ref declarations straight
/// from the on-disk source files. We bypass `load_static(wasm_bytes)`
/// here because the test fixture isn't sealed — it's just a raw
/// componentized wasm without the embedded custom sections.
/// Production path (`api::applicant::shared::lookup_policy`) reads
/// the sections directly out of the wasm via `load_static`.
fn load_test_text_refs() -> HashSet<String> {
    use enclavid_embedded::{read_disclosure_fields, read_i18n};
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let disclosure_path =
        format!("{manifest_dir}/tests/fixtures/test-policy/disclosure-fields.json");
    let i18n_path = format!("{manifest_dir}/tests/fixtures/test-policy/i18n.json");
    let fields = read_disclosure_fields(std::path::Path::new(&disclosure_path))
        .expect("read disclosure-fields.json")
        .map(|s| s.fields)
        .unwrap_or_default();
    let i18n_keys = read_i18n(std::path::Path::new(&i18n_path))
        .expect("read i18n.json")
        .map(|s| s.entries)
        .unwrap_or_default()
        .into_keys()
        .collect::<Vec<_>>();
    fields.into_iter().chain(i18n_keys).collect()
}

/// Stub host resources for the engine. The listener is a no-op — the
/// test stays on the consent=false path so the only events fired are
/// state-only (no disclosures), and we don't assert on them. The
/// `registered_text_refs` set is shared across rounds so every
/// `prompt-disclosure` / `prompt-media` call passes the engine's
/// membership check.
fn test_run_inputs(registered: &Arc<HashSet<String>>) -> RunInputs {
    RunInputs {
        listener: Arc::new(NoopListener),
        registered_text_refs: registered.clone(),
    }
}

fn fake_image() -> Vec<u8> {
    vec![0xFF, 0xD8, 0xFF, 0xE0]
}

fn assert_suspended(status: &RunStatus, round: usize) {
    match status {
        RunStatus::Suspended(_) => {}
        RunStatus::Completed(_) => panic!("round {round} expected Suspended"),
    }
}

/// Attach a passport clip to the last Suspended event's Media request.
/// The clip is a list of JPEG frames; tests use a single dummy frame
/// at step index 0 (single-shot passport).
fn attach_passport(session: &mut SessionStateProto, frame: Vec<u8>) {
    let ev = session.events.last_mut().expect("session log is empty");
    let Some(call_event::Status::Suspended(sus)) = ev.status.as_mut() else {
        panic!("last event is not Suspended: {:?}", ev.status);
    };
    let Some(suspended::Request::Media(media)) = sus.request.as_mut() else {
        panic!("expected Media request");
    };
    media
        .clips
        .insert(0, Clip { frames: vec![frame] });
}

/// Attach consent=accepted to the last Suspended event's Consent request.
fn attach_consent(session: &mut SessionStateProto, accepted: bool) {
    let ev = session.events.last_mut().expect("session log is empty");
    let Some(call_event::Status::Suspended(sus)) = ev.status.as_mut() else {
        panic!("last event is not Suspended: {:?}", ev.status);
    };
    let Some(suspended::Request::Consent(c)) = sus.request.as_mut() else {
        panic!("expected Consent request");
    };
    c.accepted = Some(accepted);
}
