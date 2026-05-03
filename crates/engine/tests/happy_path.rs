//! End-to-end: runs a test policy through the engine, simulating user inputs
//! between rounds by attaching typed response data to the Suspended request.
//!
//! The test policy wasm is compiled on-demand (first test invocation) rather
//! than via a build.rs — this keeps normal engine builds free of wasm tooling
//! dependencies and nightly toolchain requirements.

use std::process::Command;
use std::sync::OnceLock;

use enclavid_engine::policy::{Decision, RunResources};
use enclavid_engine::{RunStatus, Runner, SessionState};
use enclavid_host_bridge::{
    Passport, SessionState as SessionStateProto, call_event, document_request, suspended,
};
use wit_component::ComponentEncoder;

#[tokio::test]
async fn passport_then_consent_rejected() {
    // Exercises the full suspend/resume loop without going through
    // consent=true — which would require a live DisclosureStore. The
    // rejection path validates replay of the passport cache hit + the
    // consent → typed response transition without external side effects.
    let component_bytes = test_policy_component();
    let runner = Runner::new().unwrap();
    let component = runner.compile(component_bytes).unwrap();

    let session = SessionState::default();

    // Round 1: evaluate → prompt-passport → Suspended.
    let (status, mut session, _pending) = runner
        .run(&component, session, vec![], test_resources())
        .await
        .unwrap();
    assert_suspended(&status, 1);

    // Simulate user submitting passport image.
    attach_passport(&mut session, fake_image());

    // Round 2: replays passport → prompt-disclosure → Suspended.
    let (status, mut session, _pending) = runner
        .run(&component, session, vec![], test_resources())
        .await
        .unwrap();
    assert_suspended(&status, 2);

    // Simulate user rejecting consent — side-effect-free path.
    attach_consent(&mut session, false);

    // Round 3: replays both → Completed(Rejected).
    let (status, _, _pending) = runner
        .run(&component, session, vec![], test_resources())
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

/// Stub host resources for the engine. After the buffer-on-engine
/// refactor there's no DisclosureStore handle to inject — pending
/// disclosures accumulate in HostState in-memory and would be returned
/// by `runner.run` for the api to commit. This test stays on the
/// consent=false path so no disclosure entries are produced.
fn test_resources() -> RunResources {
    RunResources {
        client_pk: b"test-pk".to_vec(),
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

/// Attach passport image to the last Suspended event's Document request.
fn attach_passport(session: &mut SessionStateProto, image: Vec<u8>) {
    let ev = session.events.last_mut().expect("session log is empty");
    let Some(call_event::Status::Suspended(sus)) = ev.status.as_mut() else {
        panic!("last event is not Suspended: {:?}", ev.status);
    };
    let Some(suspended::Request::Document(doc)) = sus.request.as_mut() else {
        panic!("expected Document request");
    };
    doc.kind = Some(document_request::Kind::Passport(Passport { image: Some(image) }));
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
