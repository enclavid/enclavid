//! End-to-end: runs a test policy — composed with the `enclavid:well-known`
//! plugin — through the engine, simulating user inputs between rounds by
//! attaching typed response data to the Suspended request.
//!
//! The policy and the plugin wasm are compiled on-demand (first test
//! invocation) rather than via a build.rs — this keeps normal engine builds
//! free of wasm tooling dependencies and nightly toolchain requirements.
//!
//! The test policy pulls its capture flows (`capture::passport`,
//! `capture::selfie`) and disclosure `display-field`s from the well-known
//! plugin, so the run links one plugin at slot 1. Flow:
//! passport capture → selfie capture → consent → Completed.

use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::OnceLock;

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use enclavid_engine::{
    ComponentDecls, Decision, EmbeddedRegistry, PluginInstance, RunInputs, RunStatus, Runner,
    SessionChange, SessionListener, SessionState, Translation,
};
use broker_client::{
    Clip, SessionState as SessionStateProto, call_event, suspended,
};
use wit_component::ComponentEncoder;

/// WIT package id the policy imports its capture / disclosure-field helpers
/// from; used as the plugin descriptor label at compose time.
const WELL_KNOWN_PACKAGE: &str = "enclavid:well-known@0.1.0";

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
async fn passport_selfie_then_consent_rejected() {
    // Exercises the full suspend/resume loop with a linked plugin, without
    // going through consent=true — which would require a live
    // DisclosureStore. The rejection path validates replay of both capture
    // cache hits + the consent → typed response transition without external
    // side effects.
    let runner = Runner::new().unwrap();
    let policy = runner.compile(test_policy_component()).unwrap();
    let plugin = PluginInstance {
        package: WELL_KNOWN_PACKAGE.to_string(),
        component: Arc::new(runner.compile(well_known_component()).unwrap()),
    };
    let plugins = vec![plugin];

    // Composition-wide `EmbeddedRegistry`: slot 0 = policy, slot 1 =
    // well-known — the SAME order as `plugins` above, which the engine
    // relies on to align slot indices. Same construction the api crate does
    // in `lookup_policy`. The `ref_key` is a fixed test value; production
    // derives it per-policy from `tee_seal_key + policy_ref`.
    let mut builder = EmbeddedRegistry::builder([7u8; 32]);
    builder.add_component(load_test_policy_decls());
    builder.add_component(load_well_known_decls());
    let embedded = Arc::new(builder.build());

    let session = SessionState::default();

    // Round 1: evaluate → capture::passport() → prompt-media → Suspended.
    let (status, mut session) = runner
        .run(&policy, &plugins, session, vec![], test_run_inputs(&embedded))
        .await
        .unwrap();
    assert_suspended(&status, 1);
    attach_media_clip(&mut session, fake_image());

    // Round 2: replays passport → capture::selfie() → prompt-media → Suspended.
    let (status, mut session) = runner
        .run(&policy, &plugins, session, vec![], test_run_inputs(&embedded))
        .await
        .unwrap();
    assert_suspended(&status, 2);
    attach_media_clip(&mut session, fake_image());

    // Round 3: replays both captures → prompt-disclosure → Suspended (Consent).
    let (status, mut session) = runner
        .run(&policy, &plugins, session, vec![], test_run_inputs(&embedded))
        .await
        .unwrap();
    assert_suspended(&status, 3);
    attach_consent(&mut session, false);

    // Round 4: replays everything → Completed(Rejected).
    let (status, _) = runner
        .run(&policy, &plugins, session, vec![], test_run_inputs(&embedded))
        .await
        .unwrap();
    match status {
        RunStatus::Completed(Decision::Rejected) => {}
        _ => panic!("round 4 expected Completed(Rejected)"),
    }
}

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
/// on-disk source files. We bypass `load_embedded(wasm_bytes)` here because
/// the test fixture isn't sealed — it's a raw componentized wasm without
/// the embedded custom sections. Production
/// (`api::applicant::shared::lookup_policy`) reads them via `load_embedded`.
fn load_test_policy_decls() -> ComponentDecls {
    use enclavid_embedded::read_disclosure_fields;
    let dir = format!("{}/tests/fixtures/test-policy", env!("CARGO_MANIFEST_DIR"));
    let disclosure_fields = read_disclosure_fields(Path::new(&format!("{dir}/disclosure-fields.json")))
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

/// Stub host resources for the engine. The listener is a no-op — the
/// test stays on the consent=false path so the only events fired are
/// state-only (no disclosures), and we don't assert on them. The
/// composition-wide `EmbeddedRegistry` is shared across rounds so
/// every issued ref keeps its slot attribution stable on replay.
fn test_run_inputs(embedded: &Arc<EmbeddedRegistry>) -> RunInputs {
    RunInputs {
        listener: Arc::new(NoopListener),
        embedded: embedded.clone(),
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

/// Attach a captured clip to the last Suspended event's Media request.
/// Both the passport and selfie specs from the plugin are single-shot
/// (one capture step), so the clip lands at step index 0.
fn attach_media_clip(session: &mut SessionStateProto, frame: Vec<u8>) {
    let ev = session.events.last_mut().expect("session log is empty");
    let Some(call_event::Status::Suspended(sus)) = ev.status.as_mut() else {
        panic!("last event is not Suspended: {:?}", ev.status);
    };
    let Some(suspended::Request::Media(media)) = sus.request.as_mut() else {
        panic!("expected Media request");
    };
    media.clips.insert(0, Clip { frames: vec![frame] });
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
