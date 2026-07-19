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
//!               seven fields the policy rendered — six canonical KYC fields
//!               plus the face-age estimate).
//!
//! The policy and the plugin wasm are compiled on-demand (first test
//! invocation) rather than via a build.rs — this keeps normal engine
//! builds free of wasm tooling dependencies and nightly requirements.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use broker_client::{Clip, Decision, Event, MediaResult, Prompt, SessionState as Session};
use engine_compiler::Compiler;
use engine_executor::{
    Component, ConsentDisclosure, EmbeddedImport, EmbeddedRegistry, Executor, MediaStore,
    PluginInstance, Prop, RunInputs, RunResult, RunStatus, SessionChange, SessionListener,
};

/// End-to-end test harness mirroring the old in-process `Runner` facade: a
/// [`Compiler`] + [`Executor`] on SEPARATE engines, bridged by serialized
/// cwasm — exactly the production path (compose over there, deserialize +
/// run over here). Its `compose` round-trips the fused component through
/// cwasm so the returned `component` is instantiable on the executor engine.
struct TestRunner {
    compiler: Compiler,
    executor: Executor,
}

/// A composed policy landed on the executor engine (post round-trip), with
/// the same field names the tests read off the old `Composition`.
struct Fused {
    component: Component,
    embedded_imports: Vec<EmbeddedImport>,
}

impl TestRunner {
    fn new() -> RunResult<Self> {
        Ok(Self {
            compiler: Compiler::new()?,
            executor: Executor::new()?,
        })
    }

    fn fuse(&self, policy_wasm: &[u8], plugins: &[PluginInstance]) -> RunResult<Vec<u8>> {
        self.compiler.fuse(policy_wasm, plugins)
    }

    /// Compose on the compiler engine, then serialize → deserialize onto the
    /// executor engine so the component is runnable here (the cross-engine
    /// cwasm bridge the real fleet uses across CVMs).
    fn compose(&self, policy_wasm: &[u8], plugins: &[PluginInstance]) -> RunResult<Fused> {
        let composition = self.compiler.compose(policy_wasm, plugins)?;
        let cwasm = self.compiler.serialize_component(&composition.component)?;
        let component = self.executor.deserialize_component(&cwasm)?;
        Ok(Fused {
            component,
            embedded_imports: composition.embedded_imports,
        })
    }

    async fn run(
        &self,
        component: &Component,
        embedded_imports: &[EmbeddedImport],
        session: Session,
        event: Event,
        props: Vec<(String, Prop)>,
        inputs: RunInputs,
    ) -> RunResult<(RunStatus, Session)> {
        self.executor
            .run(component, embedded_imports, session, event, props, inputs)
            .await
    }
}

/// In-memory stand-in for the host blob store, shared with the
/// [`RecordingListener`] (which populates it from each round's captured
/// media) so a later `frame::from-blob-ref` rehydrate hits. Stage 3 swaps in
/// the broker-backed store; this proves the engine seam.
#[derive(Clone, Default)]
struct MemMediaStore(Arc<Mutex<HashMap<[u8; 32], Arc<Vec<u8>>>>>);

impl MediaStore for MemMediaStore {
    fn load<'a>(
        &'a self,
        blob_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = RunResult<Option<Arc<Vec<u8>>>>> + Send + 'a>> {
        let hit = self.0.lock().unwrap().get(blob_hash).cloned();
        Box::pin(async move { Ok(hit) })
    }
}

/// A media store that COUNTS every `load` call, over a shared blob map. Proves
/// the pull is lazy: `from-blob-ref` alone must not load; `bytes()` must.
#[derive(Clone, Default)]
struct CountingMediaStore {
    map: Arc<Mutex<HashMap<[u8; 32], Arc<Vec<u8>>>>>,
    loads: Arc<AtomicUsize>,
}

impl MediaStore for CountingMediaStore {
    fn load<'a>(
        &'a self,
        blob_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = RunResult<Option<Arc<Vec<u8>>>>> + Send + 'a>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        let hit = self.map.lock().unwrap().get(blob_hash).cloned();
        Box::pin(async move { Ok(hit) })
    }
}

/// WIT package id the policy imports its capture / disclosure-field
/// helpers from; used as the plugin descriptor label at compose time.
const WELL_KNOWN_PACKAGE: &str = "enclavid:well-known@0.1.0";
/// Package id of the minimal second plugin the policy imports (its
/// `tag::get()` supplies the consent requester). Linked alongside
/// well-known in the dynamic path, and at runtime over a pre-fused core
/// in the hybrid test.
const EXTRA_PACKAGE: &str = "enclavid:extra@0.1.0";
/// Package id of the face-age plugin the policy calls on the selfie
/// round. Ships no embedded catalog (no i18n/icons/DF), so it adds no
/// strict-routing twin.
const FACE_AGE_PACKAGE: &str = "enclavid:face-age@0.1.0";
/// Package id of the preprocess plugin — decodes the selfie `clip` into the
/// plugin-owned `decoded-frame` the policy threads to face-age. Ships no
/// embedded catalog, so it adds no strict-routing twin.
const PREPROCESS_PACKAGE: &str = "enclavid:preprocess@0.1.0";
/// Package id of the face-detect plugin — locates the `face` in the
/// decoded-frame, which the policy threads to face-age. Ships no embedded
/// catalog, so it adds no strict-routing twin.
const FACE_DETECT_PACKAGE: &str = "enclavid:face-detect@0.1.0";

/// The plugins the policy imports — well-known + extra + face-age. All
/// must be present in every composition, since the policy calls into
/// each (well-known for specs/DF, extra for the requester tag, face-age
/// on the selfie round).
fn all_plugins() -> Vec<PluginInstance> {
    vec![
        PluginInstance {
            package: WELL_KNOWN_PACKAGE.to_string(),
            wasm: well_known_component().to_vec(),
        },
        PluginInstance {
            package: EXTRA_PACKAGE.to_string(),
            wasm: extra_component().to_vec(),
        },
        PluginInstance {
            package: PREPROCESS_PACKAGE.to_string(),
            wasm: preprocess_component().to_vec(),
        },
        PluginInstance {
            package: FACE_DETECT_PACKAGE.to_string(),
            wasm: face_detect_component().to_vec(),
        },
        PluginInstance {
            package: FACE_AGE_PACKAGE.to_string(),
            wasm: face_age_component().to_vec(),
        },
    ]
}

/// Recording listener: captures every sealed disclosure the runtime
/// fires, so the test can assert the consent gate (reject seals nothing,
/// accept seals exactly what was shown).
#[derive(Default)]
struct RecordingListener {
    sealed: Mutex<Vec<Vec<broker_client::DisplayField>>>,
    /// Backs the shared [`MemMediaStore`] — every captured frame the runtime
    /// stages this round is inserted here, simulating the atomic media+state
    /// commit, so a later rehydrate finds it. `Arc<Vec<u8>>` so the insert
    /// shares the runtime's allocation (no deep copy).
    media: Arc<Mutex<HashMap<[u8; 32], Arc<Vec<u8>>>>>,
}

impl RecordingListener {
    /// A media store sharing this listener's blob map (write via the listener,
    /// read via `frame::from-blob-ref`).
    fn media_store(&self) -> Arc<dyn MediaStore> {
        Arc::new(MemMediaStore(self.media.clone()))
    }
}

impl SessionListener for RecordingListener {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = RunResult<()>> + Send + 'a>> {
        let rounds: Vec<Vec<broker_client::DisplayField>> = change
            .disclosures
            .iter()
            .map(|d: &ConsentDisclosure| d.fields.clone())
            .collect();
        let blobs: Vec<([u8; 32], Arc<Vec<u8>>)> = change
            .media
            .map(|m| m.blobs.iter().map(|(h, b)| (*h, b.clone())).collect())
            .unwrap_or_default();
        Box::pin(async move {
            self.sealed.lock().unwrap().extend(rounds);
            self.media.lock().unwrap().extend(blobs);
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
    // The seven fields the policy rendered on the consent screen — the six
    // canonical KYC fields plus the face-age estimate — show == seal.
    assert_eq!(
        sealed[0].len(),
        7,
        "sealed disclosure must carry all seven rendered fields",
    );
    // Values survive verbatim (the long address triggers the runtime's
    // sanitise path but is plain ASCII, so it round-trips unchanged).
    assert!(
        sealed[0].iter().any(|f| f.value == "Jane Q. Citizen"),
        "sealed fields must include the rendered full_name value",
    );
    // The face-age estimate reached the consent disclosure: it is the only
    // field whose value is a bare integer (the canonical fields carry names /
    // dashed dates / alphanumerics). Proves the plugin-computed age is
    // disclosed through the consent gate, not auto-shared.
    assert!(
        sealed[0].iter().any(|f| f.value.parse::<i32>().is_ok()),
        "sealed fields must include the face-age estimate (a numeric value)",
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

    // Media BYTES never enter `state`: the frames are stored host-side and the
    // policy keeps only a `blob-ref` (a 64-char hex content hash — the cross-
    // round handle it rehydrates from). So the engine's `SessionState.state`
    // (the REAL bytes, pre-seal) stays tiny — step tag + at most one ref —
    // never anywhere near a JPEG frame (KiB+), no matter how many media rounds
    // accumulate.
    assert!(baseline <= 8, "policy step state should be tiny, got {baseline}");
    // The passport round stashes the passport frame's ref (step + 64 hex chars).
    assert!(
        after_passport_len <= baseline + 64,
        "passport round state = step + one blob-ref, got {after_passport_len}",
    );
    // The selfie round rehydrates + drops the ref, back to just the step tag.
    assert!(
        after_selfie_len <= 8,
        "selfie round must drop the ref, back to a tiny step state, got {after_selfie_len}",
    );
}

/// A `blob::from-blob-ref` MISS: the passport ref the policy stashed isn't in
/// the store (here: a store that never gets the captured blobs), so the selfie
/// round's rehydrate returns `None` and the engine TRAPS the round (a fabricated
/// / unknown ref is never a legitimate outcome). Proves the miss-traps path.
#[tokio::test]
async fn reload_by_ref_misses() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());
    // An empty store, NOT the listener's map — so captured blobs never land in
    // what `from-blob-ref` reads, forcing a miss on the selfie round.
    let empty_store: Arc<dyn MediaStore> = Arc::new(MemMediaStore::default());
    let inputs = || RunInputs {
        listener: listener.clone(),
        embedded: h.embedded.clone(),
        media_store: empty_store.clone(),
    };
    let round = |session, event| {
        h.runner.run(
            &h.policy,
            &h.embedded_imports,
            session,
            event,
            vec![],
            inputs(),
        )
    };

    let (_s, session) = round(Session::default(), Event::Start).await.unwrap();
    let (_s, session) = round(session, Event::Media(fake_capture())).await.unwrap();
    // Selfie round rehydrates the passport ref and reads its `bytes()`; the ref
    // is absent from the empty store → the lazy pull returns None → the engine
    // TRAPS the round (a fabricated/unknown ref is never a legitimate outcome),
    // so the run errors rather than returning a status.
    let result = round(session, Event::Media(fake_capture())).await;
    assert!(
        result.is_err(),
        "a from-blob-ref miss must trap the round, not yield a recoverable status",
    );
}

/// LAZY pull: `blob::from-blob-ref` returns a COLD handle that does NO host
/// load; the load fires only when `bytes()` is read. Proven with a counting
/// store — the `skip_passport_read` prop makes the selfie round rehydrate the
/// passport handle but skip `bytes()`, so `from-blob-ref` alone loads nothing.
#[tokio::test]
async fn from_blob_ref_is_lazy_load_on_bytes() {
    async fn passport_loads(read_bytes: bool) -> usize {
        let h = Harness::new();
        let listener = Arc::new(RecordingListener::default());
        let loads = Arc::new(AtomicUsize::new(0));
        // The counting store shares the listener's captured-blob map, so the
        // passport reload finds the frame the passport round stored.
        let store: Arc<dyn MediaStore> = Arc::new(CountingMediaStore {
            map: listener.media.clone(),
            loads: loads.clone(),
        });
        let props: Vec<(String, Prop)> = if read_bytes {
            vec![]
        } else {
            vec![("skip_passport_read".to_string(), Prop::Int(1))]
        };
        let inputs = || RunInputs {
            listener: listener.clone(),
            embedded: h.embedded.clone(),
            media_store: store.clone(),
        };
        let round = |session, event| {
            h.runner.run(
                &h.policy,
                &h.embedded_imports,
                session,
                event,
                props.clone(),
                inputs(),
            )
        };
        let (_s, session) = round(Session::default(), Event::Start).await.unwrap();
        let (_s, session) = round(session, Event::Media(fake_capture())).await.unwrap();
        // Selfie round: rehydrates the passport by ref; reads bytes() iff `read_bytes`.
        // The selfie's own frame is the warm ingest blob, so its decode loads nothing.
        let _ = round(session, Event::Media(fake_capture())).await.unwrap();
        loads.load(Ordering::SeqCst)
    }

    assert_eq!(
        passport_loads(false).await,
        0,
        "from-blob-ref alone must not trigger a host load (lazy)",
    );
    assert_eq!(
        passport_loads(true).await,
        1,
        "reading bytes() on the rehydrated blob must pull exactly once",
    );
}

#[tokio::test]
async fn empty_passport_clip_is_retryable() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());

    // genesis → render media(passport)
    let (status, session) = h.run(Session::default(), Event::Start, &listener).await;
    assert_media(&status, "genesis (passport)");

    // Feed a capture with ZERO frames. The policy reads the host-owned
    // `clip` resource (`frame_count` / `frame`), sees an empty capture,
    // and returns a retryable rejection — proving the frames reach the
    // policy as a readable resource handle, not as bytes lowered into its
    // linear memory.
    let empty = MediaResult {
        slot: 0,
        clip: Clip { frames: vec![] },
    };
    let (status, _session) = h.run(session, Event::Media(empty), &listener).await;
    match status {
        RunStatus::Completed(Decision::RejectedRetryable) => {}
        _ => panic!("empty passport clip must yield Completed(RejectedRetryable)"),
    }
}

#[tokio::test]
async fn empty_selfie_clip_is_retryable_via_plugin() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());

    // genesis → passport prompt
    let (status, session) = h.run(Session::default(), Event::Start, &listener).await;
    assert_media(&status, "genesis (passport)");
    // passport clip → selfie prompt
    let (status, session) = h
        .run(session, Event::Media(fake_capture()), &listener)
        .await;
    assert_media(&status, "passport → selfie");

    // Feed a selfie capture with ZERO frames. On the selfie round the
    // policy hands the clip to the FUSED face-age plugin; the plugin reads
    // 0 frames and returns confidence 0; the policy maps that to a
    // retryable rejection. Proves the plugin was invoked across the fused
    // boundary during `handle` and actually read the clip resource — the
    // full clip-consumer path, not just the policy-side read.
    let empty = MediaResult {
        slot: 0,
        clip: Clip { frames: vec![] },
    };
    let (status, _session) = h.run(session, Event::Media(empty), &listener).await;
    match status {
        RunStatus::Completed(Decision::RejectedRetryable) => {}
        _ => panic!("empty selfie clip must yield Completed(RejectedRetryable) via the face-age plugin"),
    }
}

#[tokio::test]
async fn oversized_state_traps() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());

    // Drive genesis with a consumer config that makes the policy return a
    // blob one byte over the cap — the runtime must trap the round rather
    // than seal an over-cap (clip-smuggling) state.
    let over = engine_executor::limits::POLICY_MAX_STATE_BYTES as i64 + 1;
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

/// STATIC-strict consumption: fuse policy + well-known into a
/// self-contained artifact (what `enclavid link` would ship), then feed
/// it back with NO runtime plugins. The engine must reconstruct the
/// embedded manifest from the artifact's own `embedded-slot:*` imports,
/// recover the nested catalogs for the registry, and resolve both
/// strict (plugin i18n/icons) and merged (DF) refs through it.
#[tokio::test]
async fn static_fused_artifact_resolves_strictly() {
    let runner = TestRunner::new().unwrap();
    let fused = runner.fuse(test_policy_component(), &all_plugins()).unwrap();

    // The twins survive as distinct `embedded-slot:*` imports (strict
    // routing) — not collapsed to canonical. The policy calls only
    // `localized` (its capture icons come from well-known), so wit_bindgen
    // elides its unused icons import; distinct twins are: policy (i18n) +
    // well-known (i18n+icons) + extra (i18n) = 4. face-age ships no
    // embedded catalog, so it adds no twin.
    let imports = engine_compiler::top_level_imports(&fused).unwrap();
    let slots: Vec<&String> = imports
        .iter()
        .filter(|n| n.starts_with("embedded-slot:"))
        .collect();
    assert_eq!(
        slots.len(),
        4,
        "policy(i18n) + well-known(i18n+icons) + extra(i18n) = 4 distinct twin imports, got {slots:?}",
    );
    // Each twin name carries the routed interface version (`0.1.0` →
    // `-0-1-0`, kept off the semver `@` track) so two components with
    // byte-identical catalogs but different versions can't collide onto
    // one twin — and reconstruct can recover the version below.
    assert!(
        slots.iter().all(|n| n.contains("-0-1-0/")),
        "twin names must carry the interface version, got {slots:?}",
    );

    // Consume with an empty plugin list — the static path. The engine
    // reconstructs the strict manifest from the artifact's own
    // `embedded-slot:*` imports.
    let composition = runner.compose(&fused, &[]).unwrap();
    assert_eq!(
        composition.embedded_imports.len(),
        4,
        "static artifact's strict manifest reconstructed from its imports",
    );

    // Registry from the fused artifact's OWN nested catalogs, policy first.
    let mut cats = engine_compiler::load_embedded_nested(&fused).unwrap();
    assert!(
        cats.iter().filter(|c| c.is_policy).count() == 1,
        "exactly one nested policy catalog recovered, got {}",
        cats.len(),
    );
    cats.sort_by_key(|c| !c.is_policy);
    let mut builder = EmbeddedRegistry::builder();
    for c in cats {
        builder.add_component(c.hash, c.decls);
    }
    let embedded = Arc::new(builder.build());
    let listener = Arc::new(RecordingListener::default());

    // start → media(passport) → media(selfie) → consent-disclosure.
    // Each media prompt resolves the plugin's i18n/icons strictly; the
    // consent screen resolves DF (merged) — all through the static
    // artifact with no runtime fusion.
    let inputs = || RunInputs {
        listener: listener.clone(),
        embedded: embedded.clone(),
        media_store: listener.media_store(),
    };
    let (status, session) = runner
        .run(&composition.component, &composition.embedded_imports, Session::default(), Event::Start, vec![], inputs())
        .await
        .expect("static round 1");
    assert_media(&status, "static: round 1 (passport)");
    let (status, session) = runner
        .run(&composition.component, &composition.embedded_imports, session, Event::Media(fake_capture()), vec![], inputs())
        .await
        .expect("static round 2");
    assert_media(&status, "static: round 2 (selfie)");
    let (status, _session) = runner
        .run(&composition.component, &composition.embedded_imports, session, Event::Media(fake_capture()), vec![], inputs())
        .await
        .expect("static round 3");
    match &status {
        RunStatus::AwaitingInput(Prompt::ConsentDisclosure(_)) => {}
        _ => panic!("static: round 3 expected AwaitingInput(ConsentDisclosure)"),
    }
}

/// The definitive runtime proof of STRICT per-component isolation.
///
/// The test-policy and well-known BOTH declare the i18n key
/// `passport_title` with different text. well-known's passport capture
/// spec resolves `localized("passport_title")` — under strict routing
/// it MUST resolve against well-known's OWN catalog ("Your passport"),
/// via its own twin import. If resolution were first-match (the failure
/// mode when the twins collapse), it would pick the POLICY's colliding
/// value instead (policy is composed first). So this asserts the plugin
/// never sees the policy's translation.
#[tokio::test]
async fn strict_routing_isolates_colliding_i18n_key() {
    let h = Harness::new();
    let listener = Arc::new(RecordingListener::default());

    // Round 1: start → render media(passport). The spec's `label_ref` is
    // the token well-known produced from `localized("passport_title")`.
    let (status, _session) = h.run(Session::default(), Event::Start, &listener).await;
    let spec = match status {
        RunStatus::AwaitingInput(Prompt::Media(spec)) => spec,
        _ => panic!("round 1 expected AwaitingInput(Media)"),
    };

    // The engine resolved `spec.label` (well-known's `passport_title`) at
    // the action boundary; the domain carries the translation set
    // directly, no registry lookup needed.
    let en = spec
        .label
        .translations
        .iter()
        .find(|t| t.language == "en")
        .expect("en translation present")
        .text
        .as_str();

    assert_eq!(
        en, "Your passport",
        "well-known's passport spec must resolve its OWN passport_title \
         (strict isolation) — got the policy's colliding value, which \
         means routing collapsed to first-match",
    );

    // Guard against a vacuous test: the collision must be REAL — the
    // policy declared a DIFFERENT passport_title that first-match (policy
    // composed first) would have leaked here.
    let policy_value = "POLICY-OWNED passport_title (must NOT leak into the plugin)";
    assert!(
        h.embedded
            .localized
            .declared()
            .any(|rows| rows.iter().any(|t| t.text == policy_value)),
        "the policy's colliding passport_title must be registered, else \
         the isolation assertion above is vacuous",
    );
}

/// HYBRID composition: a pre-fused core (policy + well-known baked) plus a
/// runtime plugin (extra) linked on top. The policy imports `extra/tag`,
/// which the core leaves unsatisfied; the runtime fusion wires it, routes
/// extra's embedded to its own twin, and passes through the core's baked
/// twins. The consent requester ref (`tag::get()` → `extra_tag`) must
/// resolve against the RUNTIME extra plugin's OWN catalog — proving
/// strict routing survives the pass-through, not first-match (which
/// would leak the policy's colliding `extra_tag`).
#[tokio::test]
async fn hybrid_core_plus_runtime_plugin_resolves_strictly() {
    let runner = TestRunner::new().unwrap();

    // CORE: policy + well-known + preprocess + face-age baked. The policy
    // still imports extra/tag (unsatisfied — a runtime import of the core).
    let baked = vec![
        PluginInstance {
            package: WELL_KNOWN_PACKAGE.to_string(),
            wasm: well_known_component().to_vec(),
        },
        PluginInstance {
            package: PREPROCESS_PACKAGE.to_string(),
            wasm: preprocess_component().to_vec(),
        },
        PluginInstance {
            package: FACE_DETECT_PACKAGE.to_string(),
            wasm: face_detect_component().to_vec(),
        },
        PluginInstance {
            package: FACE_AGE_PACKAGE.to_string(),
            wasm: face_age_component().to_vec(),
        },
    ];
    let core = runner.fuse(test_policy_component(), &baked).unwrap();

    // HYBRID: link extra at runtime over the pre-fused core.
    let runtime = vec![PluginInstance {
        package: EXTRA_PACKAGE.to_string(),
        wasm: extra_component().to_vec(),
    }];
    let composition = runner.compose(&core, &runtime).unwrap();

    // Registry: policy + well-known recovered from the core's nested
    // catalogs (policy first), plus the runtime extra catalog.
    let mut cats = engine_compiler::load_embedded_nested(&core).unwrap();
    cats.sort_by_key(|c| !c.is_policy);
    let mut builder = EmbeddedRegistry::builder();
    for c in cats {
        builder.add_component(c.hash, c.decls);
    }
    let extra_cat = engine_compiler::load_embedded(extra_component()).unwrap();
    builder.add_component(extra_cat.hash, extra_cat.decls);
    let embedded = Arc::new(builder.build());
    let listener = Arc::new(RecordingListener::default());

    let inputs = || RunInputs {
        listener: listener.clone(),
        embedded: embedded.clone(),
        media_store: listener.media_store(),
    };
    // start → media(passport) → media(selfie) → consent-disclosure.
    let (status, session) = runner
        .run(&composition.component, &composition.embedded_imports, Session::default(), Event::Start, vec![], inputs())
        .await
        .expect("hybrid round 1");
    assert_media(&status, "hybrid: round 1 (passport)");
    let (status, session) = runner
        .run(&composition.component, &composition.embedded_imports, session, Event::Media(fake_capture()), vec![], inputs())
        .await
        .expect("hybrid round 2");
    assert_media(&status, "hybrid: round 2 (selfie)");
    let (status, _session) = runner
        .run(&composition.component, &composition.embedded_imports, session, Event::Media(fake_capture()), vec![], inputs())
        .await
        .expect("hybrid round 3");
    let disclosure = match status {
        RunStatus::AwaitingInput(Prompt::ConsentDisclosure(d)) => d,
        _ => panic!("hybrid round 3 expected AwaitingInput(ConsentDisclosure)"),
    };

    // The requester came from the RUNTIME extra plugin (`tag::get()`);
    // the engine resolved it at the boundary into `disclosure.requester`.
    let en = disclosure
        .requester
        .translations
        .iter()
        .find(|t| t.language == "en")
        .expect("en translation present")
        .text
        .as_str();
    assert_eq!(
        en, "EXTRA-PLUGIN-TAG",
        "runtime extra plugin must resolve extra_tag against its OWN \
         catalog in a hybrid composition — got the policy's colliding value",
    );

    // Collision is real: the policy declared a different extra_tag.
    let policy_value = "POLICY-OWNED extra_tag (must NOT leak into the extra plugin)";
    assert!(
        embedded
            .localized
            .declared()
            .any(|rows| rows.iter().any(|t| t.text == policy_value)),
        "the policy's colliding extra_tag must be registered, else the \
         isolation assertion above is vacuous",
    );
}

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

struct Harness {
    runner: TestRunner,
    /// The fused policy+well-known component (wac single-store fusion),
    /// compiled once and driven through every reducer round.
    policy: Component,
    /// Distinct per-catalog i18n/icons imports the fusion produced —
    /// handed to `run` so the host Linker registers them.
    embedded_imports: Vec<EmbeddedImport>,
    embedded: Arc<EmbeddedRegistry>,
}

impl Harness {
    fn new() -> Self {
        let runner = TestRunner::new().unwrap();
        // Fuse the test policy with BOTH plugins into one component (the
        // same path `TestRunner::compose` takes in prod). The fixtures carry
        // their embedded sections (embedded verbatim from the author
        // JSON), so `compose` derives each catalog's content-hash from
        // the same bytes the registry keys on.
        let composition = runner.compose(test_policy_component(), &all_plugins()).unwrap();

        // Composition-wide `EmbeddedRegistry`, keyed by each component's
        // catalog content-hash — policy first, then the plugins in the
        // same order as the fused set. Both decls and hash come straight
        // from the sealed wasm (`load_embedded`), so they match exactly
        // what `compose` routed the imports under. The `ref_key` is a
        // fixed test value; production derives it per-policy from
        // `tee_seal_key + policy_ref`.
        let mut builder = EmbeddedRegistry::builder();
        for wasm in [
            test_policy_component(),
            well_known_component(),
            extra_component(),
        ] {
            let cat = engine_compiler::load_embedded(wasm).expect("load embedded");
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
            media_store: listener.media_store(),
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
/// single-shot, so the clip fills step index 0). The frame is a REAL
/// encoded JPEG so the face-age plugin's in-sandbox decode → preprocess →
/// inference pipeline (run on the selfie round) has something to decode.
fn fake_capture() -> MediaResult {
    MediaResult {
        slot: 0,
        clip: Clip {
            frames: vec![jpeg_frame()],
        },
    }
}

/// A decodable solid mid-gray 64×64 RGB JPEG. The pixel values are
/// irrelevant to the tests — only that the frame decodes so the plugin
/// returns a usable (confidence > 0) estimate.
fn jpeg_frame() -> Vec<u8> {
    use jpeg_encoder::{ColorType, Encoder};
    const W: u16 = 64;
    const H: u16 = 64;
    let rgb = vec![128u8; W as usize * H as usize * 3];
    let mut buf = Vec::new();
    Encoder::new(&mut buf, 90)
        .encode(&rgb, W, H, ColorType::Rgb)
        .expect("encode test jpeg");
    buf
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

fn extra_dir() -> String {
    format!("{}/tests/fixtures/test-extra", env!("CARGO_MANIFEST_DIR"))
}

fn face_age_dir() -> String {
    format!("{}/../../plugins/face-age", env!("CARGO_MANIFEST_DIR"))
}

fn preprocess_dir() -> String {
    format!("{}/../../plugins/preprocess", env!("CARGO_MANIFEST_DIR"))
}

fn face_detect_dir() -> String {
    format!("{}/../../plugins/face-detect", env!("CARGO_MANIFEST_DIR"))
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
            xtask::embed_sections(
                xtask::build_componentized(&dir, &module).expect("build_componentized"),
                &dir,
            )
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
            xtask::embed_sections(
                xtask::build_componentized(&dir, &module).expect("build_componentized"),
                &dir,
            )
        })
        .as_slice()
}

/// Build the minimal `enclavid:extra` plugin (cached), componentize it,
/// and embed its `i18n.json` as a custom section.
fn extra_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = extra_dir();
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/test_extra.wasm");
            xtask::embed_sections(
                xtask::build_componentized(&dir, &module).expect("build_componentized"),
                &dir,
            )
        })
        .as_slice()
}

/// Build the `enclavid:face-age` plugin (cached) and componentize it. It
/// ships no embedded JSON, so `embed_sections` appends nothing — the
/// artifact carries only its `check` export + the `enclavid:vision/types`
/// import (the `decoded-frame` it reads crops from).
fn face_age_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = face_age_dir();
            // face-age is a member of the `plugins/` workspace, so its wasm
            // lands in the SHARED workspace target, not the crate dir.
            let module = format!(
                "{}/../../plugins/target/wasm32-unknown-unknown/release/face_age.wasm",
                env!("CARGO_MANIFEST_DIR"),
            );
            xtask::embed_sections(
                xtask::build_componentized(&dir, &module).expect("build_componentized"),
                &dir,
            )
        })
        .as_slice()
}

/// Build the `enclavid:preprocess` plugin (cached) and componentize it. It
/// OWNS the `decoded-frame` resource (exports `enclavid:vision/types`) and
/// imports the host `clip`; no embedded JSON.
fn preprocess_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = preprocess_dir();
            let module = format!(
                "{}/../../plugins/target/wasm32-unknown-unknown/release/preprocess.wasm",
                env!("CARGO_MANIFEST_DIR"),
            );
            xtask::embed_sections(
                xtask::build_componentized(&dir, &module).expect("build_componentized"),
                &dir,
            )
        })
        .as_slice()
}

/// Build the `enclavid:face-detect` plugin (cached) and componentize it. It
/// imports `enclavid:vision/types` (reads the preprocess-owned
/// `decoded-frame`) and exports `detect`; no embedded JSON. Default build =
/// the weightless placeholder (whole frame as the face).
fn face_detect_component() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = face_detect_dir();
            let module = format!(
                "{}/../../plugins/target/wasm32-unknown-unknown/release/face_detect.wasm",
                env!("CARGO_MANIFEST_DIR"),
            );
            xtask::embed_sections(
                xtask::build_componentized(&dir, &module).expect("build_componentized"),
                &dir,
            )
        })
        .as_slice()
}

// `build_componentized` + `embed_sections` moved to the shared `xtask`
// crate so this test and the `xtask push-plugins` publish tool build
// artifacts identically. Called as `xtask::build_componentized` /
// `xtask::embed_sections` above.
