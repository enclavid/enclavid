//! End-to-end: runs a test policy — composed with the `enclavid:well-known`
//! plugin — through the PURE-REDUCER engine, threading the opaque `state`
//! blob + building a per-round `event` and asserting the returned action.
//!
//! The policy is `handle(state, event) -> (state, action)`.
//! The harness owns the mailbox: each round it inspects the previous
//! round's `current_prompt`, fabricates the matching applicant input
//! (a fake photo for a media prompt, an accept/reject bool for a consent
//! prompt), and calls `run` again.
//!
//! Two flows are driven:
//!   * REJECT  — passport → selfie → consent-disclosure(false) → Rejected.
//!   * APPROVE — passport → selfie → consent-disclosure(true)  → Approved,
//!               with the seven fields the policy rendered on the consent
//!               screen — six canonical KYC fields plus the face-age estimate.
//!
//! What a round DISCLOSES is not asserted here and cannot be: the runtime no
//! longer decides it. The orchestrator derives it from the prompt it rendered
//! and the event it built, and tests it there (`applicant::shared`). What this
//! file still owns is the half that produces the screen — that the fused
//! composition renders those fields with those values.
//!
//! The policy and the plugin wasm are compiled on-demand (first test
//! invocation) rather than via a build.rs — this keeps normal engine
//! builds free of wasm tooling dependencies and nightly requirements.

use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use coprocess_channel::{receive, send};
use enclavid_media::protocol::{MAX_REQUEST_BYTES, Opened, Request, Response, Size};
use engine_compiler::Compiler;
use engine_executor::{
    Component, ComponentDecls, DEFAULT_ROUND_FUEL, DecoderFailed, EmbeddedImport, EmbeddedRegistry,
    Executor, MediaStarter, MediaStore, ModelImport, ModelStarter, PictureBounds, PluginInstance,
    PrimedComposition, RunError, RunInputs, RunResult, RunStatus, SessionChange, SessionListener,
};
use engine_types::composition::ModelLayer;
use engine_types::text::Localized;
use session_types::{
    Capture, Decision, Event, MediaResult, Prompt, SessionState as Session, VideoCapture,
};
use xtask::fixtures;

/// The test policy's props when the consumer gives none, as api writes them:
/// its record in WAVE, every field an option and none of them given.
const NO_PROPS: &[u8] = b"{:}";

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
    catalogs: Vec<([u8; 32], ComponentDecls)>,
    models: Vec<ModelImport>,
}

impl Fused {
    /// The registry its catalogs make, as the round's process builds it.
    fn registry(&self) -> Arc<EmbeddedRegistry> {
        let mut builder = EmbeddedRegistry::builder();
        for (hash, decls) in &self.catalogs {
            builder.add_component(*hash, decls.clone());
        }
        Arc::new(builder.build().expect("the texts read"))
    }
}

/// `text` in English, as the applicant reading English sees it.
fn english(text: &Localized) -> &str {
    text.translations
        .iter()
        .find(|t| t.language == "en")
        .map_or("", |t| t.text.as_str())
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
        let composition = self.compiler.compose(policy_wasm, &[], plugins)?;
        let cwasm = self.compiler.serialize_component(&composition.component)?;
        // The POSITIVE case for the supervisor's L1 admission check, asserted
        // against a real artifact where one already exists. Its own unit tests can
        // only show what is refused; writing an accepted header by hand would test
        // this tree's guess at wasmtime's format rather than wasmtime's.
        assert!(
            engine_executor::admission::is_precompiled_component(&cwasm),
            "a freshly serialized composition must pass L1 admission"
        );
        let component = self.executor.deserialize_component(&cwasm)?;
        Ok(Fused {
            component,
            embedded_imports: composition.embedded_imports,
            catalogs: composition.catalogs,
            models: composition.models,
        })
    }

    /// Build the reusable `InstancePre` once (the Linker + type-check), mirroring
    /// the production `RemoteChild::prime`. Every [`run`](Self::run) drives a
    /// fresh round against it — so a multi-round test exercises the real
    /// prime-once / run-many path.
    fn prime(
        &self,
        fused: &Fused,
        embedded: Arc<EmbeddedRegistry>,
    ) -> RunResult<PrimedComposition> {
        self.executor.prime(
            &fused.component,
            &fused.embedded_imports,
            embedded,
            &fused.models,
        )
    }

    async fn run(
        &self,
        primed: &PrimedComposition,
        session: Session,
        event: Event,
        props: &[u8],
        inputs: RunInputs,
    ) -> RunResult<(RunStatus, Session)> {
        self.executor
            .run(primed, session, event, props, inputs)
            .await
    }
}

/// In-memory stand-in for the host blob store, shared with the
/// [`PersistListener`] (which populates it from each round's event, as api
/// does) so a later `frame::from-blob-ref` rehydrate hits. Stage 3 swaps in
/// the hatch-backed store; this proves the engine seam.
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

/// The plugins the policy imports — well-known + extra + the vision trio. All
/// must be present in every composition, since the policy calls into each.
/// Built by [`xtask::fixtures`], shared with `engine-executor-child`'s
/// child-process test.
fn all_plugins() -> Vec<PluginInstance> {
    fixtures::all_plugins()
        .into_iter()
        .map(|(package, wasm)| PluginInstance {
            package: package.to_string(),
            wasm: wasm.to_vec(),
            model_layers: Vec::new(),
        })
        .collect()
}

/// For a composition with no models: a round that starts one is a defect of
/// the test.
struct NoModels;

impl ModelStarter for NoModels {
    fn start(
        &self,
        _: u32,
    ) -> Pin<Box<dyn Future<Output = RunResult<std::os::unix::net::UnixStream>> + Send + '_>> {
        Box::pin(async { Err(RunError::msg("no composition here has models")) })
    }
}

/// The models of a composition, each its graph and data file, run in the
/// coprocess binary as the execution-worker starts them: each start counted
/// per model, and each process held — killed — until the test is done with
/// this.
struct Models {
    exe: PathBuf,
    /// Each model's graph and data file, in the composition's order of its
    /// models; one with no data file is handed an empty file, as the worker
    /// hands it.
    files: Vec<(File, File)>,
    started: Vec<AtomicUsize>,
    processes: Mutex<Vec<tokio::process::Child>>,
}

impl Models {
    /// How many times each model was started.
    fn started(&self) -> Vec<usize> {
        self.started
            .iter()
            .map(|n| n.load(Ordering::SeqCst))
            .collect()
    }
}

impl ModelStarter for Models {
    fn start(
        &self,
        index: u32,
    ) -> Pin<Box<dyn Future<Output = RunResult<std::os::unix::net::UnixStream>> + Send + '_>> {
        use std::os::fd::{AsFd, OwnedFd};

        Box::pin(async move {
            let index = index as usize;
            let (graph, data) = self
                .files
                .get(index)
                .ok_or_else(|| RunError::msg("no such model"))?;
            self.started[index].fetch_add(1, Ordering::SeqCst);
            let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
            let process = engine_supervisor::spawn_coprocess(
                &self.exe,
                OwnedFd::from(theirs),
                &[graph.as_fd(), data.as_fd()],
                cfg!(target_os = "linux"),
            )?;
            self.processes.lock().unwrap().push(process);
            Ok(ours)
        })
    }
}

/// Each capture a round decodes, decoded in the media coprocess binary as the
/// execution-worker starts it: each start counted, and each process held —
/// killed — until the test is done with this.
struct Decoders {
    exe: PathBuf,
    started: AtomicUsize,
    processes: Mutex<Vec<tokio::process::Child>>,
}

impl Decoders {
    /// Decoders running `exe`.
    fn of(exe: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            exe,
            started: AtomicUsize::new(0),
            processes: Mutex::new(Vec::new()),
        })
    }

    /// Decoders of photos, as the image's decode them: the binary built
    /// without `video`, which links no libvpx.
    fn of_photos() -> Arc<Self> {
        static EXE: OnceLock<PathBuf> = OnceLock::new();
        Self::of(EXE.get_or_init(xtask::media_binary).clone())
    }

    /// How many the round started.
    fn started(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }
}

impl MediaStarter for Decoders {
    fn start(
        &self,
        _: u32,
    ) -> Pin<Box<dyn Future<Output = RunResult<std::os::unix::net::UnixStream>> + Send + '_>> {
        use std::os::fd::OwnedFd;

        Box::pin(async move {
            self.started.fetch_add(1, Ordering::SeqCst);
            let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
            let process = engine_supervisor::spawn_coprocess(
                &self.exe,
                OwnedFd::from(theirs),
                &[],
                cfg!(target_os = "linux"),
            )?;
            self.processes.lock().unwrap().push(process);
            Ok(ours)
        })
    }
}

/// A stand-in for the process decoding a capture, on a thread of the test's:
/// it reads each request and writes the next of its answers back as they are,
/// then lets go of its socket, as a process that has ended does.
struct Answering(Vec<Vec<u8>>);

impl MediaStarter for Answering {
    fn start(
        &self,
        _: u32,
    ) -> Pin<Box<dyn Future<Output = RunResult<std::os::unix::net::UnixStream>> + Send + '_>> {
        use std::io::Write;

        Box::pin(async move {
            let (ours, mut theirs) = std::os::unix::net::UnixStream::pair()?;
            let answers = self.0.clone();
            std::thread::spawn(move || {
                for answer in answers {
                    let Ok(Some(_)) = receive::<Request>(&mut theirs, MAX_REQUEST_BYTES) else {
                        return;
                    };
                    if theirs.write_all(&answer).is_err() {
                        return;
                    }
                }
            });
            Ok(ours)
        })
    }
}

/// A stand-in for a process that reads the round's request and neither
/// answers it nor lets go of its socket: one the applicant's bytes have
/// stalled, which only the bound on an ask tells from one still working.
struct Stalling;

impl MediaStarter for Stalling {
    fn start(
        &self,
        _: u32,
    ) -> Pin<Box<dyn Future<Output = RunResult<std::os::unix::net::UnixStream>> + Send + '_>> {
        Box::pin(async move {
            let (ours, mut theirs) = std::os::unix::net::UnixStream::pair()?;
            std::thread::spawn(move || {
                let _ = receive::<Request>(&mut theirs, MAX_REQUEST_BYTES);
                loop {
                    std::thread::park();
                }
            });
            Ok(ours)
        })
    }
}

/// `response` as the channel carries it.
fn framed(response: &Response) -> Vec<u8> {
    let mut bytes = Vec::new();
    send(&mut bytes, response).expect("a response encodes");
    bytes
}

/// Stands in for the orchestrator: keeps the blob store the applicant's frames
/// go into, and counts the round fires so a test can assert that a round which
/// trapped persisted nothing at all.
///
/// It records neither the round's disclosure nor its captures, because neither is
/// reported any more. The orchestrator holds both: it derives the disclosure from
/// the prompt it rendered and the event it built, and it content-addresses the
/// frames it read off `/input` before sending them (`enclavid-api`,
/// `applicant::shared` and `applicant::persister`). `capture` below mirrors that
/// second half.
#[derive(Default)]
struct PersistListener {
    /// Backs the shared [`MemMediaStore`]. Filled by [`Self::capture`] from the
    /// same event that is handed to the round, exactly as api fills it from the
    /// event it built, so a later rehydrate finds the frame.
    media: Arc<Mutex<HashMap<[u8; 32], Arc<Vec<u8>>>>>,
    /// How many times the round fired. A trapped round must not persist.
    fires: Mutex<u32>,
    /// The decision each fire carried, in order: the orchestrator commits it
    /// with that round's state.
    decisions: Mutex<Vec<Option<Decision>>>,
}

impl PersistListener {
    /// A media store sharing this listener's blob map (write via [`Self::capture`],
    /// read via `frame::from-blob-ref`).
    fn media_store(&self) -> Arc<dyn MediaStore> {
        Arc::new(MemMediaStore(self.media.clone()))
    }

    /// Every round committed no decision but the last, and the last committed
    /// `decision` — the one its status reports.
    fn finished_with(&self, decision: Decision) {
        let decisions = self.decisions.lock().unwrap();
        let (last, earlier) = decisions.split_last().expect("a round fired");
        assert_eq!(
            *last,
            Some(decision),
            "the finishing round commits its decision"
        );
        assert!(
            earlier.iter().all(Option::is_none),
            "a round that did not finish committed a decision: {earlier:?}"
        );
    }

    /// Content-address the event's captures and store them — what api does
    /// before the round, over the bytes it is about to send.
    fn capture(&self, event: &Event) {
        let Event::Media(result) = event else {
            return;
        };
        let mut store = self.media.lock().unwrap();
        for blob in result.blobs() {
            store.insert(blake3::hash(blob).into(), Arc::new(blob.to_vec()));
        }
    }
}

impl SessionListener for PersistListener {
    fn on_session_change<'a>(
        &'a self,
        change: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = RunResult<()>> + Send + 'a>> {
        let decision = change.decision;
        Box::pin(async move {
            *self.fires.lock().unwrap() += 1;
            self.decisions.lock().unwrap().push(decision);
            Ok(())
        })
    }
}

/// The fleet's own compile — catalogs, fusion, the check that nothing it
/// imports goes unserved — takes the real policy with every plugin it imports,
/// the composition every round here runs.
#[test]
fn the_fleets_compile_takes_the_real_composition() {
    Compiler::new()
        .unwrap()
        .compile_to_parts(fixtures::test_policy().to_vec(), Vec::new(), all_plugins())
        .expect("the real composition compiles");
}

#[tokio::test]
async fn passport_selfie_consent_reject_reaches_rejected() {
    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());

    let session = h.drive_to_consent(&listener).await;

    // Reject the consent screen → the policy branches to Rejected. A decline is
    // a first-class answer, not a failure.
    let (status, _session) = h
        .run(session, Event::ConsentDisclosure(false), &listener)
        .await;
    match status {
        RunStatus::Completed(Decision::Rejected) => {}
        _ => panic!("reject round expected Completed(Rejected)"),
    }
    listener.finished_with(Decision::Rejected);
}

#[tokio::test]
async fn passport_selfie_consent_accept_reaches_approved_over_the_rendered_fields() {
    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());

    let session = h.drive_to_consent(&listener).await;

    // The screen the applicant is about to answer. This is the value the
    // orchestrator seals from on an accept, so asserting it here is asserting
    // what would be disclosed — without this side deciding it.
    let Some(Prompt::ConsentDisclosure(screen)) = session.current_prompt.clone() else {
        panic!("drive_to_consent must leave a consent screen as current_prompt");
    };

    // The seven fields the policy rendered — the six canonical KYC fields plus
    // the face-age estimate.
    assert_eq!(
        screen.fields.len(),
        7,
        "the consent screen must carry all seven rendered fields",
    );
    // Values survive verbatim (the long address triggers the runtime's
    // sanitise path but is plain ASCII, so it round-trips unchanged).
    assert!(
        screen.fields.iter().any(|f| f.value == "Jane Q. Citizen"),
        "rendered fields must include the full_name value",
    );
    // The face-age estimate reached the consent screen: it is the only field
    // whose value is a bare integer (the canonical fields carry names / dashed
    // dates / alphanumerics). Proves the plugin-computed age is disclosed
    // through the consent screen, not auto-shared.
    assert!(
        screen.fields.iter().any(|f| f.value.parse::<i32>().is_ok()),
        "rendered fields must include the face-age estimate (a numeric value)",
    );
    // The keys are the policy's disclosure fields, the cases of its `key`,
    // which it hands the well-known helpers; the labels are texts — the
    // nationality's the plugin's own, which the policy took by the plugin's
    // slot.
    let keys: Vec<&str> = screen.fields.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "full-name",
            "date-of-birth",
            "nationality",
            "passport-number",
            "document-expiry",
            "address",
            "estimated-age",
        ]
    );
    assert_eq!(english(&screen.fields[0].label), "Full name");
    assert_eq!(english(&screen.fields[2].label), "Nationality");
    assert_eq!(english(&screen.fields[6].label), "Estimated age");
    assert_eq!(
        english(&screen.reason),
        "Identity verification for the test policy."
    );
    assert_eq!(english(&screen.requester), "EXTRA-PLUGIN-TAG");

    // Accept → the policy branches to Approved.
    let (status, _session) = h
        .run(session, Event::ConsentDisclosure(true), &listener)
        .await;
    match status {
        RunStatus::Completed(Decision::Approved) => {}
        _ => panic!("accept round expected Completed(Approved)"),
    }
    listener.finished_with(Decision::Approved);
}

/// The selfie round on vendors' models as they ship them: face-detect built
/// `--features blazeface` hands the frame to its slot's model `detector`,
/// whose graph is the layer `detector.onnx`, and face-age built `--features
/// mivolo` hands the face found to its slot's model `age`, whose graph and data
/// file are the layers `age.onnx` and `age.onnx.data`. The compile pairs each
/// with its files. A frame with no face ends its round on the detector alone,
/// asking for a retake; a photo of a face reaches MiVOLO, and its estimate the
/// consent screen. Neither the models, the coprocess nor the photo is in the
/// repository: `BLAZEFACE_MODEL` names BlazeFace's graph, `MIVOLO_MODEL` the
/// directory of a vendor's `mivolo.onnx` and `mivolo.onnx.data`, `FACE_PHOTO`
/// a JPEG of one face as a camera frames a selfie, and
/// `ENCLAVID_INFERENCE_BIN` the coprocess binary built with ONNX Runtime
/// linked in:
///   cargo test -p engine-executor --test happy_path -- --ignored vendor
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BLAZEFACE_MODEL, MIVOLO_MODEL, FACE_PHOTO and ENCLAVID_INFERENCE_BIN"]
async fn the_selfie_age_is_read_by_vendor_models() {
    let path = |var: &str| {
        PathBuf::from(std::env::var_os(var).unwrap_or_else(|| panic!("{var} is not set")))
    };
    let detector = path("BLAZEFACE_MODEL");
    let dir = path("MIVOLO_MODEL");
    let (graph, data) = (dir.join("mivolo.onnx"), dir.join("mivolo.onnx.data"));
    let photo = std::fs::read(path("FACE_PHOTO")).expect("the photo is there");
    let exe = path("ENCLAVID_INFERENCE_BIN");
    let layer = |name: &str, path: &PathBuf, sha: u8| ModelLayer {
        name: name.into(),
        sha256: [sha; 32],
        length: std::fs::metadata(path)
            .expect("the model file is there")
            .len(),
    };
    let mut plugins = all_plugins();
    for plugin in &mut plugins {
        if plugin.package == fixtures::FACE_DETECT_PACKAGE {
            plugin.wasm = fixtures::face_detect_blazeface().to_vec();
            plugin.model_layers = vec![layer("detector.onnx", &detector, 1)];
        } else if plugin.package == fixtures::FACE_AGE_PACKAGE {
            plugin.wasm = fixtures::face_age_mivolo().to_vec();
            plugin.model_layers = vec![
                layer("age.onnx", &graph, 2),
                layer("age.onnx.data", &data, 3),
            ];
        }
    }
    let models = Arc::new(Models {
        exe,
        files: vec![
            (
                File::open(&detector).unwrap(),
                File::open("/dev/null").unwrap(),
            ),
            (File::open(&graph).unwrap(), File::open(&data).unwrap()),
        ],
        started: vec![AtomicUsize::new(0), AtomicUsize::new(0)],
        processes: Mutex::new(Vec::new()),
    });
    let h = Harness::with(&plugins, models.clone());
    assert_eq!(
        h.models,
        vec![
            ModelImport {
                instance_name: "enclavid-ext:face-detect/models@0.1.0".into(),
                function: "detector".into(),
                resource: "detector-model".into(),
                graph: 0,
                data: None,
            },
            ModelImport {
                instance_name: "enclavid-ext:face-age/models@0.1.0".into(),
                function: "age".into(),
                resource: "age-model".into(),
                graph: 1,
                data: Some(2),
            },
        ]
    );

    // A gray frame: no face, so the round asks for a retake and never starts
    // MiVOLO.
    let listener = Arc::new(PersistListener::default());
    let session = h.drive_to_selfie(&listener).await;
    let (status, _) = h
        .run(session, Event::Media(fake_capture()), &listener)
        .await;
    assert!(
        matches!(status, RunStatus::Completed(Decision::RejectedRetryable)),
        "no face, a retake"
    );
    assert_eq!(models.started(), [1, 0], "the detector alone");

    // A face: MiVOLO reads its age, and the estimate reaches the screen.
    let listener = Arc::new(PersistListener::default());
    let session = h.drive_to_selfie(&listener).await;
    let (status, _) = h
        .run(session, Event::Media(capture_of(photo)), &listener)
        .await;
    let RunStatus::AwaitingInput(Prompt::ConsentDisclosure(screen)) = status else {
        panic!("a face found and read leads to the consent screen");
    };
    let age: i32 = screen
        .fields
        .iter()
        .find(|f| f.key == "estimated-age")
        .expect("the estimate reaches the consent screen")
        .value
        .parse()
        .expect("the estimate is a whole number of years");
    eprintln!("estimated age: {age}");
    assert!((0..=122).contains(&age), "MiVOLO's range holds {age}");
    assert_eq!(models.started(), [2, 1], "each model once a round");
}

/// The video the media coprocess's own test decodes: 12 frames of 160×120 at
/// 15 a second, a keyframe every 5, a dark luma gradient with a bright 16×16
/// square that moves 8 px right each frame.
const SQUARE: &[u8] = include_bytes!("../../engine-executor-media/tests/fixtures/square.webm");

/// The test policy's state tag for a video it decoded, and for one that did
/// not decode.
const VIDEO_DECODED: u8 = 4;
const VIDEO_UNDECODED: u8 = 5;

/// A frame as the test policy's probe wrote it into its state.
#[derive(Debug)]
struct Probed {
    index: u32,
    timestamp_ms: u32,
    keyframe: bool,
    width: u32,
    height: u32,
    rgb: Vec<u8>,
}

/// The frames the probe wrote after [`VIDEO_DECODED`], and every pixel of the
/// first frame as it read it again after the last.
fn probed(state: &[u8]) -> (Vec<Probed>, Vec<u8>) {
    let (&tag, mut rest) = state.split_first().expect("a state");
    assert_eq!(tag, VIDEO_DECODED, "the video decoded");
    let u32_at = |rest: &mut &[u8]| {
        let (n, tail) = rest.split_at(4);
        *rest = tail;
        u32::from_be_bytes(n.try_into().unwrap())
    };
    let count = u32_at(&mut rest);
    let mut frames = Vec::new();
    for _ in 0..count {
        let index = u32_at(&mut rest);
        let timestamp_ms = u32_at(&mut rest);
        let (&keyframe, tail) = rest.split_first().unwrap();
        rest = tail;
        let (width, height) = (u32_at(&mut rest), u32_at(&mut rest));
        let (rgb, tail) = rest.split_at((width * height * 3) as usize);
        rest = tail;
        frames.push(Probed {
            index,
            timestamp_ms,
            keyframe: keyframe == 1,
            width,
            height,
            rgb: rgb.to_vec(),
        });
    }
    (frames, rest.to_vec())
}

/// Where across a quarter-size frame the square is: the mean column of the
/// pixels brighter than the background can be, in the rows it crosses.
fn square_column(frame: &Probed) -> f64 {
    let (mut weight, mut moment) = (0.0, 0.0);
    for (i, pixel) in frame.rgb.as_chunks::<3>().0.iter().enumerate() {
        if (13..17).contains(&(i / frame.width as usize)) && pixel[0] > 160 {
            weight += 1.0;
            moment += (i % frame.width as usize) as f64;
        }
    }
    moment / weight
}

/// The video `webm`, recorded at a one-step media prompt.
fn video(webm: &[u8]) -> Event {
    Event::Media(MediaResult {
        captures: vec![Capture::Video(VideoCapture {
            video: webm.to_vec(),
            guides: Vec::new(),
        })],
    })
}

/// Decoders of videos too: the media coprocess binary built with libvpx
/// linked in, which `ENCLAVID_MEDIA_BIN` names.
fn decoders_of_videos() -> Arc<Decoders> {
    let exe = std::env::var_os("ENCLAVID_MEDIA_BIN").expect("ENCLAVID_MEDIA_BIN is not set");
    Decoders::of(exe.into())
}

/// A video in the passport's place reaches the policy as a `video` it lists
/// the frames of and decodes through the host, in a process of the round's
/// own: each frame in order, at its time, its keyframes marked, and each image
/// read at a quarter of its size — the square seen moving right; the first
/// frame read again after the last is itself. Bytes that are not a video have
/// no frames, and the round goes on. Needs the coprocess:
///   VPX_INCLUDE=… VPX_LIB=… cargo build -p engine-executor-media
///   ENCLAVID_MEDIA_BIN=target/debug/engine-executor-media \
///     cargo test -p engine-executor --test happy_path -- --ignored video
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ENCLAVID_MEDIA_BIN"]
async fn a_video_is_decoded_in_a_process_of_its_own() {
    let decoders = decoders_of_videos();
    let h = Harness::new().decoding(decoders.clone());
    let listener = Arc::new(PersistListener::default());

    let (_, session) = h.run(Session::default(), Event::Start, &listener).await;
    let (status, session) = h.run(session, video(SQUARE), &listener).await;
    assert!(matches!(status, RunStatus::Completed(Decision::Review)));
    let (frames, again) = probed(&session.state);
    assert_eq!(frames.len(), 12);
    // The first frame whole, read again out of order: 160 × 120, each of its
    // quarter-size pixels the one at the middle of the four by four it
    // covers, (4i + 2, 4j + 2).
    assert_eq!(again.len(), 160 * 120 * 3);
    for (at, quarter) in frames[0].rgb.as_chunks::<3>().0.iter().enumerate() {
        let (i, j) = (at % 40, at / 40);
        let whole = ((4 * j + 2) * 160 + 4 * i + 2) * 3;
        assert_eq!(&again[whole..whole + 3], quarter, "pixel ({i}, {j})");
    }
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(frame.index, i as u32);
        // A frame each 66.7 ms, as the WebM's millisecond ticks round it.
        assert!(
            frame.timestamp_ms.abs_diff(i as u32 * 1000 / 15) <= 1,
            "{frame:?}"
        );
        assert_eq!(frame.keyframe, i % 5 == 0, "frame {i}");
        assert_eq!((frame.width, frame.height), (40, 30));
        // The square's middle at 18 + 8i px is at (18 + 8i) / 4 a quarter
        // the size, give or take a column for the codec and the sampling.
        let column = square_column(frame);
        let expected = (18 + 8 * i) as f64 / 4.0;
        assert!(
            (column - expected).abs() <= 1.0,
            "frame {i}: column {column}"
        );
    }
    assert_eq!(decoders.started(), 1, "one process for the video");

    let (_, session) = h.run(Session::default(), Event::Start, &listener).await;
    let (status, session) = h.run(session, video(b"not a webm"), &listener).await;
    assert!(matches!(status, RunStatus::Completed(Decision::Review)));
    assert_eq!(session.state, [VIDEO_UNDECODED]);
}

/// A region larger than a picture can be traps the round: the policy's own
/// doing, whatever the video. Needs the coprocess, as the test above.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ENCLAVID_MEDIA_BIN"]
async fn a_region_past_the_bound_traps_the_round() {
    let props = b"{region-past-the-bound: some(true)}";
    let h = Harness::new().decoding(decoders_of_videos());
    let listener = Arc::new(PersistListener::default());
    let (_, session) = h
        .round(Session::default(), Event::Start, props, &listener)
        .await
        .expect("the start round");
    let fires = *listener.fires.lock().unwrap();
    assert!(
        h.round(session, video(SQUARE), props, &listener)
            .await
            .is_err()
    );
    assert_eq!(*listener.fires.lock().unwrap(), fires, "nothing persisted");
}

/// Where the platform decodes no video, a video has no frames: the policy
/// sees a video that does not decode, and the round goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_build_without_video_lists_no_frames() {
    let decoders = Decoders::of_photos();
    let h = Harness::new().decoding(decoders.clone());
    let listener = Arc::new(PersistListener::default());
    let (_, session) = h.run(Session::default(), Event::Start, &listener).await;
    let (status, session) = h.run(session, video(SQUARE), &listener).await;
    assert!(matches!(status, RunStatus::Completed(Decision::Review)));
    assert_eq!(session.state, [VIDEO_UNDECODED]);
    assert_eq!(decoders.started(), 1);
}

/// A WebM whose one block is too short to hold its own header, which
/// webm-iterable panics on: the process decoding it ends before it answers.
const CUT_BLOCK: &[u8] = &[
    // The EBML header: a WebM.
    0x1a, 0x45, 0xdf, 0xa3, 0x87, 0x42, 0x82, 0x84, b'w', b'e', b'b', b'm',
    // A segment, of a size it does not say.
    0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // A cluster of 6 bytes: its time, 0, and a block of 1 byte, its track
    // number alone.
    0x1f, 0x43, 0xb6, 0x75, 0x86, 0xe7, 0x81, 0x00, 0xa3, 0x81, 0x81,
];

/// A video that ends the process decoding it has no frames, as bytes that are
/// not a video have, and the round goes on. Needs the coprocess, as the tests
/// above.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ENCLAVID_MEDIA_BIN"]
async fn a_video_that_ends_its_decoder_has_no_frames() {
    let decoders = decoders_of_videos();
    let h = Harness::new().decoding(decoders.clone());
    let listener = Arc::new(PersistListener::default());
    let (_, session) = h.run(Session::default(), Event::Start, &listener).await;
    let (status, session) = h.run(session, video(CUT_BLOCK), &listener).await;
    assert!(matches!(status, RunStatus::Completed(Decision::Review)));
    assert_eq!(session.state, [VIDEO_UNDECODED]);
    let mut process = decoders
        .processes
        .lock()
        .unwrap()
        .pop()
        .expect("a process for the video");
    let ended = process.wait().await.unwrap();
    assert!(!ended.success(), "the video ended it: {ended}");
}

/// A process decoding a capture that ends — the applicant's bytes can end it
/// — leaves its capture undecoded, and the round goes on: one gone before it
/// answers the open gives the selfie no image, one gone at the first region
/// gives the image no pixels. Either way the policy asks for a retake.
#[tokio::test(flavor = "multi_thread")]
async fn a_decoder_that_ends_leaves_its_capture_undecoded() {
    let opened = framed(&Response::Opened(Opened::Photo(Size {
        width: 64,
        height: 64,
    })));
    let gone_before_the_open: Arc<dyn MediaStarter> = Decoders::of("true".into());
    let gone_at_a_region: Arc<dyn MediaStarter> = Arc::new(Answering(vec![opened]));
    for media in [gone_before_the_open, gone_at_a_region] {
        let h = Harness::new().decoding(media);
        let listener = Arc::new(PersistListener::default());
        let session = h.drive_to_selfie(&listener).await;
        let (status, _) = h
            .run(session, Event::Media(fake_capture()), &listener)
            .await;
        assert!(matches!(
            status,
            RunStatus::Completed(Decision::RejectedRetryable)
        ));
    }
}

/// A process decoding a capture that stalls — neither answering nor ending —
/// leaves its capture undecoded once the ask is past its bound, so the round
/// goes on instead of waiting out its own deadline. The clock is the test's,
/// so no test waits that bound out.
#[tokio::test(start_paused = true)]
async fn a_decoder_that_stalls_leaves_its_capture_undecoded() {
    let h = Harness::new().decoding(Arc::new(Stalling));
    let listener = Arc::new(PersistListener::default());
    let session = h.drive_to_selfie(&listener).await;
    let (status, _) = h
        .run(session, Event::Media(fake_capture()), &listener)
        .await;
    assert!(matches!(
        status,
        RunStatus::Completed(Decision::RejectedRetryable)
    ));
}

/// A process decoding a capture that answers what no decoder answers — bytes
/// that are no response, a response to another request — fails the round as
/// the platform's own failure, not the policy's: [`DecoderFailed`]. Nothing
/// is persisted.
#[tokio::test(flavor = "multi_thread")]
async fn a_decoder_answering_out_of_turn_fails_the_round() {
    let no_response = vec![0, 0, 0, 1, 0xff];
    let pixels_to_the_open = framed(&Response::Pixels(Vec::new()));
    for answer in [no_response, pixels_to_the_open] {
        let h = Harness::new().decoding(Arc::new(Answering(vec![answer])));
        let listener = Arc::new(PersistListener::default());
        let session = h.drive_to_selfie(&listener).await;
        let fires = *listener.fires.lock().unwrap();
        let failure = h
            .round(session, Event::Media(fake_capture()), NO_PROPS, &listener)
            .await
            .err()
            .expect("the round fails");
        assert!(
            failure.chain().any(|cause| cause.is::<DecoderFailed>()),
            "{failure:#}"
        );
        assert_eq!(*listener.fires.lock().unwrap(), fires, "nothing persisted");
    }
}

#[tokio::test]
async fn media_rounds_keep_state_minimal() {
    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());

    // genesis → render media(passport)
    let (_s0, after_genesis) = h.run(Session::default(), Event::Start, &listener).await;
    let baseline = after_genesis.state.len();

    // passport photo → render media(selfie)
    let (_s1, after_passport) = h
        .run(after_genesis, Event::Media(fake_capture()), &listener)
        .await;
    let after_passport_len = after_passport.state.len();

    // selfie photo → render consent-disclosure
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
    assert!(
        baseline <= 8,
        "policy step state should be tiny, got {baseline}"
    );
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
    let listener = Arc::new(PersistListener::default());
    // An empty store, NOT the listener's map — so captured blobs never land in
    // what `from-blob-ref` reads, forcing a miss on the selfie round.
    let empty_store: Arc<dyn MediaStore> = Arc::new(MemMediaStore::default());
    let inputs = || RunInputs {
        listener: listener.clone(),
        media_store: empty_store.clone(),
        models: Arc::new(NoModels),
        media: Decoders::of_photos(),
        fuel: DEFAULT_ROUND_FUEL,
        picture_bounds: PictureBounds::DEFAULT,
    };
    let round = |session, event: Event| {
        listener.capture(&event);
        h.runner.run(&h.primed, session, event, NO_PROPS, inputs())
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
        let listener = Arc::new(PersistListener::default());
        let loads = Arc::new(AtomicUsize::new(0));
        // The counting store shares the listener's captured-blob map, so the
        // passport reload finds the frame the passport round stored.
        let store: Arc<dyn MediaStore> = Arc::new(CountingMediaStore {
            map: listener.media.clone(),
            loads: loads.clone(),
        });
        let props: &[u8] = if read_bytes {
            NO_PROPS
        } else {
            b"{skip-passport-read: some(true)}"
        };
        let inputs = || RunInputs {
            listener: listener.clone(),
            media_store: store.clone(),
            models: Arc::new(NoModels),
            media: Decoders::of_photos(),
            fuel: DEFAULT_ROUND_FUEL,
            picture_bounds: PictureBounds::DEFAULT,
        };
        let round = |session, event: Event| {
            listener.capture(&event);
            h.runner.run(&h.primed, session, event, props, inputs())
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
async fn a_passport_without_a_photo_is_retryable() {
    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());

    // genesis → render media(passport)
    let (status, session) = h.run(Session::default(), Event::Start, &listener).await;
    assert_media(&status, "genesis (passport)");

    // Feed a capture with NO photo. The policy finds no photo among the
    // captures and returns a retryable rejection.
    let empty = MediaResult { captures: vec![] };
    let (status, _session) = h.run(session, Event::Media(empty), &listener).await;
    match status {
        RunStatus::Completed(Decision::RejectedRetryable) => {}
        _ => panic!("a passport without a photo must yield Completed(RejectedRetryable)"),
    }
}

#[tokio::test]
async fn an_empty_selfie_is_retryable_via_plugin() {
    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());

    // genesis → passport prompt
    let (status, session) = h.run(Session::default(), Event::Start, &listener).await;
    assert_media(&status, "genesis (passport)");
    // passport photo → selfie prompt
    let (status, session) = h
        .run(session, Event::Media(fake_capture()), &listener)
        .await;
    assert_media(&status, "passport → selfie");

    // Feed a selfie photo of ZERO bytes. On the selfie round the policy hands
    // it to the FUSED vision plugin, which cannot decode it; the policy maps
    // that to a retryable rejection. Proves the plugin was invoked across the
    // fused boundary during `handle` and actually read the blob resource —
    // the full capture-consumer path, not just the policy-side read.
    let (status, _session) = h
        .run(session, Event::Media(capture_of(Vec::new())), &listener)
        .await;
    match status {
        RunStatus::Completed(Decision::RejectedRetryable) => {}
        _ => {
            panic!("an empty selfie must yield Completed(RejectedRetryable) via the vision plugin")
        }
    }
}

/// Props that do not read as the record the policy declares fail the round
/// before the policy runs: nothing it could do with half its props is reached,
/// and nothing is persisted. api never sends such props — it read them against
/// the same record when it prepared the session — but a round's peer is any
/// attested guest, and none the policy has.
#[tokio::test]
async fn props_that_do_not_read_as_the_policys_record_fail_the_round() {
    let h = Harness::new();
    for props in [
        "{state-bloat: some(-1)}",
        r#"{state-bloat: some("big")}"#,
        "{stateBloat: some(1)}",
        r#"{"state-bloat": 1}"#,
        "",
    ] {
        let listener = Arc::new(PersistListener::default());
        let result = h
            .runner
            .run(
                &h.primed,
                Session::default(),
                Event::Start,
                props.as_bytes(),
                h.inputs(&listener),
            )
            .await;
        assert!(result.is_err(), "{props} ran");
        assert_eq!(*listener.fires.lock().unwrap(), 0, "{props} persisted");
    }
}

#[tokio::test]
async fn oversized_state_traps() {
    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());

    // Drive genesis with props that make the policy return a blob one byte
    // over the cap — the runtime must trap the round rather than seal an
    // over-cap (clip-smuggling) state.
    let over = engine_executor::limits::POLICY_MAX_STATE_BYTES + 1;
    let props = format!("{{state-bloat: some({over})}}");

    let result = h
        .runner
        .run(
            &h.primed,
            Session::default(),
            Event::Start,
            props.as_bytes(),
            h.inputs(&listener),
        )
        .await;

    assert!(
        result.is_err(),
        "a state blob over POLICY_MAX_STATE_BYTES must trap the round",
    );

    // And it trapped BEFORE the listener fired, so nothing about the round was
    // persisted — the cap is a backstop, not a filter applied after the fact.
    assert_eq!(
        *listener.fires.lock().unwrap(),
        0,
        "a trapped over-cap round must persist nothing",
    );
}

/// The round's WASI clocks and randomness as the policy reads them (the
/// `wasi-probe` prop): the wall clock is the second the round started; the
/// monotonic clock starts there, and a deadline asked about — checked or waited
/// on — moves it there at once and is ready; the random bytes are fresh, so the
/// same round run again draws others.
#[tokio::test]
async fn a_round_reads_its_own_time_and_fresh_randomness() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());
    let genesis = || {
        h.runner.run(
            &h.primed,
            Session::default(),
            Event::Start,
            b"{wasi-probe: some(true)}",
            h.inputs(&listener),
        )
    };
    let now = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };

    let started = now();
    let (_, first) = genesis().await.expect("the round runs");
    let ended = now();
    let (_, again) = genesis().await.expect("the round runs");

    let read = |at: usize| u64::from_be_bytes(first.state[at..at + 8].try_into().unwrap());
    let (wall, before, after) = (read(0), read(8), read(16));
    assert!(
        (started..=ended).contains(&wall),
        "{wall} outside {started}..={ended}"
    );
    assert_eq!(before, wall * 1_000_000_000);
    assert_eq!(
        after,
        before + 1 + 1_000_000_000,
        "asking moves the clock to the deadline, and so does a wait, at once"
    );
    assert_eq!(
        first.state[24..26],
        [1, 1],
        "a deadline asked about is ready"
    );

    let random = |session: &Session| session.state[26..].to_vec();
    assert_eq!(random(&first).len(), 16);
    assert_ne!(random(&first), random(&again));
}

/// STATIC consumption: fuse the policy and every plugin into one artifact
/// before the session, as a consumer may with plain `wac` — a fusion that
/// knows nothing of the slots — then feed it back with NO runtime plugins.
/// The engine finds each slot among the artifact's imports and its catalog
/// nested inside, and resolves both the plugins' texts (each from its own
/// catalog) and the policy's disclosure fields through it.
#[tokio::test]
async fn static_fused_artifact_resolves_strictly() {
    let runner = TestRunner::new().unwrap();
    let fused = runner
        .fuse(fixtures::test_policy(), &all_plugins())
        .unwrap();

    // The slots survive the fusion as distinct imports, one per slot:
    // policy + well-known + extra = 3 — the policy's import of well-known's
    // texts and well-known's own made one. The vision plugins have no texts,
    // so they import none, and icons are the host's own.
    let imports = engine_compiler::top_level_imports(&fused).unwrap();
    let mut slots: Vec<&str> = imports
        .iter()
        .map(String::as_str)
        .filter(|n| n.starts_with("enclavid-ext:") && n.contains("/i18n@"))
        .collect();
    slots.sort_unstable();
    assert_eq!(
        slots,
        [
            "enclavid-ext:extra/i18n@0.1.0",
            "enclavid-ext:policy/i18n@0.1.0",
            "enclavid-ext:well-known/i18n@0.1.0",
        ],
    );

    // Consume with an empty plugin list — the static path.
    let composition = runner.compose(&fused, &[]).unwrap();
    assert_eq!(
        composition.embedded_imports.len(),
        3,
        "each slot found among the artifact's imports",
    );
    let embedded = composition.registry();
    let listener = Arc::new(PersistListener::default());

    // start → media(passport) → media(selfie) → consent-disclosure.
    // Each media prompt is the plugin's own texts; the consent screen
    // resolves DF (merged) — all through the static artifact with no
    // runtime fusion.
    let primed = runner
        .prime(&composition, embedded.clone())
        .expect("prime static composition");
    let inputs = || RunInputs {
        listener: listener.clone(),
        media_store: listener.media_store(),
        models: Arc::new(NoModels),
        media: Decoders::of_photos(),
        fuel: DEFAULT_ROUND_FUEL,
        picture_bounds: PictureBounds::DEFAULT,
    };
    let round = |session, event: Event| {
        listener.capture(&event);
        runner.run(&primed, session, event, NO_PROPS, inputs())
    };
    let (status, session) = round(Session::default(), Event::Start)
        .await
        .expect("static round 1");
    assert_media(&status, "static: round 1 (passport)");
    let (status, session) = round(session, Event::Media(fake_capture()))
        .await
        .expect("static round 2");
    assert_media(&status, "static: round 2 (selfie)");
    let (status, _session) = round(session, Event::Media(fake_capture()))
        .await
        .expect("static round 3");
    match &status {
        RunStatus::AwaitingInput(Prompt::ConsentDisclosure(_)) => {}
        _ => panic!("static: round 3 expected AwaitingInput(ConsentDisclosure)"),
    }
}

/// Whether any catalog of `registry` holds `text` as a text.
fn registered(registry: &EmbeddedRegistry, text: &str) -> bool {
    registry
        .localized
        .declared()
        .any(|rows| rows.iter().any(|t| t.text == text))
}

/// The definitive runtime proof of STRICT per-component isolation.
///
/// The test-policy and well-known BOTH have a text `passport-title`, each
/// its own. well-known's passport capture spec is
/// `localized(passport-title)` through well-known's OWN slot, so it MUST
/// be well-known's text ("Your passport"). If resolution were first-match
/// (the failure mode were the slots to collapse into one), it would pick
/// the POLICY's colliding text instead (policy is composed first). So this
/// asserts the plugin never sees the policy's text.
#[tokio::test]
async fn strict_routing_isolates_colliding_i18n_key() {
    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());

    // Round 1: start → render media(passport). The spec's label is the
    // text well-known minted through its own slot.
    let (status, _session) = h.run(Session::default(), Event::Start, &listener).await;
    let spec = match status {
        RunStatus::AwaitingInput(Prompt::Media(spec)) => spec,
        _ => panic!("round 1 expected AwaitingInput(Media)"),
    };

    // The engine resolved `spec.label` at the action boundary; the domain
    // carries the text whole, no registry lookup needed.
    assert_eq!(
        english(&spec.label),
        "Your passport",
        "well-known's passport spec must be its OWN passport-title \
         (strict isolation) — got the policy's colliding text, which \
         means the slots collapsed to first-match",
    );

    // Guard against a vacuous test: the collision must be REAL — the
    // policy has a DIFFERENT passport-title that first-match (policy
    // composed first) would have leaked here.
    assert!(
        registered(
            &h.embedded,
            "POLICY-OWNED passport-title (must NOT leak into the plugin)"
        ),
        "the policy's colliding passport-title must be registered, else \
         the isolation assertion above is vacuous",
    );
}

/// A capture step's icon is the host's own: well-known calls
/// `icons::passport()` of `enclavid:host-icons/icons`, the host mints its
/// ref, and the prompt carries the name the frontend draws.
#[tokio::test]
async fn a_capture_step_carries_the_icon_it_named() {
    let h = Harness::new();
    let listener = Arc::new(PersistListener::default());

    let (status, _session) = h.run(Session::default(), Event::Start, &listener).await;
    let RunStatus::AwaitingInput(Prompt::Media(spec)) = status else {
        panic!("round 1 expected AwaitingInput(Media)");
    };
    assert_eq!(spec.captures[0].icon.as_deref(), Some("passport"));
}

/// HYBRID composition: a pre-fused core (policy + well-known baked) plus a
/// runtime plugin (extra) linked on top. The policy imports `extra/tag`,
/// which the core leaves unsatisfied; the runtime fusion wires it, and
/// every slot — the core's and extra's — comes through. The consent
/// requester (`tag::get()` → `extra-tag`) must be the RUNTIME extra
/// plugin's OWN text — proving each slot is served from its own catalog
/// however the composition was put together, not first-match (which would
/// leak the policy's colliding `extra-tag`).
#[tokio::test]
async fn hybrid_core_plus_runtime_plugin_resolves_strictly() {
    let runner = TestRunner::new().unwrap();

    // CORE: policy + well-known + vision + face-age baked. The policy still
    // imports extra/tag (unsatisfied — a runtime import of the core).
    let baked = vec![
        PluginInstance {
            package: fixtures::WELL_KNOWN_PACKAGE.to_string(),
            wasm: fixtures::well_known().to_vec(),
            model_layers: Vec::new(),
        },
        PluginInstance {
            package: fixtures::VISION_PACKAGE.to_string(),
            wasm: fixtures::vision().to_vec(),
            model_layers: Vec::new(),
        },
        PluginInstance {
            package: fixtures::FACE_DETECT_PACKAGE.to_string(),
            wasm: fixtures::face_detect().to_vec(),
            model_layers: Vec::new(),
        },
        PluginInstance {
            package: fixtures::FACE_AGE_PACKAGE.to_string(),
            wasm: fixtures::face_age().to_vec(),
            model_layers: Vec::new(),
        },
    ];
    let core = runner.fuse(fixtures::test_policy(), &baked).unwrap();

    // HYBRID: link extra at runtime over the pre-fused core.
    let runtime = vec![PluginInstance {
        package: fixtures::EXTRA_PACKAGE.to_string(),
        wasm: fixtures::extra().to_vec(),
        model_layers: Vec::new(),
    }];
    let composition = runner.compose(&core, &runtime).unwrap();
    assert_eq!(composition.embedded_imports.len(), 3);

    // Registry: policy + well-known from the core's nested catalogs, plus
    // the runtime extra's — as the compile found them.
    let embedded = composition.registry();
    let listener = Arc::new(PersistListener::default());

    let primed = runner
        .prime(&composition, embedded.clone())
        .expect("prime hybrid composition");
    let inputs = || RunInputs {
        listener: listener.clone(),
        media_store: listener.media_store(),
        models: Arc::new(NoModels),
        media: Decoders::of_photos(),
        fuel: DEFAULT_ROUND_FUEL,
        picture_bounds: PictureBounds::DEFAULT,
    };
    // start → media(passport) → media(selfie) → consent-disclosure.
    let round = |session, event: Event| {
        listener.capture(&event);
        runner.run(&primed, session, event, NO_PROPS, inputs())
    };
    let (status, session) = round(Session::default(), Event::Start)
        .await
        .expect("hybrid round 1");
    assert_media(&status, "hybrid: round 1 (passport)");
    let (status, session) = round(session, Event::Media(fake_capture()))
        .await
        .expect("hybrid round 2");
    assert_media(&status, "hybrid: round 2 (selfie)");
    let (status, _session) = round(session, Event::Media(fake_capture()))
        .await
        .expect("hybrid round 3");
    let disclosure = match status {
        RunStatus::AwaitingInput(Prompt::ConsentDisclosure(d)) => d,
        _ => panic!("hybrid round 3 expected AwaitingInput(ConsentDisclosure)"),
    };

    // The requester came from the RUNTIME extra plugin (`tag::get()`);
    // the engine resolved it at the boundary into `disclosure.requester`.
    assert_eq!(
        english(&disclosure.requester),
        "EXTRA-PLUGIN-TAG",
        "the runtime extra plugin's extra-tag must be its OWN text in a \
         hybrid composition — got the policy's colliding text",
    );

    // Collision is real: the policy has a different extra-tag.
    assert!(
        registered(
            &embedded,
            "POLICY-OWNED extra-tag (must NOT leak into the extra plugin)"
        ),
        "the policy's colliding extra-tag must be registered, else the \
         isolation assertion above is vacuous",
    );
}

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

struct Harness {
    runner: TestRunner,
    /// The fused policy+well-known composition, primed ONCE (Linker +
    /// `InstancePre`) and driven through every reducer round — the prime-once /
    /// run-many path, same as production.
    primed: PrimedComposition,
    /// Kept for assertions that reach into the registry directly (declared
    /// translations, collision checks).
    embedded: Arc<EmbeddedRegistry>,
    /// The composition's models, as the compile paired them with its model
    /// files.
    models: Vec<ModelImport>,
    /// What starts the processes every round of it runs its models in.
    starter: Arc<dyn ModelStarter>,
    /// What starts the processes every round of it decodes its videos in.
    media: Arc<dyn MediaStarter>,
}

impl Harness {
    fn new() -> Self {
        Self::with(&all_plugins(), Arc::new(NoModels))
    }

    /// The test policy with `plugins`, its rounds running their models in the
    /// processes `starter` starts.
    fn with(plugins: &[PluginInstance], starter: Arc<dyn ModelStarter>) -> Self {
        let runner = TestRunner::new().unwrap();
        // Fuse the test policy with every plugin into one component (the
        // same path `TestRunner::compose` takes in prod). The fixtures carry
        // their catalogs, embedded as `enclavid {policy,plugin} embed`
        // embeds them, so each slot is named after the same bytes the
        // registry keys on.
        let composition = runner.compose(fixtures::test_policy(), plugins).unwrap();

        // Composition-wide `EmbeddedRegistry`, keyed by each catalog's
        // content-hash, from the catalogs the compile found — what the
        // round's process builds it from.
        let embedded = composition.registry();

        let primed = runner
            .prime(&composition, embedded.clone())
            .expect("prime composition");

        Self {
            runner,
            primed,
            embedded,
            models: composition.models,
            starter,
            media: Decoders::of_photos(),
        }
    }

    /// This, its rounds decoding their videos in the processes `media`
    /// starts.
    fn decoding(self, media: Arc<dyn MediaStarter>) -> Self {
        Self { media, ..self }
    }

    fn inputs(&self, listener: &Arc<PersistListener>) -> RunInputs {
        RunInputs {
            listener: listener.clone(),
            media_store: listener.media_store(),
            models: self.starter.clone(),
            media: self.media.clone(),
            fuel: DEFAULT_ROUND_FUEL,
            picture_bounds: PictureBounds::DEFAULT,
        }
    }

    /// One reducer round.
    async fn run(
        &self,
        session: Session,
        event: Event,
        listener: &Arc<PersistListener>,
    ) -> (RunStatus, Session) {
        self.round(session, event, NO_PROPS, listener)
            .await
            .expect("reducer round")
    }

    /// One reducer round, of a session created with `props`.
    async fn round(
        &self,
        session: Session,
        event: Event,
        props: &[u8],
        listener: &Arc<PersistListener>,
    ) -> RunResult<(RunStatus, Session)> {
        // Store the frames BEFORE the round, over the bytes about to be sent —
        // the orchestrator's order, and the reason it needs nothing back.
        listener.capture(&event);
        self.runner
            .run(&self.primed, session, event, props, self.inputs(listener))
            .await
    }

    /// Drive start → passport, leaving the session sitting on the selfie
    /// prompt.
    async fn drive_to_selfie(&self, listener: &Arc<PersistListener>) -> Session {
        // Round 1: start → render media(passport).
        let (status, session) = self.run(Session::default(), Event::Start, listener).await;
        assert_media(&status, "round 1 (passport)");

        // Round 2: media(passport) → render media(selfie).
        let (status, session) = self
            .run(session, Event::Media(fake_capture()), listener)
            .await;
        assert_media(&status, "round 2 (selfie)");
        session
    }

    /// Drive the common prefix: start → passport → selfie, leaving the
    /// session sitting on the consent-disclosure prompt.
    async fn drive_to_consent(&self, listener: &Arc<PersistListener>) -> Session {
        let session = self.drive_to_selfie(listener).await;

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
/// one photo step). The photo is a REAL encoded JPEG so the in-sandbox
/// decode → detect → estimate pipeline (run on the selfie round) has
/// something to decode.
fn fake_capture() -> MediaResult {
    capture_of(jpeg_frame())
}

/// A single-step capture of the photo `jpeg`.
fn capture_of(jpeg: Vec<u8>) -> MediaResult {
    MediaResult {
        captures: vec![Capture::Photo(jpeg)],
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
