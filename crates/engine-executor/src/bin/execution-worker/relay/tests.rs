//! A composition's models, run by real children of this worker that api drives
//! over the leg, each model in a real process of its own: the first round's
//! child starts its models, the relay fills their files from api's callbacks
//! and starts their processes on them; the next round of the composition
//! starts them again on the same files, and api is not asked for one again.
//!
//! The model's process is the coprocess binary built with ONNX Runtime linked
//! in, which `ENCLAVID_INFERENCE_BIN` names; the graphs are made in code.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use enclavid_boundary::{Asserted, AuthN, Exposed, Untrusted};
use enclavid_boundary_macros::boundary;
use enclavid_inference::fixture;
use engine_executor::admission::DEFAULT_BUNDLE_CACHE_ENTRIES;
use engine_executor::{DEFAULT_ROUND_FUEL, Decision, Event, SessionState, compat_token};
use engine_rpc::{
    BundleSource, BundleStream, CallbackError, CatalogEntry, Committed, CompatToken,
    CompiledBundle, CompositionKey, ExecError, ExecutorLeg, LegSettings, MediaBytes, MediaHash,
    ModelFileDigest, ModelFileStream, Padded, PrepareOutcome, PrepareReply, PrepareRequest,
    RemoteCallbacksAt, RoundProps, RunOutcome, RunReply, RunRequest, RunStatus,
};
use engine_supervisor::{ChildRunner, ChildTimes, CoprocessConfig, RunnerConfig};
use engine_types::composition::ModelLayer;
use engine_types::limits::{MAX_MODEL_FILE_BYTES, MAX_MODELS};
use tokio::sync::Semaphore;

use crate::boundary::AnyCaller;
use crate::bundles::Bundles;
use crate::service::{Caller, Supervisor};

/// How long anything here may wait: room, a stream, a round.
const WAIT: Duration = Duration::from_secs(60);

/// `linear`'s weights, as its data file holds them.
const W: [[f32; 2]; 3] = [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]];
const B: [f32; 2] = [0.5, -0.5];

boundary! {
    /// api, for the test: every concern answered.
    Api {
        calls: [engine_rpc::RemoteExecutor],
        serves: [engine_rpc::RemoteCallbacks],
        observer: Test,
    }
    out (AuthN,) {
        /// test fixture
        _: AuthN::SelfProduced,
        RunRequest,
        PrepareRequest,
        BundleStream,
        Option<MediaBytes>,
        Committed,
        CallbackError,
        ModelFileStream,
    }
    in (Asserted,) {
        /// test fixture
        _: Asserted::Contained,
        RunOutcome,
        RunReply,
        PrepareOutcome,
        PrepareReply,
        ExecError,
        MediaHash,
        Padded<SessionState>,
        Padded<Option<Decision>>,
        ModelFileDigest,
    }
}

/// api's side of the callbacks: serves the model files by digest, and records
/// what the rounds asked for and committed.
#[derive(Clone, Default)]
struct ApiCallbacks {
    files: Arc<HashMap<[u8; 32], Vec<u8>>>,
    digests: Arc<Mutex<Vec<ModelFileDigest>>>,
    states: Arc<Mutex<Vec<Vec<u8>>>>,
    decisions: Arc<Mutex<Vec<Option<Decision>>>>,
}

impl RemoteCallbacksAt<Api> for ApiCallbacks {
    async fn media_load(
        &self,
        _hash: Untrusted<MediaHash, (), Api>,
    ) -> Result<Exposed<Option<MediaBytes>, (), Api>, CallbackError> {
        Err(CallbackError)
    }

    async fn session_change(
        &self,
        state: Untrusted<Padded<SessionState>, (), Api>,
        decision: Untrusted<Padded<Option<Decision>>, (), Api>,
    ) -> Result<Exposed<Committed, (), Api>, CallbackError> {
        let state = state.into_inner().open()?;
        let decision = decision.into_inner().open()?;
        self.states.lock().unwrap().push(state.state);
        self.decisions.lock().unwrap().push(decision);
        Ok(Api::expose(Committed))
    }

    async fn model_file_load(
        &self,
        digest: Untrusted<ModelFileDigest, (), Api>,
    ) -> Result<Exposed<ModelFileStream, (), Api>, CallbackError> {
        let digest = digest.into_inner();
        self.digests.lock().unwrap().push(digest);
        let bytes = self.files.get(&digest.0).ok_or(CallbackError)?.clone();
        let header = fleet_stream::BlobHeader::of(&bytes).ok_or(CallbackError)?;
        let (tx, body) = fleet_stream::bin::channel();
        tokio::spawn(fleet_stream::send(tx, bytes));
        Ok(Api::expose(ModelFileStream { header, body }))
    }
}

/// A worker of one child at a time, spawning `child`, and each model beside
/// it in `inference`.
fn supervisor(child: &Path, inference: &Path) -> Arc<Supervisor> {
    Arc::new(Supervisor {
        bundles: Arc::new(Bundles::new(256 << 20, DEFAULT_BUNDLE_CACHE_ENTRIES)),
        empty: Arc::new(std::fs::File::open("/dev/null").unwrap()),
        rounds: Semaphore::new(1),
        capacity_wait: WAIT,
        bundle_stream: engine_rpc::DEFAULT_BUNDLE_STREAM_DEADLINE,
        bundle_stream_idle: engine_rpc::DEFAULT_BUNDLE_STREAM_IDLE,
        round_fuel: DEFAULT_ROUND_FUEL,
        callback_request_buffer: engine_rpc::DEFAULT_CALLBACK_REQUEST_BUFFER,
        runner: ChildRunner::new(
            RunnerConfig {
                exe: child.to_path_buf(),
                coprocess: Some(CoprocessConfig {
                    exe: inference.to_path_buf(),
                    max: MAX_MODELS,
                }),
                max_children: 1,
                deadline: WAIT,
                admission_wait: Some(WAIT),
                times: ChildTimes::default(),
            },
            None,
        ),
        compat_token: CompatToken::parse(&compat_token()).expect("this build's ABI id"),
    })
}

/// api's end of a leg to a worker of `sup`, which sees api as the caller
/// `test`.
async fn leg(sup: Arc<Supervisor>) -> ExecutorLeg<Api> {
    let (worker, api) = tokio::io::duplex(1 << 20);
    let (worker_read, worker_write) = tokio::io::split(worker);
    let (api_read, api_write) = tokio::io::split(api);
    let caller = Arc::new(Caller {
        sup,
        measurement: "test".into(),
    });
    tokio::spawn(async move {
        let _ = engine_rpc::serve_executor::<AnyCaller, _, _, _>(
            worker_read,
            worker_write,
            caller,
            engine_rpc::DEFAULT_REQUEST_BUFFER,
            &LegSettings::default(),
        )
        .await;
    });
    let (leg, _ended) = engine_rpc::connect_executor::<Api, _, _>(
        api_read,
        api_write,
        &LegSettings::default(),
        engine_rpc::DEFAULT_CALLBACK_REQUEST_BUFFER,
    )
    .await
    .expect("the leg comes up");
    leg
}

/// A round of the composition from its start.
fn round() -> Exposed<RunRequest, (), Api> {
    Api::expose(RunRequest {
        composition_key: CompositionKey::from_digest([0x33; 32]),
        max_cwasm_bytes: engine_rpc::MAX_CWASM_BYTES,
        props: Padded::seal(&RoundProps(Vec::new())).expect("fits the frame"),
        session_state: Padded::seal(&SessionState::default()).expect("fits the frame"),
        event: Event::Start,
    })
}

/// The test policy compiled with its model files, as api has it from a
/// compile.
fn bundle(layers: Vec<ModelLayer>) -> CompiledBundle {
    let parts = engine_compiler::Compiler::new()
        .expect("a compiler")
        .compile_to_parts(xtask::fixtures::test_models().to_vec(), layers, Vec::new())
        .expect("the test policy compiles with its models");
    CompiledBundle {
        cwasm: parts.cwasm,
        embedded_imports: parts.embedded_imports,
        catalogs: parts
            .catalogs
            .into_iter()
            .map(|(hash, decls)| CatalogEntry { hash, decls })
            .collect(),
        models: parts.models,
        files: parts.files,
    }
}

/// What the policy's models compute over the tensors it makes, worked here:
/// the state each round of it commits — `linear`'s output, then `split`'s
/// three, then `widen`'s bytes as floats, each its dimensions and then its
/// elements, little-endian.
fn computed() -> Vec<u8> {
    let x: Vec<f32> = (0..6).map(|i| i as f32 * 0.5).collect();
    let linear: Vec<f32> = x
        .chunks(3)
        .flat_map(|row| (0..2).map(move |j| (0..3).map(|k| row[k] * W[k][j]).sum::<f32>() + B[j]))
        .collect();
    let (a, b) = ([1.0f32, 2.0, 3.0, 4.0], [0.5f32, 0.25, 0.125, 0.0625]);
    let sum: Vec<f32> = a.iter().zip(&b).map(|(a, b)| a + b).collect();
    let wide = [0u8, 7, 255].map(f32::from);
    let tensors: [(&[u64], &[f32]); 5] = [
        (&[2, 2], &linear),
        (&[4], &a),
        (&[4], &b),
        (&[4], &sum),
        (&[3], &wide),
    ];
    let mut state = Vec::new();
    for (dims, data) in tensors {
        state.extend(dims.iter().flat_map(|d| d.to_le_bytes()));
        state.extend(data.iter().flat_map(|v| v.to_le_bytes()));
    }
    state
}

/// The first round's child starts its three models: their files — `linear`'s
/// graph and data file, `split`'s and `widen`'s graphs — are asked of api by
/// the digests the bundle declared and filled, and each model runs in its own
/// process on them. The second round starts its models again on the files the
/// first filled, and api is not asked for one again. Each round commits what
/// the models computed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ENCLAVID_INFERENCE_BIN"]
async fn a_rounds_models_run_in_processes_of_their_own() {
    let inference = PathBuf::from(
        std::env::var_os("ENCLAVID_INFERENCE_BIN")
            .expect("ENCLAVID_INFERENCE_BIN names the coprocess binary"),
    );
    let child = xtask::child_binary("engine-executor-child");
    let (linear, data) = fixture::linear("linear.onnx.data", W, B);
    let split = fixture::split();
    let mut files = HashMap::new();
    let mut layer = |name: &str, bytes: Vec<u8>| {
        let header = fleet_stream::BlobHeader::<MAX_MODEL_FILE_BYTES>::of(&bytes)
            .expect("the file is within the bound");
        files.insert(header.sha256(), bytes);
        ModelLayer {
            name: name.into(),
            sha256: header.sha256(),
            length: header.length(),
        }
    };
    let layers = vec![
        layer("linear.onnx", linear),
        layer("linear.onnx.data", data),
        layer("split.onnx", split),
        layer("widen.onnx", fixture::widen()),
    ];
    let asked: Vec<_> = layers.iter().map(|l| ModelFileDigest(l.sha256)).collect();
    let bundle = BundleSource::whole(bundle(layers)).expect("the bundle streams");
    let leg = leg(supervisor(&child, &inference)).await;
    let api = ApiCallbacks {
        files: Arc::new(files),
        ..ApiCallbacks::default()
    };

    let first = leg
        .run_with_bundle(round(), bundle, api.clone())
        .await
        .expect("the first round runs")
        .into_inner();
    assert!(
        matches!(first, RunStatus::Completed(Decision::Approved)),
        "{first:?}"
    );

    let RunOutcome::Ran(second) = leg
        .run(round(), api.clone())
        .await
        .expect("the second round runs")
        .into_inner()
    else {
        panic!("the composition the first round filled was not kept");
    };
    let second = second.open().expect("the status frames");
    assert!(
        matches!(second, RunStatus::Completed(Decision::Approved)),
        "{second:?}"
    );

    assert_eq!(*api.digests.lock().unwrap(), asked);
    let state = computed();
    assert_eq!(*api.states.lock().unwrap(), [state.clone(), state]);
    assert_eq!(
        *api.decisions.lock().unwrap(),
        [Some(Decision::Approved), Some(Decision::Approved)]
    );
}
