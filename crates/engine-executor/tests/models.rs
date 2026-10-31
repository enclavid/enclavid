//! A composition's models, run from this process: a policy that runs the three
//! models of its own slot — a tensor in and one out, two in and a record of
//! three out, `u8` in and `f32` out — each started as the round first hands it
//! out and answered over its socket by a stand-in for its process, which
//! speaks the coprocess's protocol and computes something simple of its own.

use std::fs::File;
use std::future::Future;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use enclavid_inference::protocol::{self, Data, Failure, Tensor};
use engine_compiler::Compiler;
use engine_executor::{
    DEFAULT_ROUND_FUEL, EmbeddedRegistry, Executor, MediaStore, ModelStarter, PrimedComposition,
    RunError, RunInputs, RunResult, RunStatus, SessionChange, SessionListener,
};
use engine_types::composition::{ModelFile, ModelImport, ModelLayer};
use session_types::{Decision, Event, SessionState};

const POLICY_MODELS: &str = "enclavid-ext:policy/models@0.1.0";

fn f32s(dims: &[u64], data: &[f32]) -> Tensor {
    Tensor {
        dims: dims.to_vec(),
        data: Data::F32(data.to_vec()),
    }
}

/// The tensors the policy runs its models over, as it makes them.
fn x() -> Tensor {
    f32s(&[2, 3], &(0..6).map(|i| i as f32 * 0.5).collect::<Vec<_>>())
}

fn a() -> Tensor {
    f32s(&[4], &[1.0, 2.0, 3.0, 4.0])
}

fn b() -> Tensor {
    f32s(&[4], &[0.5, 0.25, 0.125, 0.0625])
}

fn bytes() -> Tensor {
    Tensor {
        dims: vec![3],
        data: Data::U8(vec![0, 7, 255]),
    }
}

/// What a stand-in process answers a request with.
#[derive(Clone, Copy)]
enum Answer {
    /// `linear` adds one to each element; `split` gives its two inputs back
    /// and their sum; `widen` gives its bytes as `f32`.
    Computed,
    /// Every request is refused for this.
    Refused(Failure),
    /// The outputs are of another element type than the `run`s return.
    OtherType,
    /// One output fewer than the `run`s return.
    Fewer,
    /// The socket is closed before any request is read.
    HungUp,
}

/// The stand-in's answer to `inputs`, as model `index` computes it.
fn computed(index: u32, inputs: Vec<Tensor>) -> Result<Vec<Tensor>, Failure> {
    match (index, inputs.as_slice()) {
        (0, [x]) => {
            let Data::F32(x_data) = &x.data else {
                return Err(Failure::Inputs);
            };
            Ok(vec![f32s(
                &x.dims,
                &x_data.iter().map(|v| v + 1.0).collect::<Vec<_>>(),
            )])
        }
        (1, [a, b]) => {
            let (Data::F32(a_data), Data::F32(b_data)) = (&a.data, &b.data) else {
                return Err(Failure::Inputs);
            };
            let sum: Vec<f32> = a_data.iter().zip(b_data).map(|(a, b)| a + b).collect();
            Ok(vec![a.clone(), b.clone(), f32s(&a.dims, &sum)])
        }
        (2, [x]) => {
            let Data::U8(x_data) = &x.data else {
                return Err(Failure::Inputs);
            };
            Ok(vec![f32s(
                &x.dims,
                &x_data.iter().map(|v| f32::from(*v)).collect::<Vec<_>>(),
            )])
        }
        _ => Err(Failure::Inputs),
    }
}

/// The stand-in's answer as `answer` shapes it.
fn answered(answer: Answer, index: u32, inputs: Vec<Tensor>) -> Result<Vec<Tensor>, Failure> {
    match answer {
        Answer::Refused(failure) => Err(failure),
        Answer::OtherType => Ok(computed(index, inputs)?
            .into_iter()
            .map(|t| Tensor {
                data: Data::I64(vec![0; t.data.len()]),
                dims: t.dims,
            })
            .collect()),
        Answer::Fewer => {
            let mut outputs = computed(index, inputs)?;
            outputs.pop();
            Ok(outputs)
        }
        _ => computed(index, inputs),
    }
}

/// Starts a stand-in for each model's process: a thread on one end of a
/// socketpair, the other end handed to the round. Records which models it
/// was asked to start.
struct StandIns {
    answer: Answer,
    started: Mutex<Vec<u32>>,
}

impl StandIns {
    fn new(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            answer,
            started: Mutex::new(Vec::new()),
        })
    }
}

impl ModelStarter for StandIns {
    fn start(&self, index: u32) -> Pin<Box<dyn Future<Output = RunResult<File>> + Send + '_>> {
        self.started.lock().unwrap().push(index);
        let answer = self.answer;
        Box::pin(async move {
            let (ours, theirs) = UnixStream::pair()?;
            std::thread::spawn(move || {
                let mut socket = theirs;
                if let Answer::HungUp = answer {
                    return;
                }
                while let Ok(Some(request)) = protocol::read_request(&mut socket) {
                    let reply = answered(answer, index, request.inputs);
                    if protocol::write_answer(&mut socket, &reply).is_err() {
                        return;
                    }
                    let _ = socket.flush();
                }
            });
            Ok(File::from(std::os::fd::OwnedFd::from(ours)))
        })
    }
}

struct NoMedia;

impl MediaStore for NoMedia {
    fn load<'a>(
        &'a self,
        _: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = RunResult<Option<Arc<Vec<u8>>>>> + Send + 'a>> {
        Box::pin(async { Ok(None) })
    }
}

struct Discard;

impl SessionListener for Discard {
    fn on_session_change<'a>(
        &'a self,
        _: SessionChange<'a>,
    ) -> Pin<Box<dyn Future<Output = RunResult<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

fn layer(name: &str, sha: u8) -> ModelLayer {
    ModelLayer {
        name: name.into(),
        sha256: [sha; 32],
        length: 1000 + u64::from(sha),
    }
}

/// The test policy, compiled with its graphs — `linear` with a data file,
/// `split` and `widen` without — and primed here.
fn primed() -> (
    Executor,
    PrimedComposition,
    Vec<ModelImport>,
    Vec<ModelFile>,
) {
    let compiler = Compiler::new().unwrap();
    let layers = [
        layer("linear.onnx", 1),
        layer("linear.onnx.data", 2),
        layer("split.onnx", 3),
        layer("widen.onnx", 4),
    ];
    let composition = compiler
        .compose(xtask::fixtures::test_models(), &layers, &[])
        .unwrap();
    let executor = Executor::new().unwrap();
    let cwasm = compiler
        .serialize_component(&composition.component)
        .unwrap();
    let component = executor.deserialize_component(&cwasm).unwrap();
    let primed = executor
        .prime(
            &component,
            &composition.embedded_imports,
            Arc::new(EmbeddedRegistry::builder().build().unwrap()),
            &composition.models,
        )
        .unwrap();
    (executor, primed, composition.models, composition.files)
}

async fn round(
    executor: &Executor,
    primed: &PrimedComposition,
    models: Arc<dyn ModelStarter>,
) -> RunResult<(RunStatus, SessionState)> {
    executor
        .run(
            primed,
            SessionState::default(),
            Event::Start,
            b"",
            RunInputs {
                listener: Arc::new(Discard),
                media_store: Arc::new(NoMedia),
                models,
                fuel: DEFAULT_ROUND_FUEL,
            },
        )
        .await
}

/// Each of `tensors`' dimensions, then its elements, as `f32`, little-endian,
/// in order: the state the policy returns.
fn state(tensors: &[Tensor]) -> Vec<u8> {
    let mut state = Vec::new();
    for tensor in tensors {
        state.extend(tensor.dims.iter().flat_map(|d| d.to_le_bytes()));
        let Data::F32(data) = &tensor.data else {
            panic!("not f32: {:?}", tensor.data);
        };
        state.extend(data.iter().flat_map(|v| v.to_le_bytes()));
    }
    state
}

#[test]
fn the_compile_hands_each_model_its_resource_and_files() {
    let (_, _, models, files) = primed();
    let model = |function: &str, resource: &str, graph, data| ModelImport {
        instance_name: POLICY_MODELS.into(),
        function: function.into(),
        resource: resource.into(),
        graph,
        data,
    };
    assert_eq!(
        models,
        vec![
            model("linear", "linear-model", 0, Some(1)),
            model("split", "split-model", 2, None),
            model("widen", "widen-model", 3, None),
        ]
    );
    assert_eq!(files.len(), 4);
}

/// Each model runs in its own process, started once however many times the
/// round hands it out, and what each answers is what the policy gets — one
/// tensor, a record of three by name, a tensor of another element type than
/// its input.
#[tokio::test(flavor = "multi_thread")]
async fn a_policys_models_run_as_their_processes_answer() {
    let (executor, primed, _, _) = primed();
    let models = StandIns::new(Answer::Computed);
    let (status, session) = round(&executor, &primed, models.clone()).await.unwrap();
    assert!(matches!(status, RunStatus::Completed(Decision::Approved)));
    assert_eq!(*models.started.lock().unwrap(), vec![0, 1, 2]);
    let mut want = computed(0, vec![x()]).unwrap();
    want.extend(computed(1, vec![a(), b()]).unwrap());
    want.extend(computed(2, vec![bytes()]).unwrap());
    assert_eq!(session.state, state(&want));
}

/// What a process answers that its `run` does not return — a refusal of any
/// kind, tensors of another element type, fewer of them — traps the round, as
/// a process that goes away does, and one that does not start.
#[tokio::test(flavor = "multi_thread")]
async fn what_a_run_does_not_return_traps_the_round() {
    struct NoStart;
    impl ModelStarter for NoStart {
        fn start(&self, _: u32) -> Pin<Box<dyn Future<Output = RunResult<File>> + Send + '_>> {
            Box::pin(async { Err(RunError::msg("no process")) })
        }
    }
    let (executor, primed, _, _) = primed();
    let mut starters: Vec<(String, Arc<dyn ModelStarter>)> = vec![
        ("other type".into(), StandIns::new(Answer::OtherType)),
        ("fewer".into(), StandIns::new(Answer::Fewer)),
        ("hung up".into(), StandIns::new(Answer::HungUp)),
        ("no start".into(), Arc::new(NoStart)),
    ];
    for failure in [Failure::NoModel, Failure::Inputs, Failure::Run] {
        starters.push((
            format!("{failure:?}"),
            StandIns::new(Answer::Refused(failure)),
        ));
    }
    for (what, starter) in starters {
        assert!(round(&executor, &primed, starter).await.is_err(), "{what}");
    }
}
