//! The coprocess as a runner starts it: on a socket, its models handed from
//! fd 3, and on Linux under the coprocess's syscall filters — so a run here is
//! a run under the narrowing it does to itself once its models are loaded.
//!
//! It links ONNX Runtime, so it builds where `ORT_LIB_LOCATION` names a build
//! of it — image/onnxruntime's, in the image's toolchain.

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use enclavid_inference::fixture;
use enclavid_inference::protocol::{Data, Failure, Request, Tensor, read_answer, write_request};

const DATA: &str = "linear.onnx.data";
const W: [[f32; 2]; 3] = [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]];
const B: [f32; 2] = [0.5, -0.5];

fn f32s(dims: &[u64], data: Vec<f32>) -> Tensor {
    Tensor {
        dims: dims.to_vec(),
        data: Data::F32(data),
    }
}

fn file(bytes: &[u8]) -> File {
    let mut file = tempfile::tempfile().expect("a temporary file");
    file.write_all(bytes).expect("write it");
    file
}

/// The coprocess, started on a socket with `models` handed in order — each a
/// graph and its data file — and the other end of the socket.
fn start(models: &[(Vec<u8>, Vec<u8>)]) -> (tokio::process::Child, UnixStream) {
    let files: Vec<File> = models
        .iter()
        .flat_map(|(graph, data)| [file(graph), file(data)])
        .collect();
    let handed: Vec<BorrowedFd<'_>> = files.iter().map(|f| f.as_fd()).collect();
    let (ours, theirs) = UnixStream::pair().expect("a socket pair");
    let coprocess = engine_supervisor::spawn_coprocess(
        Path::new(env!("CARGO_BIN_EXE_engine-executor-inference")),
        OwnedFd::from(theirs),
        &handed,
        cfg!(target_os = "linux"),
    )
    .expect("the coprocess starts");
    (coprocess, ours)
}

fn ask(socket: &mut UnixStream, model: u32, inputs: Vec<Tensor>) -> Result<Vec<Tensor>, Failure> {
    write_request(socket, &Request { model, inputs }).expect("send the request");
    read_answer(socket).expect("read the answer")
}

fn x(rows: &[[f32; 3]]) -> Tensor {
    f32s(
        &[rows.len() as u64, 3],
        rows.iter().flatten().copied().collect(),
    )
}

/// `x · W + b`, row by row, as the graph computes it.
fn expected(rows: &[[f32; 3]]) -> Tensor {
    let data = rows
        .iter()
        .flat_map(|row| (0..2).map(move |j| (0..3).map(|i| row[i] * W[i][j]).sum::<f32>() + B[j]))
        .collect();
    f32s(&[rows.len() as u64, 2], data)
}

/// A model runs, its weights read from the data file where they lie, and the
/// answer is the graph's — for any batch its named dimension takes. When the
/// round lets go of the socket, the coprocess is done.
#[tokio::test]
async fn a_model_runs_and_the_answer_is_the_graphs() {
    let (mut coprocess, mut socket) = start(&[fixture::linear(DATA, W, B)]);
    for rows in [
        &[[1.0, 1.0, 1.0]][..],
        &[[2.0, 0.0, 1.0], [0.5, -1.0, 3.0]][..],
    ] {
        assert_eq!(ask(&mut socket, 0, vec![x(rows)]), Ok(vec![expected(rows)]));
    }
    // Answering, it runs under three filters: the two it was started under
    // and the one it narrowed itself with once its models were loaded.
    #[cfg(target_os = "linux")]
    {
        let pid = coprocess.id().expect("the coprocess is running");
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("its status");
        assert!(
            status.lines().any(|l| l == "Seccomp_filters:\t3"),
            "{status}"
        );
    }
    drop(socket);
    let status = coprocess.wait().await.expect("wait for the coprocess");
    assert!(status.success(), "{status:?}");
}

/// A request for a model the coprocess does not have, or with inputs the
/// graph does not take, is answered with why — and the coprocess goes on
/// answering.
#[tokio::test]
async fn what_a_model_does_not_take_is_answered_and_the_next_request_runs() {
    let (_coprocess, mut socket) = start(&[fixture::linear(DATA, W, B)]);
    let rows = [[1.0, 2.0, 3.0]];
    assert_eq!(ask(&mut socket, 1, vec![x(&rows)]), Err(Failure::NoModel));
    assert_eq!(ask(&mut socket, 0, vec![]), Err(Failure::Inputs));
    let wrong_width = f32s(&[1, 4], vec![0.0; 4]);
    assert_eq!(ask(&mut socket, 0, vec![wrong_width]), Err(Failure::Inputs));
    let wrong_rank = f32s(&[3], vec![0.0; 3]);
    assert_eq!(ask(&mut socket, 0, vec![wrong_rank]), Err(Failure::Inputs));
    let too_wide = f32s(&[u64::MAX, 0], vec![]);
    assert_eq!(ask(&mut socket, 0, vec![too_wide]), Err(Failure::Inputs));
    let wrong_type = Tensor {
        dims: vec![1, 3],
        data: Data::F64(vec![1.0, 2.0, 3.0]),
    };
    assert_eq!(ask(&mut socket, 0, vec![wrong_type]), Err(Failure::Inputs));
    assert_eq!(
        ask(&mut socket, 0, vec![x(&rows)]),
        Ok(vec![expected(&rows)])
    );
}

/// A model whose input and output are of different element types is given
/// the one and gives back the other.
#[tokio::test]
async fn a_model_gives_back_the_element_type_its_graph_declares() {
    let (_coprocess, mut socket) = start(&[(fixture::widen(), Vec::new())]);
    let bytes = Tensor {
        dims: vec![3],
        data: Data::U8(vec![0, 7, 255]),
    };
    assert_eq!(
        ask(&mut socket, 0, vec![bytes]),
        Ok(vec![f32s(&[3], vec![0.0, 7.0, 255.0])])
    );
}

/// A vendor's model as its vendor ships it — MiVOLO's graph and data file, in
/// `MIVOLO_MODEL` (`mivolo.onnx` and `mivolo.onnx.data`) — gives the age torch
/// gives for the same input, `MIVOLO_INPUT` and `MIVOLO_OUTPUT` as raw f32.
/// Ignored: the files are a hundred megabytes and are not in the repository.
#[tokio::test]
#[ignore]
async fn a_vendors_model_answers_as_its_vendor_ran_it() {
    let path = |var: &str| std::env::var(var).unwrap_or_else(|_| panic!("{var} names a file"));
    let read = |p: String| std::fs::read(p).expect("read the file");
    let floats = |bytes: Vec<u8>| -> Vec<f32> {
        let (whole, _) = bytes.as_chunks::<4>();
        whole.iter().map(|b| f32::from_le_bytes(*b)).collect()
    };
    let dir = path("MIVOLO_MODEL");
    let model = (
        read(format!("{dir}/mivolo.onnx")),
        read(format!("{dir}/mivolo.onnx.data")),
    );
    let input = floats(read(path("MIVOLO_INPUT")));
    let want = floats(read(path("MIVOLO_OUTPUT")));

    let (_coprocess, mut socket) = start(&[model]);
    let started = std::time::Instant::now();
    let outputs =
        ask(&mut socket, 0, vec![f32s(&[1, 6, 384, 384], input)]).expect("the model runs");
    let Data::F32(got) = &outputs[0].data else {
        panic!("not f32: {:?}", outputs[0].data.element());
    };
    let diff = got
        .iter()
        .zip(&want)
        .map(|(a, b)| (a - b).abs())
        .fold(0f32, f32::max);
    eprintln!(
        "first run {:.2} s, age {:.2}, max |diff| {diff:.1e}",
        started.elapsed().as_secs_f64(),
        got[2] * 122.0 + 61.0
    );
    assert!(diff < 1e-4, "{got:?} against {want:?}");
}

/// A model whose graph is refused is no model to the round, and the models
/// beside it still run.
#[tokio::test]
async fn a_refused_model_is_none_and_its_neighbours_run() {
    // A graph whose weights name a path, not a file beside it.
    let refused = fixture::linear("../elsewhere", W, B);
    let (_coprocess, mut socket) = start(&[refused, fixture::linear(DATA, W, B)]);
    let rows = [[1.0, 0.0, 0.0]];
    assert_eq!(ask(&mut socket, 0, vec![x(&rows)]), Err(Failure::NoModel));
    assert_eq!(
        ask(&mut socket, 1, vec![x(&rows)]),
        Ok(vec![expected(&rows)])
    );
}
