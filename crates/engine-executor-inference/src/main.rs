//! The coprocess a model runs in.
//!
//! On fd 0 is the socket whose other end the round holds, on fd 3 the model's
//! graph and on fd 4 its data file — empty where it has none. One model and no
//! more: whatever a graph makes of ONNX Runtime, the process it reaches holds
//! no other model's weights. The coprocess checks and loads the model, narrows
//! itself so that no thread of it opens a file or starts a program from then
//! on, and answers the round's requests one at a time until the round lets go
//! of the socket.
//!
//! A model whose graph is refused, or that ONNX Runtime does not load, is
//! answered as no model at all. Why is the vendor's to see where the graph is
//! checked before any session runs it, not the round's to read.

use std::fs::File;
use std::os::fd::{AsFd, FromRawFd, OwnedFd, RawFd};
use std::process::ExitCode;

use enclavid_inference::graph::{self, DataFile, Dim, Element, Port, Weight};
use enclavid_inference::protocol::{self, Data, Failure, Tensor};
use half::slice::{HalfBitsSliceExt, HalfFloatSliceExt};
use half::{bf16, f16};
use memmap2::Mmap;
use ort::environment::Environment;
use ort::session::{Session, SessionInputValue};
use ort::value::{DynValue, PrimitiveTensorElementType, TensorRef};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Where the descriptors handed to a process start: after stdio, where the
/// supervisor places them.
const HANDED: RawFd = 3;

type Stop = Box<dyn std::error::Error>;

fn main() -> ExitCode {
    match serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn serve() -> Result<(), Stop> {
    let (graph, data) = handed()?;
    // Read and written as a file, with read(2) and write(2): a socket type
    // reads through recvfrom, which the coprocess's filter does not have.
    let mut socket = File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let environment = ort::init().with_telemetry(false).build()?;
    let mut model = Model::load(&environment, &graph, &data).ok();
    drop((graph, data));
    narrow()?;
    while let Some(request) = protocol::read_request(&mut socket)? {
        let answer = match (request.model, model.as_mut()) {
            (0, Some(model)) => model.run(&request.inputs),
            _ => Err(Failure::NoModel),
        };
        protocol::write_answer(&mut socket, &answer)?;
    }
    Ok(())
}

/// The model handed on fd 3 and fd 4: its graph and its data file. Both are
/// open and nothing past them is — the supervisor closed the rest at the exec,
/// and this runs before anything here opens a file — or the coprocess stops:
/// it runs one model and no more.
fn handed() -> Result<(File, File), Stop> {
    let mut files = Vec::new();
    for fd in HANDED.. {
        // SAFETY: `F_GETFD` on a bare number reads its flags or fails with
        // EBADF; it creates, closes and dereferences nothing.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
            break;
        }
        // SAFETY: open, as just checked, handed to this process at its exec,
        // and owned by nothing else in it.
        files.push(File::from(unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    let mut files = files.into_iter();
    match (files.next(), files.next(), files.next()) {
        (Some(graph), Some(data), None) => Ok((graph, data)),
        _ => Err("the handed files are not one model's graph and data file".into()),
    }
}

/// Once its model is loaded the coprocess has no file to open and no program
/// to start, so a filter of its own — on top of the one it was started under,
/// which can only be narrowed — ends it if any of its threads tries either,
/// whatever a graph has made of ONNX Runtime.
#[cfg(target_os = "linux")]
fn narrow() -> Result<(), Stop> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

    #[cfg(target_arch = "x86_64")]
    const ARCH: TargetArch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    const ARCH: TargetArch = TargetArch::aarch64;

    let rules = [libc::SYS_openat, libc::SYS_execve]
        .into_iter()
        .map(|sys| (sys, Vec::new()))
        .collect();
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        ARCH,
    )?
    .try_into()?;
    seccompiler::apply_filter_all_threads(&filter)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn narrow() -> Result<(), Stop> {
    Ok(())
}

/// A model, loaded: its session, what a run is given and gives back, and the
/// weights it is fed from its data file, which stays mapped for as long as the
/// coprocess runs.
struct Model {
    session: Session,
    inputs: Vec<Port>,
    outputs: Vec<Port>,
    weights: Vec<Weight>,
    data: Option<Mmap>,
}

impl Model {
    /// Check the model in `graph` and `data` and load it. The graph is held
    /// only while it loads: ONNX Runtime keeps its own copy.
    fn load(environment: &Environment, graph: &File, data: &File) -> Result<Model, Stop> {
        let graph = map(graph)?;
        let data = map(data)?;
        let file = DataFile {
            name: None,
            len: data.as_ref().map_or(0, |data| data.len() as u64),
        };
        let checked = graph::check(graph.as_deref().unwrap_or_default(), Some(file))?;
        let session = Session::builder(environment)?
            // A round runs on one core; rounds run side by side on the rest.
            .with_intra_threads(1)?
            .with_inter_threads(1)?
            // With a memory pattern, every run after the first takes one block
            // for all its activations beside what the first left in the arena.
            .with_memory_pattern(false)?
            .commit_from_memory(&checked.graph)?;
        Ok(Model {
            session,
            inputs: checked.inputs,
            outputs: checked.outputs,
            weights: checked.weights,
            data,
        })
    }

    /// Run the model over `inputs`, one per input of the graph, in its order
    /// and of its element type.
    fn run(&mut self, inputs: &[Tensor]) -> Result<Vec<Tensor>, Failure> {
        if inputs.len() != self.inputs.len() {
            return Err(Failure::Inputs);
        }
        let mut feed: Vec<(&str, SessionInputValue<'_>)> =
            Vec::with_capacity(inputs.len() + self.weights.len());
        for (tensor, port) in inputs.iter().zip(&self.inputs) {
            if tensor.data.element() != port.element {
                return Err(Failure::Inputs);
            }
            let shape = shape(&tensor.dims, port.dims.as_deref()).ok_or(Failure::Inputs)?;
            feed.push((
                port.name.as_str(),
                input(&tensor.data, shape).ok_or(Failure::Inputs)?,
            ));
        }
        let data = self.data.as_deref().unwrap_or_default();
        for weight in &self.weights {
            feed.push((
                weight.name.as_str(),
                view(weight, data).ok_or(Failure::Run)?,
            ));
        }
        let outputs = self.session.run(feed).map_err(|_| Failure::Run)?;
        self.outputs
            .iter()
            .map(|port| {
                let value = outputs.get(port.name.as_str()).ok_or(Failure::Run)?;
                output(value, port.element).ok_or(Failure::Run)
            })
            .collect()
    }
}

/// `data` as ONNX Runtime is given it, in `shape`: the elements where they
/// lie, half-precision bits as the floats they are.
fn input(data: &Data, shape: Vec<i64>) -> Option<SessionInputValue<'_>> {
    match data {
        Data::F32(v) => elements(v, shape),
        Data::F64(v) => elements(v, shape),
        Data::F16(v) => elements(v.reinterpret_cast::<f16>(), shape),
        Data::Bf16(v) => elements(v.reinterpret_cast::<bf16>(), shape),
        Data::I8(v) => elements(v, shape),
        Data::U8(v) => elements(v, shape),
        Data::I16(v) => elements(v, shape),
        Data::U16(v) => elements(v, shape),
        Data::I32(v) => elements(v, shape),
        Data::U32(v) => elements(v, shape),
        Data::I64(v) => elements(v, shape),
        Data::U64(v) => elements(v, shape),
    }
}

/// The output `value` as the tensor of `element` its graph declares it: no
/// other type is taken.
fn output(value: &DynValue, element: Element) -> Option<Tensor> {
    match element {
        Element::F32 => extract(value, |v: &[f32]| Data::F32(v.to_vec())),
        Element::F64 => extract(value, |v: &[f64]| Data::F64(v.to_vec())),
        Element::F16 => extract(value, |v: &[f16]| Data::F16(v.reinterpret_cast().to_vec())),
        Element::Bf16 => extract(value, |v: &[bf16]| {
            Data::Bf16(v.reinterpret_cast().to_vec())
        }),
        Element::I8 => extract(value, |v: &[i8]| Data::I8(v.to_vec())),
        Element::U8 => extract(value, |v: &[u8]| Data::U8(v.to_vec())),
        Element::I16 => extract(value, |v: &[i16]| Data::I16(v.to_vec())),
        Element::U16 => extract(value, |v: &[u16]| Data::U16(v.to_vec())),
        Element::I32 => extract(value, |v: &[i32]| Data::I32(v.to_vec())),
        Element::U32 => extract(value, |v: &[u32]| Data::U32(v.to_vec())),
        Element::I64 => extract(value, |v: &[i64]| Data::I64(v.to_vec())),
        Element::U64 => extract(value, |v: &[u64]| Data::U64(v.to_vec())),
    }
}

/// The tensor `value` is, if its elements are of `T`, copied out as `data`
/// makes them.
fn extract<T: PrimitiveTensorElementType>(
    value: &DynValue,
    data: impl FnOnce(&[T]) -> Data,
) -> Option<Tensor> {
    let (shape, elements) = value.try_extract_tensor::<T>().ok()?;
    let dims = shape
        .iter()
        .map(|&d| u64::try_from(d).ok())
        .collect::<Option<_>>()?;
    Some(Tensor {
        dims,
        data: data(elements),
    })
}

/// `file` mapped, or `None` where it is empty.
fn map(file: &File) -> Result<Option<Mmap>, Stop> {
    if file.metadata()?.len() == 0 {
        return Ok(None);
    }
    // SAFETY: the supervisor hands a model's files sealed against writing, so
    // what this maps does not change under the sessions reading it.
    Ok(Some(unsafe { Mmap::map(file)? }))
}

/// The shape ONNX Runtime is given for an input of `dims`, if they fit what
/// its graph declares: the declared rank, the declared fixed sizes, and every
/// size one ONNX Runtime can take.
fn shape(dims: &[u64], declared: Option<&[Dim]>) -> Option<Vec<i64>> {
    if let Some(declared) = declared {
        let fits = declared.len() == dims.len()
            && declared
                .iter()
                .zip(dims)
                .all(|(d, &n)| !matches!(d, Dim::Fixed(f) if *f != n));
        if !fits {
            return None;
        }
    }
    dims.iter().map(|&d| i64::try_from(d).ok()).collect()
}

/// `weight` as ONNX Runtime is given it: its elements where they lie in
/// `data`, which the check held it to — inside the file, aligned to its
/// element.
fn view<'a>(weight: &Weight, data: &'a [u8]) -> Option<SessionInputValue<'a>> {
    let start = usize::try_from(weight.offset).ok()?;
    let end = start.checked_add(usize::try_from(weight.len).ok()?)?;
    let bytes = data.get(start..end)?;
    let shape = weight
        .dims
        .iter()
        .map(|&d| i64::try_from(d).ok())
        .collect::<Option<Vec<_>>>()?;
    match weight.element {
        Element::F32 => typed::<f32>(bytes, shape),
        Element::F64 => typed::<f64>(bytes, shape),
        Element::F16 => typed::<f16>(bytes, shape),
        Element::Bf16 => typed::<bf16>(bytes, shape),
        Element::I8 => typed::<i8>(bytes, shape),
        Element::U8 => typed::<u8>(bytes, shape),
        Element::I16 => typed::<i16>(bytes, shape),
        Element::U16 => typed::<u16>(bytes, shape),
        Element::I32 => typed::<i32>(bytes, shape),
        Element::U32 => typed::<u32>(bytes, shape),
        Element::I64 => typed::<i64>(bytes, shape),
        Element::U64 => typed::<u64>(bytes, shape),
    }
}

fn typed<T>(bytes: &[u8], shape: Vec<i64>) -> Option<SessionInputValue<'_>>
where
    T: PrimitiveTensorElementType
        + FromBytes
        + Immutable
        + KnownLayout
        + Clone
        + std::fmt::Debug
        + 'static,
{
    elements(<[T]>::ref_from_bytes(bytes).ok()?, shape)
}

/// `elements` as a tensor of `shape`, borrowed, not copied.
fn elements<T>(elements: &[T], shape: Vec<i64>) -> Option<SessionInputValue<'_>>
where
    T: PrimitiveTensorElementType + Clone + std::fmt::Debug + 'static,
{
    Some(TensorRef::from_array_view((shape, elements)).ok()?.into())
}

#[cfg(test)]
mod tests {
    /// The handed files start where the supervisor puts a process's handed
    /// descriptors.
    #[test]
    fn handed_files_start_where_the_supervisor_puts_them() {
        assert_eq!(super::HANDED, engine_supervisor::INHERITED_FD);
    }
}
