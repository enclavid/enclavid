//! What a round and its model's coprocess say to each other, over the socket
//! the supervisor paired them with: a request names a model and gives its
//! inputs, and the answer gives the outputs or says why there are none.
//!
//! Each end reads what the other wrote and trusts none of it: every count,
//! rank, dimension and element type is bounded before anything is allocated
//! for it, so no message makes its reader allocate more than [`MAX_BYTES`] of
//! elements.
//!
//! Little-endian throughout:
//!
//! ```text
//! request  u32 model, u32 count, `count` tensors
//! answer   u32 status: 0, then u32 count and `count` tensors — or a Failure
//! tensor   i32 element type, as ONNX's `TensorProto.DataType` numbers it,
//!          u32 rank, `rank` × u64 dimensions, then its elements as they lie
//!          in memory
//! ```

use std::io::{self, Read, Write};

use zerocopy::IntoBytes;

use crate::graph::Element;

#[cfg(test)]
mod tests;

#[cfg(not(target_endian = "little"))]
compile_error!("the protocol's elements are written as they lie in memory, little-endian");

/// The most tensors one message carries.
pub const MAX_TENSORS: u32 = 64;
/// The most dimensions one tensor has.
pub const MAX_RANK: u32 = 8;
/// The most bytes of elements one message carries, its tensors together:
/// 64 MiB.
pub const MAX_BYTES: u64 = 64 << 20;

/// A tensor's elements in row-major order, each element type in a vector of
/// its own — half-precision ones as their bits.
#[derive(Clone, Debug, PartialEq)]
pub enum Data {
    F32(Vec<f32>),
    F64(Vec<f64>),
    F16(Vec<u16>),
    Bf16(Vec<u16>),
    I8(Vec<i8>),
    U8(Vec<u8>),
    I16(Vec<i16>),
    U16(Vec<u16>),
    I32(Vec<i32>),
    U32(Vec<u32>),
    I64(Vec<i64>),
    U64(Vec<u64>),
}

/// `$body` over the vector `$data` holds, `$v`, whatever its element type.
macro_rules! each {
    ($data:expr, $v:ident => $body:expr) => {
        match $data {
            Data::F32($v) => $body,
            Data::F64($v) => $body,
            Data::F16($v) | Data::Bf16($v) | Data::U16($v) => $body,
            Data::I8($v) => $body,
            Data::U8($v) => $body,
            Data::I16($v) => $body,
            Data::I32($v) => $body,
            Data::U32($v) => $body,
            Data::I64($v) => $body,
            Data::U64($v) => $body,
        }
    };
}

impl Data {
    /// The type of its elements.
    pub fn element(&self) -> Element {
        match self {
            Data::F32(_) => Element::F32,
            Data::F64(_) => Element::F64,
            Data::F16(_) => Element::F16,
            Data::Bf16(_) => Element::Bf16,
            Data::I8(_) => Element::I8,
            Data::U8(_) => Element::U8,
            Data::I16(_) => Element::I16,
            Data::U16(_) => Element::U16,
            Data::I32(_) => Element::I32,
            Data::U32(_) => Element::U32,
            Data::I64(_) => Element::I64,
            Data::U64(_) => Element::U64,
        }
    }

    /// How many elements it holds.
    pub fn len(&self) -> usize {
        each!(self, v => v.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn as_bytes(&self) -> &[u8] {
        each!(self, v => v.as_bytes())
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        each!(self, v => v.as_mut_bytes())
    }

    /// `len` elements of `element`, zero, to read into.
    fn zeroed(element: Element, len: usize) -> Data {
        match element {
            Element::F32 => Data::F32(vec![0.0; len]),
            Element::F64 => Data::F64(vec![0.0; len]),
            Element::F16 => Data::F16(vec![0; len]),
            Element::Bf16 => Data::Bf16(vec![0; len]),
            Element::I8 => Data::I8(vec![0; len]),
            Element::U8 => Data::U8(vec![0; len]),
            Element::I16 => Data::I16(vec![0; len]),
            Element::U16 => Data::U16(vec![0; len]),
            Element::I32 => Data::I32(vec![0; len]),
            Element::U32 => Data::U32(vec![0; len]),
            Element::I64 => Data::I64(vec![0; len]),
            Element::U64 => Data::U64(vec![0; len]),
        }
    }
}

/// A tensor: its dimensions, and its elements, as many as they hold.
#[derive(Clone, Debug, PartialEq)]
pub struct Tensor {
    pub dims: Vec<u64>,
    pub data: Data,
}

/// A run of the coprocess's model `model` over `inputs`, in the model's order.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub model: u32,
    pub inputs: Vec<Tensor>,
}

/// Why a request has no outputs. Fixed codes, and nothing else: a run's own
/// errors are ONNX Runtime's text, which is the model's to shape and not for a
/// round to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    #[error("the coprocess has no such model")]
    NoModel = 1,
    #[error("the inputs are not the model's")]
    Inputs = 2,
    #[error("the model did not run")]
    Run = 3,
}

impl Failure {
    fn of(status: u32) -> Option<Failure> {
        [Failure::NoModel, Failure::Inputs, Failure::Run]
            .into_iter()
            .find(|f| *f as u32 == status)
    }
}

/// Why a message could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("read the message: {0}")]
    Io(#[from] io::Error),
    #[error("the message is past its bounds")]
    Bounds,
    #[error("the message names element type {0}, which is none")]
    Element(i32),
    #[error("the answer has status {0}, which is none")]
    Status(u32),
}

/// Write `request`.
pub fn write_request(to: &mut impl Write, request: &Request) -> io::Result<()> {
    let mut head = Vec::with_capacity(8);
    head.extend_from_slice(&request.model.to_le_bytes());
    write_tensors(to, head, &request.inputs)
}

/// Read a request, or `None` where the other end closed the socket before
/// starting one.
pub fn read_request(from: &mut impl Read) -> Result<Option<Request>, ProtocolError> {
    let mut first = [0u8; 4];
    let mut got = 0;
    while got < first.len() {
        match from.read(&mut first[got..])? {
            0 if got == 0 => return Ok(None),
            0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            n => got += n,
        }
    }
    let model = u32::from_le_bytes(first);
    let inputs = read_tensors(from)?;
    Ok(Some(Request { model, inputs }))
}

/// Write the answer to a request: its outputs, or why there are none.
pub fn write_answer(to: &mut impl Write, answer: &Result<Vec<Tensor>, Failure>) -> io::Result<()> {
    match answer {
        Ok(outputs) => write_tensors(to, 0u32.to_le_bytes().to_vec(), outputs),
        Err(failure) => to.write_all(&(*failure as u32).to_le_bytes()),
    }
}

/// Read the answer to a request.
pub fn read_answer(from: &mut impl Read) -> Result<Result<Vec<Tensor>, Failure>, ProtocolError> {
    match read_u32(from)? {
        0 => Ok(Ok(read_tensors(from)?)),
        status => Failure::of(status)
            .map(Err)
            .ok_or(ProtocolError::Status(status)),
    }
}

/// `head`, then the count of `tensors` and each of them. A tensor whose
/// elements are not what its dimensions hold is not written.
fn write_tensors(to: &mut impl Write, mut head: Vec<u8>, tensors: &[Tensor]) -> io::Result<()> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
    head.extend_from_slice(
        &u32::try_from(tensors.len())
            .map_err(|_| invalid())?
            .to_le_bytes(),
    );
    to.write_all(&head)?;
    for tensor in tensors {
        let held = elements(&tensor.dims).ok_or_else(invalid)?;
        if usize::try_from(held).ok() != Some(tensor.data.len()) {
            return Err(invalid());
        }
        let mut dims = Vec::with_capacity(8 + 8 * tensor.dims.len());
        dims.extend_from_slice(&tensor.data.element().code().to_le_bytes());
        dims.extend_from_slice(
            &u32::try_from(tensor.dims.len())
                .map_err(|_| invalid())?
                .to_le_bytes(),
        );
        for dim in &tensor.dims {
            dims.extend_from_slice(&dim.to_le_bytes());
        }
        to.write_all(&dims)?;
        to.write_all(tensor.data.as_bytes())?;
    }
    to.flush()
}

/// A count of tensors and each of them, held to the bounds before anything is
/// allocated for one.
fn read_tensors(from: &mut impl Read) -> Result<Vec<Tensor>, ProtocolError> {
    let count = read_u32(from)?;
    if count > MAX_TENSORS {
        return Err(ProtocolError::Bounds);
    }
    let mut tensors = Vec::with_capacity(count as usize);
    let mut total = 0u64;
    for _ in 0..count {
        let code = read_u32(from)? as i32;
        let element = Element::of(code).ok_or(ProtocolError::Element(code))?;
        let rank = read_u32(from)?;
        if rank > MAX_RANK {
            return Err(ProtocolError::Bounds);
        }
        let dims = (0..rank)
            .map(|_| read_u64(from))
            .collect::<Result<Vec<_>, _>>()?;
        let held = elements(&dims).ok_or(ProtocolError::Bounds)?;
        total = held
            .checked_mul(element.size())
            .and_then(|bytes| total.checked_add(bytes))
            .filter(|&total| total <= MAX_BYTES)
            .ok_or(ProtocolError::Bounds)?;
        let mut data = Data::zeroed(element, held as usize);
        from.read_exact(data.as_mut_bytes())?;
        tensors.push(Tensor { dims, data });
    }
    Ok(tensors)
}

/// How many elements `dims` hold, if that can be counted.
fn elements(dims: &[u64]) -> Option<u64> {
    dims.iter().try_fold(1u64, |n, &d| n.checked_mul(d))
}

fn read_u32(from: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    from.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(from: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    from.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
