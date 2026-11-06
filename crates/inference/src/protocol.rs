//! What a round and its model's coprocess say to each other over their
//! channel (`coprocess-channel`): a request names a model and gives its
//! inputs, and the response gives the outputs or says why there are none.
//!
//! A tensor crosses as its element type — as ONNX's `TensorProto.DataType`
//! numbers it — its dimensions, and its elements' bytes as they lie in memory,
//! little-endian. Each end reads what the other wrote and trusts none of it: a
//! message is held to [`MAX_MESSAGE_BYTES`] before anything is allocated for
//! it, its tensors to [`MAX_TENSORS`] and their dimensions to [`MAX_RANK`] as
//! they are read, and a tensor whose element type is none or whose bytes are
//! not what its dimensions hold is not read as one. How many tensors a run
//! takes and gives is its model's, which each end holds them to.

use coprocess_channel::at_most;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::{ByteBuf, Bytes};
use zerocopy::IntoBytes;

use crate::graph::Element;

#[cfg(test)]
mod tests;

#[cfg(not(target_endian = "little"))]
compile_error!("a tensor's elements cross as they lie in memory, little-endian");

/// The most tensors a run takes, and the most it gives.
pub const MAX_TENSORS: u32 = 64;
/// The most dimensions one tensor has.
pub const MAX_RANK: u32 = 8;
/// The most bytes of elements one message carries, its tensors together:
/// 64 MiB.
pub const MAX_BYTES: u64 = 64 << 20;
/// The most bytes a message is, as the channel carries it: its elements at
/// their bound, and room for the rest of it.
pub const MAX_MESSAGE_BYTES: usize = MAX_BYTES as usize + (64 << 10);

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

/// A tensor: its dimensions, and its elements, as many as they hold. A tensor
/// whose elements are not what its dimensions hold is not sent.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(try_from = "Wire")]
pub struct Tensor {
    pub dims: Vec<u64>,
    pub data: Data,
}

/// A tensor as the channel carries it.
#[derive(Deserialize)]
struct Wire {
    element: i32,
    #[serde(deserialize_with = "dims")]
    dims: Vec<u64>,
    bytes: ByteBuf,
}

/// A tensor as it is sent, from where its elements lie: the same fields as
/// [`Wire`].
#[derive(Serialize)]
struct WireRef<'a> {
    element: i32,
    dims: &'a [u64],
    bytes: &'a Bytes,
}

impl Serialize for Tensor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if elements(&self.dims) != u64::try_from(self.data.len()).ok() {
            return Err(S::Error::custom(
                "a tensor whose elements are not what its dimensions hold",
            ));
        }
        WireRef {
            element: self.data.element().code(),
            dims: &self.dims,
            bytes: Bytes::new(self.data.as_bytes()),
        }
        .serialize(serializer)
    }
}

impl TryFrom<Wire> for Tensor {
    type Error = &'static str;

    fn try_from(wire: Wire) -> Result<Self, Self::Error> {
        let element = Element::of(wire.element).ok_or("an element type that is none")?;
        let held = elements(&wire.dims)
            .filter(|&n| n.checked_mul(element.size()) == Some(wire.bytes.len() as u64))
            .ok_or("bytes that are not what the dimensions hold")?;
        let mut data = Data::zeroed(element, held as usize);
        data.as_mut_bytes().copy_from_slice(&wire.bytes);
        Ok(Tensor {
            dims: wire.dims,
            data,
        })
    }
}

/// A run of the coprocess's model `model` over `inputs`, in the model's order.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub model: u32,
    #[serde(deserialize_with = "tensors")]
    pub inputs: Vec<Tensor>,
}

/// The coprocess's response to a request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Response {
    /// The outputs, in the model's order.
    Outputs(#[serde(deserialize_with = "tensors")] Vec<Tensor>),
    /// Why there are none.
    Failed(Failure),
}

/// Why a request has no outputs. Fixed cases, and nothing else: a run's own
/// errors are ONNX Runtime's text, which is the model's to shape and not for a
/// round to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Failure {
    #[error("the coprocess has no such model")]
    NoModel,
    #[error("the inputs are not the model's")]
    Inputs,
    #[error("the model did not run")]
    Run,
}

/// How many elements `dims` hold, if that can be counted.
fn elements(dims: &[u64]) -> Option<u64> {
    dims.iter().try_fold(1u64, |n, &d| n.checked_mul(d))
}

fn dims<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
    at_most(deserializer, MAX_RANK as usize)
}

fn tensors<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Tensor>, D::Error> {
    at_most(deserializer, MAX_TENSORS as usize)
}
