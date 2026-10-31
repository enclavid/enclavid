//! The part of ONNX's `onnx.proto` a vendor's graph is checked by: where its
//! operators come from, where graphs nest in it, the graph's inputs and
//! outputs, and every place a tensor can say its data lies somewhere else.
//!
//! Field numbers are onnx 1.22's, the version ONNX Runtime parses the graph
//! with. A field not named here is skipped when a model is read, and nothing
//! read here is written back: the graph ONNX Runtime is given is the original
//! bytes spliced (see `wire`), so a field this subset does not know stays as
//! it was. A `oneof` is named whole, every member, so that the member the last
//! occurrence sets is the one read here — as it is the one ONNX Runtime reads.
//!
//! Types are written to as well, by the rewrite (a graph input of its own for
//! each weight) and by tests, which build whole models out of them.

/// `ModelProto`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Model {
    #[prost(int64, tag = "1")]
    pub ir_version: i64,
    #[prost(message, repeated, tag = "8")]
    pub opset_import: Vec<OperatorSet>,
    #[prost(message, optional, tag = "7")]
    pub graph: Option<Graph>,
    /// Graphs inference never runs; a model that has any is refused, so they
    /// are only counted.
    #[prost(bytes = "vec", repeated, tag = "20")]
    pub training_info: Vec<Vec<u8>>,
    #[prost(message, repeated, tag = "25")]
    pub functions: Vec<Function>,
}

/// `OperatorSetIdProto`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct OperatorSet {
    #[prost(string, tag = "1")]
    pub domain: String,
    #[prost(int64, tag = "2")]
    pub version: i64,
}

/// `GraphProto`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Graph {
    #[prost(message, repeated, tag = "1")]
    pub node: Vec<Node>,
    #[prost(message, repeated, tag = "5")]
    pub initializer: Vec<Tensor>,
    /// Refused wherever it appears, so only counted.
    #[prost(bytes = "vec", repeated, tag = "15")]
    pub sparse_initializer: Vec<Vec<u8>>,
    #[prost(message, repeated, tag = "11")]
    pub input: Vec<ValueInfo>,
    #[prost(message, repeated, tag = "12")]
    pub output: Vec<ValueInfo>,
}

/// `NodeProto`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Node {
    #[prost(string, repeated, tag = "1")]
    pub input: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    pub output: Vec<String>,
    #[prost(string, tag = "4")]
    pub op_type: String,
    #[prost(string, tag = "7")]
    pub domain: String,
    #[prost(message, repeated, tag = "5")]
    pub attribute: Vec<Attribute>,
}

/// `AttributeProto`: the members that hold a tensor or a graph.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Attribute {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, optional, tag = "5")]
    pub t: Option<Tensor>,
    #[prost(message, optional, boxed, tag = "6")]
    pub g: Option<Box<Graph>>,
    #[prost(message, repeated, tag = "10")]
    pub tensors: Vec<Tensor>,
    #[prost(message, repeated, tag = "11")]
    pub graphs: Vec<Graph>,
    /// Refused wherever it appears, so only seen.
    #[prost(bytes = "vec", optional, tag = "22")]
    pub sparse_tensor: Option<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "23")]
    pub sparse_tensors: Vec<Vec<u8>>,
}

/// `TensorProto`: what it is, and where its data lies. The data itself, inline
/// in one of half a dozen fields, is not read.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Tensor {
    #[prost(int64, repeated, tag = "1")]
    pub dims: Vec<i64>,
    #[prost(int32, tag = "2")]
    pub data_type: i32,
    #[prost(string, tag = "8")]
    pub name: String,
    /// Only written by tests, which build tensors with their data inline.
    #[prost(bytes = "vec", tag = "9")]
    pub raw_data: Vec<u8>,
    #[prost(message, repeated, tag = "13")]
    pub external_data: Vec<Entry>,
    #[prost(int32, tag = "14")]
    pub data_location: i32,
}

/// `TensorProto.DataLocation.EXTERNAL`.
pub(crate) const EXTERNAL: i32 = 1;

/// `StringStringEntryProto`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Entry {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

/// `ValueInfoProto`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct ValueInfo {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, optional, tag = "2")]
    pub r#type: Option<Type>,
}

/// `TypeProto`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Type {
    #[prost(oneof = "TypeValue", tags = "1, 4, 5, 8, 9")]
    pub value: Option<TypeValue>,
}

/// `TypeProto.value`: a tensor, or anything else — a sequence, a map, a sparse
/// tensor, an optional.
#[derive(Clone, PartialEq, prost::Oneof)]
pub(crate) enum TypeValue {
    #[prost(message, tag = "1")]
    Tensor(TensorType),
    #[prost(bytes = "vec", tag = "4")]
    Sequence(Vec<u8>),
    #[prost(bytes = "vec", tag = "5")]
    Map(Vec<u8>),
    #[prost(bytes = "vec", tag = "8")]
    SparseTensor(Vec<u8>),
    #[prost(bytes = "vec", tag = "9")]
    Optional(Vec<u8>),
}

/// `TypeProto.Tensor`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct TensorType {
    #[prost(int32, tag = "1")]
    pub elem_type: i32,
    #[prost(message, optional, tag = "2")]
    pub shape: Option<Shape>,
}

/// `TensorShapeProto`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Shape {
    #[prost(message, repeated, tag = "1")]
    pub dim: Vec<Dimension>,
}

/// `TensorShapeProto.Dimension`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Dimension {
    #[prost(oneof = "DimensionValue", tags = "1, 2")]
    pub value: Option<DimensionValue>,
}

/// `TensorShapeProto.Dimension.value`.
#[derive(Clone, PartialEq, prost::Oneof)]
pub(crate) enum DimensionValue {
    #[prost(int64, tag = "1")]
    Value(i64),
    #[prost(string, tag = "2")]
    Param(String),
}

/// `FunctionProto`: a model's own operator, made of other operators, and the
/// values its attributes take where a node gives none.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Function {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, repeated, tag = "7")]
    pub node: Vec<Node>,
    #[prost(string, tag = "10")]
    pub domain: String,
    #[prost(message, repeated, tag = "11")]
    pub attribute_proto: Vec<Attribute>,
}
