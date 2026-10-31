//! A vendor's graph, checked and readied for ONNX Runtime.
//!
//! A model is the graph, `<name>.onnx`, and — when its weights are large — the
//! data file beside it, `<name>.onnx.data`: ONNX's own external-data format,
//! the graph's tensors pointing into the file by offset and length. [`check`]
//! reads the graph, refuses what could reach past computation, and gives the
//! graph back as ONNX Runtime is to be handed it: each tensor in the data file
//! taken out of the initializers and made a graph input, which the caller fills
//! with a view of the mapped file. Weights are read in place, never copied, and
//! shared by every round that runs the model.
//!
//! Refused, and why:
//! - a field ONNX does not define, in any message that holds tensors, graphs or
//!   functions — the model's, a graph's, a node's, an attribute's, a tensor's,
//!   a function's. What this check does not read, ONNX Runtime is never handed:
//!   every field it reads, the check has read first;
//! - a tensor whose data lies anywhere but the model's data file, inside it.
//!   ONNX Runtime reads a tensor that names a file from that file by its path,
//!   and one that names `*/_ORT_MEM_ADDR_/*` from the memory at its offset.
//!   None of these reaches ONNX Runtime: the graph it is handed points nowhere
//!   at all;
//! - such a tensor anywhere but the graph's own initializers: in a node's
//!   attribute, in a subgraph, in a function or the values its attributes take
//!   where a node gives none;
//! - sparse tensors, whose densifying reads such a file too — the runtime is
//!   built without them — and training information, graphs inference never
//!   runs;
//! - an operator of a domain the runtime has no operators for;
//! - inputs and outputs that are not tensors of a numeric type: what a round
//!   passes. Strings are not one — the runtime is built without them — nor
//!   `bool`.
//!
//! Everything else is allowed. Every operator is computation, control flow and
//! a model's own functions included, and a dimension may be named rather than
//! fixed: what bounds a run is the size of its input and the memory of the
//! round it runs in.

use std::collections::HashSet;

use prost::Message;

use crate::onnx::{
    Attribute, Dimension, DimensionValue, EXTERNAL, Graph, Model, Node, Shape, Tensor, TensorType,
    Type, TypeValue, ValueInfo,
};
use crate::wire;

#[cfg(test)]
mod tests;

/// The largest graph taken. What it holds inline — small weights, constants —
/// ONNX Runtime copies into every session, so every round, and larger weights
/// belong in the data file.
pub const MAX_GRAPH_BYTES: usize = 32 << 20;

/// The operator domains the runtime has operators for: the standard set
/// (named `""` or `ai.onnx`), traditional ML, and ONNX Runtime's own. A
/// model's functions add theirs.
const DOMAINS: [&str; 4] = ["", "ai.onnx", "ai.onnx.ml", "com.microsoft"];

/// `ModelProto.graph`, `GraphProto.initializer` and `GraphProto.input`: the
/// fields the rewrite touches.
const MODEL_GRAPH: u32 = 7;
const GRAPH_INITIALIZER: u32 = 5;
const GRAPH_INPUT: u32 = 11;

/// The data file a model's weights lie in: the name its tensors must give as
/// their location, and its length. Without a name, the file is the one the
/// first tensor names, and every other is held to that — for whoever has the
/// file but not its name.
#[derive(Clone, Copy, Debug)]
pub struct DataFile<'a> {
    pub name: Option<&'a str>,
    pub len: u64,
}

/// A graph checked, and readied for ONNX Runtime.
#[derive(Debug)]
pub struct Checked {
    /// What a run is given, in the graph's order.
    pub inputs: Vec<Port>,
    /// What a run gives back, in the graph's order.
    pub outputs: Vec<Port>,
    /// The graph inputs the data file fills, in the graph's order.
    pub weights: Vec<Weight>,
    /// The graph as ONNX Runtime is handed it.
    pub graph: Vec<u8>,
}

/// An input or output of a graph: its element type, and the shape it declares
/// — `None` where it declares none, and any shape goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    pub element: Element,
    pub dims: Option<Vec<Dim>>,
}

/// One dimension of a declared shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dim {
    /// This size and no other.
    Fixed(u64),
    /// Any size, named; ONNX Runtime holds every use of the name to one size.
    Named(String),
    /// Any size.
    Free,
}

/// A graph input the data file fills: its tensor's bytes at `offset`, `len`
/// long — exactly what its type and dimensions hold — and aligned to its
/// element, so they are read as elements where they lie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Weight {
    pub name: String,
    pub element: Element,
    pub dims: Vec<u64>,
    pub offset: u64,
    pub len: u64,
}

/// The element types a tensor of a model is of — a weight read in place, an
/// input or an output: those every bit pattern is a value of. A `bool` is not
/// one, nor a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Element {
    F32,
    F64,
    F16,
    Bf16,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
}

impl Element {
    /// Every element type.
    pub const ALL: [Element; 12] = [
        Element::F32,
        Element::F64,
        Element::F16,
        Element::Bf16,
        Element::I8,
        Element::U8,
        Element::I16,
        Element::U16,
        Element::I32,
        Element::U32,
        Element::I64,
        Element::U64,
    ];

    /// The element of ONNX's `TensorProto.DataType` code, if it is one.
    pub fn of(data_type: i32) -> Option<Element> {
        Some(match data_type {
            1 => Element::F32,
            2 => Element::U8,
            3 => Element::I8,
            4 => Element::U16,
            5 => Element::I16,
            6 => Element::I32,
            7 => Element::I64,
            10 => Element::F16,
            11 => Element::F64,
            12 => Element::U32,
            13 => Element::U64,
            16 => Element::Bf16,
            _ => return None,
        })
    }

    /// Its name: what the host's tensor of it is named after, `tensor-<name>`.
    pub fn name(self) -> &'static str {
        match self {
            Element::F32 => "f32",
            Element::F64 => "f64",
            Element::F16 => "f16",
            Element::Bf16 => "bf16",
            Element::I8 => "i8",
            Element::U8 => "u8",
            Element::I16 => "i16",
            Element::U16 => "u16",
            Element::I32 => "i32",
            Element::U32 => "u32",
            Element::I64 => "i64",
            Element::U64 => "u64",
        }
    }

    /// The element its name names.
    pub fn named(name: &str) -> Option<Element> {
        Element::ALL.into_iter().find(|e| e.name() == name)
    }

    /// Its `TensorProto.DataType` code.
    pub fn code(self) -> i32 {
        match self {
            Element::F32 => 1,
            Element::U8 => 2,
            Element::I8 => 3,
            Element::U16 => 4,
            Element::I16 => 5,
            Element::I32 => 6,
            Element::I64 => 7,
            Element::F16 => 10,
            Element::F64 => 11,
            Element::U32 => 12,
            Element::U64 => 13,
            Element::Bf16 => 16,
        }
    }

    /// Its size in bytes, which is also the alignment it is read at.
    pub fn size(self) -> u64 {
        match self {
            Element::I8 | Element::U8 => 1,
            Element::F16 | Element::Bf16 | Element::I16 | Element::U16 => 2,
            Element::F32 | Element::I32 | Element::U32 => 4,
            Element::F64 | Element::I64 | Element::U64 => 8,
        }
    }
}

/// Why a graph is refused. Each names what it is about, for whoever made the
/// model to find.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the graph is {0} bytes and at most {max} are taken; large weights belong in the data file", max = MAX_GRAPH_BYTES)]
    TooLarge(usize),
    #[error("the graph is not an ONNX model")]
    Malformed,
    #[error("a {0} carries field {1}, which ONNX does not define for it")]
    Unknown(&'static str, u32),
    #[error("the model has no graph")]
    NoGraph,
    #[error("the model carries training information")]
    Training,
    #[error("a `{op}` node is of domain `{domain}`, which the runtime has no operators for")]
    Domain { domain: String, op: String },
    #[error("the model holds a sparse tensor")]
    Sparse,
    #[error("tensor `{0}` keeps its data outside the graph, and only the graph's initializers may")]
    NotInitializer(String),
    #[error("tensor `{0}` points into a data file, and the model has none")]
    NoDataFile(String),
    #[error("tensor `{tensor}` names `{location}` for its data, which is not a file's name")]
    NotAFile { tensor: String, location: String },
    #[error(
        "tensor `{tensor}` names `{location}` for its data, and the model's data file is `{expected}`"
    )]
    Location {
        tensor: String,
        location: String,
        expected: String,
    },
    #[error("tensor `{tensor}`: `{key}` is not an external-data field, or is given twice")]
    Key { tensor: String, key: String },
    #[error("tensor `{0}`: its offset or length is not a number")]
    Number(String),
    #[error("tensor `{tensor}`: elements of type {data_type} are not read from a data file")]
    Element { tensor: String, data_type: i32 },
    #[error("tensor `{0}`: its length is not what its type and dimensions hold")]
    Length(String),
    #[error("tensor `{0}`: its offset is not a multiple of its element's size")]
    Unaligned(String),
    #[error("tensor `{0}` reaches past the end of the data file")]
    OutOfFile(String),
    #[error("`{0}` names two initializers, or two inputs")]
    Duplicate(String),
    #[error("{0} `{1}` is not a tensor of a numeric type")]
    NotNumeric(&'static str, String),
}

/// Check the model `graph`, its weights in `data`, and ready it for ONNX
/// Runtime. See the module.
pub fn check(graph: &[u8], data: Option<DataFile<'_>>) -> Result<Checked, Refusal> {
    if graph.len() > MAX_GRAPH_BYTES {
        return Err(Refusal::TooLarge(graph.len()));
    }
    let model = Model::decode(graph).map_err(|_| Refusal::Malformed)?;
    known(graph, Kind::Model, 0)?;
    if !model.training_info.is_empty() {
        return Err(Refusal::Training);
    }
    let top = model.graph.as_ref().ok_or(Refusal::NoGraph)?;

    let mut domains: HashSet<&str> = DOMAINS.into_iter().collect();
    domains.extend(model.functions.iter().map(|f| f.domain.as_str()));
    for function in &model.functions {
        nodes(&function.node, &domains)?;
        for attribute in &function.attribute_proto {
            within(attribute, &domains)?;
        }
    }
    if !top.sparse_initializer.is_empty() {
        return Err(Refusal::Sparse);
    }
    nodes(&top.node, &domains)?;

    // The graph's own initializers, the one place a tensor may point into the
    // data file.
    let mut initializers = HashSet::new();
    let mut weights = Vec::new();
    let mut file = data.map(|data| (data.name.map(str::to_owned), data.len));
    for tensor in &top.initializer {
        if !initializers.insert(tensor.name.as_str()) {
            return Err(Refusal::Duplicate(tensor.name.clone()));
        }
        if external(tensor) {
            weights.push(weight(tensor, file.as_mut())?);
        }
    }

    // An input an initializer also names has the initializer for its value
    // unless the caller gives another: it is the graph's, not the caller's.
    let mut names = HashSet::new();
    let mut inputs = Vec::new();
    for input in &top.input {
        if !names.insert(input.name.as_str()) {
            return Err(Refusal::Duplicate(input.name.clone()));
        }
        if !initializers.contains(input.name.as_str()) {
            inputs.push(port("input", input)?);
        }
    }
    let outputs = top
        .output
        .iter()
        .map(|output| port("output", output))
        .collect::<Result<_, _>>()?;

    let taken: HashSet<&str> = weights.iter().map(|w| w.name.as_str()).collect();
    let added: Vec<ValueInfo> = weights
        .iter()
        .filter(|w| !names.contains(w.name.as_str()))
        .map(declared)
        .collect();
    let graph = rewrite(graph, &taken, &added)?;
    Ok(Checked {
        inputs,
        outputs,
        weights,
        graph,
    })
}

/// A message of the model that holds tensors, graphs or functions, or holds one
/// that does.
#[derive(Clone, Copy)]
enum Kind {
    Model,
    Graph,
    Node,
    Attribute,
    Tensor,
    Function,
}

impl Kind {
    /// What a refusal calls it.
    fn name(self) -> &'static str {
        match self {
            Kind::Model => "model",
            Kind::Graph => "graph",
            Kind::Node => "node",
            Kind::Attribute => "attribute",
            Kind::Tensor => "tensor",
            Kind::Function => "function",
        }
    }

    /// The fields ONNX defines for it — those of ONNX 1.22, the release ONNX
    /// Runtime is built with — and the ones among them that hold a message of
    /// these kinds. Every other field it defines holds a value, or a message
    /// that holds no tensor.
    fn fields(self) -> (&'static [u32], &'static [(u32, Kind)]) {
        match self {
            Kind::Model => (
                &[1, 2, 3, 4, 5, 6, 7, 8, 14, 20, 25, 26],
                &[(7, Kind::Graph), (25, Kind::Function)],
            ),
            Kind::Graph => (
                &[1, 2, 5, 10, 11, 12, 13, 14, 15, 16],
                &[(1, Kind::Node), (5, Kind::Tensor)],
            ),
            Kind::Node => (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], &[(5, Kind::Attribute)]),
            Kind::Attribute => (
                &[
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 20, 21, 22, 23,
                ],
                &[
                    (5, Kind::Tensor),
                    (6, Kind::Graph),
                    (10, Kind::Tensor),
                    (11, Kind::Graph),
                ],
            ),
            Kind::Tensor => (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16], &[]),
            Kind::Function => (
                &[1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
                &[(7, Kind::Node), (11, Kind::Attribute)],
            ),
        }
    }
}

/// The deepest [`known`] follows messages into one another: past what decoding
/// the model allows, so it reads every model that decodes, and bounded all the
/// same.
const MAX_DEPTH: u32 = 128;

/// Every field of `message`, a `kind` at `depth`, one ONNX defines for it, and
/// so on down through the messages it holds of these kinds.
fn known(message: &[u8], kind: Kind, depth: u32) -> Result<(), Refusal> {
    if depth > MAX_DEPTH {
        return Err(Refusal::Malformed);
    }
    let (fields, nested) = kind.fields();
    for field in wire::fields(message) {
        let field = field.map_err(|_| Refusal::Malformed)?;
        if !fields.contains(&field.number) {
            return Err(Refusal::Unknown(kind.name(), field.number));
        }
        if let Some((_, inner)) = nested.iter().find(|(number, _)| *number == field.number) {
            known(field.payload.ok_or(Refusal::Malformed)?, *inner, depth + 1)?;
        }
    }
    Ok(())
}

/// Check `nodes`, and the graphs and tensors their attributes hold: each node of
/// a domain in `domains`, and no tensor whose data lies outside the graph.
fn nodes(nodes: &[Node], domains: &HashSet<&str>) -> Result<(), Refusal> {
    for node in nodes {
        if !domains.contains(node.domain.as_str()) {
            return Err(Refusal::Domain {
                domain: node.domain.clone(),
                op: node.op_type.clone(),
            });
        }
        for attribute in &node.attribute {
            within(attribute, domains)?;
        }
    }
    Ok(())
}

fn within(attribute: &Attribute, domains: &HashSet<&str>) -> Result<(), Refusal> {
    if attribute.sparse_tensor.is_some() || !attribute.sparse_tensors.is_empty() {
        return Err(Refusal::Sparse);
    }
    for tensor in attribute.t.iter().chain(&attribute.tensors) {
        inline(tensor)?;
    }
    for graph in attribute.g.iter().map(|g| &**g).chain(&attribute.graphs) {
        subgraph(graph, domains)?;
    }
    Ok(())
}

/// A graph within a node: nothing of it may lie outside it, its initializers
/// included.
fn subgraph(graph: &Graph, domains: &HashSet<&str>) -> Result<(), Refusal> {
    if !graph.sparse_initializer.is_empty() {
        return Err(Refusal::Sparse);
    }
    for tensor in &graph.initializer {
        inline(tensor)?;
    }
    nodes(&graph.node, domains)
}

fn inline(tensor: &Tensor) -> Result<(), Refusal> {
    if external(tensor) {
        return Err(Refusal::NotInitializer(tensor.name.clone()));
    }
    Ok(())
}

/// Whether `tensor` says its data lies elsewhere — by its location, or by any
/// external-data field at all.
fn external(tensor: &Tensor) -> bool {
    tensor.data_location == EXTERNAL || !tensor.external_data.is_empty()
}

/// The weight `tensor` points to in the data `file` — its name, when known or
/// once the first tensor gave it, and its length — held to the file: named for
/// it, inside it, as long as its type and dimensions say, aligned to its
/// element.
fn weight(tensor: &Tensor, file: Option<&mut (Option<String>, u64)>) -> Result<Weight, Refusal> {
    let name = || tensor.name.clone();
    let (mut location, mut offset, mut len) = (None, None, None);
    let mut seen = HashSet::new();
    for entry in &tensor.external_data {
        let key = entry.key.as_str();
        let refused = || Refusal::Key {
            tensor: name(),
            key: key.into(),
        };
        if !seen.insert(key) {
            return Err(refused());
        }
        let number = || {
            entry
                .value
                .parse::<u64>()
                .map_err(|_| Refusal::Number(name()))
        };
        match key {
            "location" => location = Some(entry.value.as_str()),
            "offset" => offset = Some(number()?),
            "length" => len = Some(number()?),
            "checksum" => {}
            _ => return Err(refused()),
        }
    }
    let (expected, data_len) = file.ok_or_else(|| Refusal::NoDataFile(name()))?;
    let location = location.unwrap_or_default();
    let plain = !matches!(location, "" | "." | "..") && !location.contains(['/', '\\', '\0']);
    if !plain {
        return Err(Refusal::NotAFile {
            tensor: name(),
            location: location.into(),
        });
    }
    let expected = expected.get_or_insert_with(|| location.to_owned());
    if location != expected {
        return Err(Refusal::Location {
            tensor: name(),
            location: location.into(),
            expected: expected.clone(),
        });
    }
    let data_len = *data_len;
    let element = Element::of(tensor.data_type).ok_or_else(|| Refusal::Element {
        tensor: name(),
        data_type: tensor.data_type,
    })?;
    let dims = tensor
        .dims
        .iter()
        .map(|&d| u64::try_from(d).map_err(|_| Refusal::Length(name())))
        .collect::<Result<Vec<_>, _>>()?;
    let size = dims
        .iter()
        .try_fold(element.size(), |size, &d| size.checked_mul(d))
        .ok_or_else(|| Refusal::Length(name()))?;
    if len.is_some_and(|len| len != size) {
        return Err(Refusal::Length(name()));
    }
    let offset = offset.unwrap_or(0);
    if !offset.is_multiple_of(element.size()) {
        return Err(Refusal::Unaligned(name()));
    }
    if offset.checked_add(size).is_none_or(|end| end > data_len) {
        return Err(Refusal::OutOfFile(name()));
    }
    Ok(Weight {
        name: name(),
        element,
        dims,
        offset,
        len: size,
    })
}

/// An input or output of the graph, held to what a round passes: a tensor of
/// one of the element types.
fn port(what: &'static str, value: &ValueInfo) -> Result<Port, Refusal> {
    let not_numeric = || Refusal::NotNumeric(what, value.name.clone());
    let Some(Type {
        value: Some(TypeValue::Tensor(tensor)),
    }) = &value.r#type
    else {
        return Err(not_numeric());
    };
    let element = Element::of(tensor.elem_type).ok_or_else(not_numeric)?;
    let dims = tensor.shape.as_ref().map(|shape| {
        shape
            .dim
            .iter()
            .map(|dim| match &dim.value {
                Some(DimensionValue::Value(v)) => u64::try_from(*v).map_or(Dim::Free, Dim::Fixed),
                Some(DimensionValue::Param(name)) => Dim::Named(name.clone()),
                None => Dim::Free,
            })
            .collect()
    });
    Ok(Port {
        name: value.name.clone(),
        element,
        dims,
    })
}

/// The graph input `weight` becomes: its initializer's type and dimensions,
/// under its name. The dimensions were the initializer's own, so each fits
/// back.
fn declared(weight: &Weight) -> ValueInfo {
    ValueInfo {
        name: weight.name.clone(),
        r#type: Some(Type {
            value: Some(TypeValue::Tensor(TensorType {
                elem_type: weight.element.code(),
                shape: Some(Shape {
                    dim: weight
                        .dims
                        .iter()
                        .map(|&d| Dimension {
                            value: Some(DimensionValue::Value(d as i64)),
                        })
                        .collect(),
                }),
            })),
        }),
    }
}

/// `model` with the initializers named in `taken` left out of its graph and
/// `added` put in as inputs — every other byte as it was.
///
/// A message field given more than once is one message merged from them all,
/// and protobuf merges by concatenation: so every `graph` the model gives is
/// read as one, as ONNX Runtime and the check above read them.
fn rewrite(model: &[u8], taken: &HashSet<&str>, added: &[ValueInfo]) -> Result<Vec<u8>, Refusal> {
    let mut graph = Vec::new();
    let mut out = Vec::with_capacity(model.len());
    for field in wire::fields(model) {
        let field = field.map_err(|_| Refusal::Malformed)?;
        match field.payload {
            Some(payload) if field.number == MODEL_GRAPH => graph.extend_from_slice(payload),
            _ => out.extend_from_slice(field.raw),
        }
    }
    let mut rewritten = Vec::with_capacity(graph.len());
    for field in wire::fields(&graph) {
        let field = field.map_err(|_| Refusal::Malformed)?;
        if let Some(payload) = field.payload
            && field.number == GRAPH_INITIALIZER
        {
            let tensor = Tensor::decode(payload).map_err(|_| Refusal::Malformed)?;
            if taken.contains(tensor.name.as_str()) {
                continue;
            }
        }
        rewritten.extend_from_slice(field.raw);
    }
    for input in added {
        wire::put_delimited(&mut rewritten, GRAPH_INPUT, &input.encode_to_vec());
    }
    wire::put_delimited(&mut out, MODEL_GRAPH, &rewritten);
    Ok(out)
}
