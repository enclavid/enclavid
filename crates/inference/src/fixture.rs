//! Models made for the tests of the crates that check and run vendor graphs:
//! never for a build that ships.

use prost::Message;

use crate::onnx::{
    Dimension, DimensionValue, EXTERNAL, Entry, Graph, Model, Node, OperatorSet, Shape, Tensor,
    TensorType, Type, TypeValue, ValueInfo,
};

/// `y = x · W + b` over `x: [batch, 3]`, `batch` named: the graph, and the
/// data file — named `data` in the graph — holding `W: [3, 2]` then `b: [2]`,
/// as ONNX's own writer lays them out.
pub fn linear(data: &str, w: [[f32; 2]; 3], b: [f32; 2]) -> (Vec<u8>, Vec<u8>) {
    let dims = |dims: &[DimensionValue]| Shape {
        dim: dims
            .iter()
            .map(|d| Dimension {
                value: Some(d.clone()),
            })
            .collect(),
    };
    let port = |name: &str, last: i64| ValueInfo {
        name: name.into(),
        r#type: Some(Type {
            value: Some(TypeValue::Tensor(TensorType {
                elem_type: 1,
                shape: Some(dims(&[
                    DimensionValue::Param("batch".into()),
                    DimensionValue::Value(last),
                ])),
            })),
        }),
    };
    let weight = |name: &str, dims: &[i64], offset: usize, len: usize| Tensor {
        dims: dims.to_vec(),
        data_type: 1,
        name: name.into(),
        raw_data: Vec::new(),
        external_data: [
            ("location", data.to_owned()),
            ("offset", offset.to_string()),
            ("length", len.to_string()),
        ]
        .into_iter()
        .map(|(key, value)| Entry {
            key: key.into(),
            value,
        })
        .collect(),
        data_location: EXTERNAL,
    };
    let node = |op: &str, input: [&str; 2], output: &str| Node {
        input: input.iter().map(|s| (*s).into()).collect(),
        output: vec![output.into()],
        op_type: op.into(),
        domain: String::new(),
        attribute: Vec::new(),
    };
    let model = Model {
        ir_version: 8,
        opset_import: vec![OperatorSet {
            domain: String::new(),
            version: 17,
        }],
        graph: Some(Graph {
            node: vec![
                node("MatMul", ["x", "W"], "xw"),
                node("Add", ["xw", "b"], "y"),
            ],
            initializer: vec![weight("W", &[3, 2], 0, 24), weight("b", &[2], 24, 8)],
            sparse_initializer: Vec::new(),
            input: vec![port("x", 3)],
            output: vec![port("y", 2)],
        }),
        training_info: Vec::new(),
        functions: Vec::new(),
    };
    let file = w
        .iter()
        .flatten()
        .chain(&b)
        .flat_map(|v| v.to_le_bytes())
        .collect();
    (model.encode_to_vec(), file)
}

/// `x` as `f32`, from `x: [n]` of `u8`, `n` named: a graph whose input and
/// output are of different element types, with no data file.
pub fn widen() -> Vec<u8> {
    let port = |name: &str, elem_type: i32| ValueInfo {
        name: name.into(),
        r#type: Some(Type {
            value: Some(TypeValue::Tensor(TensorType {
                elem_type,
                shape: Some(Shape {
                    dim: vec![Dimension {
                        value: Some(DimensionValue::Param("n".into())),
                    }],
                }),
            })),
        }),
    };
    // What `CastLike` takes the type to cast to from: a scalar `f32`.
    let like = Tensor {
        dims: Vec::new(),
        data_type: 1,
        name: "like".into(),
        raw_data: 0f32.to_le_bytes().to_vec(),
        external_data: Vec::new(),
        data_location: 0,
    };
    Model {
        ir_version: 8,
        opset_import: vec![OperatorSet {
            domain: String::new(),
            version: 17,
        }],
        graph: Some(Graph {
            node: vec![Node {
                input: vec!["x".into(), "like".into()],
                output: vec!["y".into()],
                op_type: "CastLike".into(),
                domain: String::new(),
                attribute: Vec::new(),
            }],
            initializer: vec![like],
            sparse_initializer: Vec::new(),
            input: vec![port("x", 2)],
            output: vec![port("y", 1)],
        }),
        training_info: Vec::new(),
        functions: Vec::new(),
    }
    .encode_to_vec()
}

/// `a`, `b` and `a + b` back from `a` and `b` of any one shape: a graph of two
/// inputs and three outputs, with no weights and so no data file.
pub fn split() -> Vec<u8> {
    let port = |name: &str| ValueInfo {
        name: name.into(),
        r#type: Some(Type {
            value: Some(TypeValue::Tensor(TensorType {
                elem_type: 1,
                shape: None,
            })),
        }),
    };
    let node = |op: &str, input: &[&str], output: &str| Node {
        input: input.iter().map(|s| (*s).into()).collect(),
        output: vec![output.into()],
        op_type: op.into(),
        domain: String::new(),
        attribute: Vec::new(),
    };
    Model {
        ir_version: 8,
        opset_import: vec![OperatorSet {
            domain: String::new(),
            version: 17,
        }],
        graph: Some(Graph {
            node: vec![
                node("Identity", &["a"], "p"),
                node("Identity", &["b"], "q"),
                node("Add", &["a", "b"], "r"),
            ],
            initializer: Vec::new(),
            sparse_initializer: Vec::new(),
            input: vec![port("a"), port("b")],
            output: vec![port("p"), port("q"), port("r")],
        }),
        training_info: Vec::new(),
        functions: Vec::new(),
    }
    .encode_to_vec()
}
