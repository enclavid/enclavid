use prost::Message;

use super::*;
use crate::onnx::{Entry, Function, OperatorSet};

/// `TensorProto.DataType`: `FLOAT`, `UINT8`, `STRING`, `INT64`, `BOOL`.
const FLOAT: i32 = 1;
const UINT8: i32 = 2;
const INT64: i32 = 7;
const STRING: i32 = 8;
const BOOL: i32 = 9;

const DATA: &str = "model.onnx.data";
const FILE: DataFile<'static> = DataFile {
    name: Some(DATA),
    len: 32,
};

fn shape(dims: &[i64]) -> Option<Shape> {
    Some(Shape {
        dim: dims
            .iter()
            .map(|&d| Dimension {
                value: Some(DimensionValue::Value(d)),
            })
            .collect(),
    })
}

fn value(name: &str, elem_type: i32, dims: &[i64]) -> ValueInfo {
    ValueInfo {
        name: name.into(),
        r#type: Some(Type {
            value: Some(TypeValue::Tensor(TensorType {
                elem_type,
                shape: shape(dims),
            })),
        }),
    }
}

fn external(name: &str, data_type: i32, dims: &[i64], entries: &[(&str, &str)]) -> Tensor {
    Tensor {
        dims: dims.to_vec(),
        data_type,
        name: name.into(),
        raw_data: Vec::new(),
        external_data: entries
            .iter()
            .map(|(key, value)| Entry {
                key: (*key).into(),
                value: (*value).into(),
            })
            .collect(),
        data_location: EXTERNAL,
    }
}

/// An f32 tensor in the data file at `offset`, as ONNX's own writer puts it.
fn at(name: &str, dims: &[i64], offset: u64) -> Tensor {
    let len = 4 * dims.iter().product::<i64>();
    external(
        name,
        FLOAT,
        dims,
        &[
            ("location", DATA),
            ("offset", &offset.to_string()),
            ("length", &len.to_string()),
        ],
    )
}

fn inline(name: &str, dims: &[i64]) -> Tensor {
    let n = dims.iter().product::<i64>() as usize;
    Tensor {
        dims: dims.to_vec(),
        data_type: FLOAT,
        name: name.into(),
        raw_data: vec![0; 4 * n],
        external_data: Vec::new(),
        data_location: 0,
    }
}

fn node(op: &str, inputs: &[&str], outputs: &[&str]) -> Node {
    Node {
        input: inputs.iter().map(|s| (*s).into()).collect(),
        output: outputs.iter().map(|s| (*s).into()).collect(),
        op_type: op.into(),
        domain: String::new(),
        attribute: Vec::new(),
    }
}

/// `y = x · W + b`, `W` and `b` in the data file.
fn linear() -> Graph {
    Graph {
        node: vec![
            node("MatMul", &["x", "W"], &["xw"]),
            node("Add", &["xw", "b"], &["y"]),
        ],
        initializer: vec![at("W", &[3, 2], 0), at("b", &[2], 24)],
        sparse_initializer: Vec::new(),
        input: vec![value("x", FLOAT, &[1, 3])],
        output: vec![value("y", FLOAT, &[1, 2])],
    }
}

fn model(graph: Graph) -> Model {
    Model {
        ir_version: 8,
        opset_import: vec![OperatorSet {
            domain: String::new(),
            version: 17,
        }],
        graph: Some(graph),
        training_info: Vec::new(),
        functions: Vec::new(),
    }
}

fn checked(model: &Model) -> Result<Checked, Refusal> {
    check(&model.encode_to_vec(), Some(FILE))
}

fn names(values: &[ValueInfo]) -> Vec<&str> {
    values.iter().map(|v| v.name.as_str()).collect()
}

/// The weights in the data file leave the initializers and become inputs of
/// their own type and shape; what the caller gives is what it gave before.
#[test]
fn weights_in_the_data_file_become_inputs() {
    let checked = checked(&model(linear())).unwrap();
    assert_eq!(
        checked.inputs,
        [Port {
            name: "x".into(),
            element: Element::F32,
            dims: Some(vec![Dim::Fixed(1), Dim::Fixed(3)]),
        }]
    );
    assert_eq!(names_of(&checked.outputs), ["y"]);
    assert_eq!(
        checked.weights,
        [
            Weight {
                name: "W".into(),
                element: Element::F32,
                dims: vec![3, 2],
                offset: 0,
                len: 24,
            },
            Weight {
                name: "b".into(),
                element: Element::F32,
                dims: vec![2],
                offset: 24,
                len: 8,
            },
        ]
    );

    let ready = Model::decode(&checked.graph[..]).unwrap().graph.unwrap();
    assert!(ready.initializer.is_empty());
    assert_eq!(names(&ready.input), ["x", "W", "b"]);
    assert_eq!(ready.input[1], value("W", FLOAT, &[3, 2]));
    assert_eq!(ready.node, linear().node);
}

fn names_of(ports: &[Port]) -> Vec<&str> {
    ports.iter().map(|p| p.name.as_str()).collect()
}

/// A field the check does not know — the model's producer, the graph's
/// documentation — reaches ONNX Runtime byte for byte.
#[test]
fn what_the_check_does_not_know_survives() {
    let mut graph = linear().encode_to_vec();
    wire::put_delimited(&mut graph, 10, b"graph documentation");
    let bytes = model(Graph::default()).encode_to_vec();
    let mut with_graph = Vec::new();
    // The model's own fields, without the empty graph the encoding gave it,
    // then the producer and the graph.
    for field in wire::fields(&bytes) {
        let field = field.unwrap();
        if field.number != MODEL_GRAPH {
            with_graph.extend_from_slice(field.raw);
        }
    }
    wire::put_delimited(&mut with_graph, 2, b"vendor tool");
    wire::put_delimited(&mut with_graph, MODEL_GRAPH, &graph);

    let ready = check(&with_graph, Some(FILE)).unwrap().graph;
    let holds = |needle: &[u8]| ready.windows(needle.len()).any(|w| w == needle);
    assert!(holds(b"vendor tool") && holds(b"graph documentation"));
}

/// An initializer whose data is inline stays one: only the data file's
/// tensors become inputs.
#[test]
fn an_inline_initializer_stays() {
    let mut graph = linear();
    graph.initializer.push(inline("scale", &[2]));
    let checked = checked(&model(graph)).unwrap();
    assert_eq!(checked.weights.len(), 2);
    let ready = Model::decode(&checked.graph[..]).unwrap().graph.unwrap();
    assert_eq!(ready.initializer, [inline("scale", &[2])]);
}

/// A graph given in two parts is one graph, merged — as ONNX Runtime reads it:
/// the weights in the second part are found and taken out all the same.
#[test]
fn a_graph_given_twice_is_one_graph() {
    let whole = linear();
    let first = Graph {
        node: whole.node.clone(),
        input: whole.input.clone(),
        ..Graph::default()
    };
    let second = Graph {
        initializer: whole.initializer.clone(),
        output: whole.output.clone(),
        ..Graph::default()
    };
    let mut bytes = Vec::new();
    for field in wire::fields(&model(Graph::default()).encode_to_vec()) {
        let field = field.unwrap();
        if field.number != MODEL_GRAPH {
            bytes.extend_from_slice(field.raw);
        }
    }
    wire::put_delimited(&mut bytes, MODEL_GRAPH, &first.encode_to_vec());
    wire::put_delimited(&mut bytes, MODEL_GRAPH, &second.encode_to_vec());

    let checked = check(&bytes, Some(FILE)).unwrap();
    assert_eq!(checked.weights.len(), 2);
    let ready = Model::decode(&checked.graph[..]).unwrap().graph.unwrap();
    assert!(ready.initializer.is_empty());
    assert_eq!(names(&ready.input), ["x", "W", "b"]);
}

/// An input an initializer names is the graph's: the caller does not give it,
/// and becoming a weight adds no second input of the name.
#[test]
fn an_input_an_initializer_names_is_the_graphs() {
    let mut graph = linear();
    graph.input.push(value("W", FLOAT, &[3, 2]));
    let checked = checked(&model(graph)).unwrap();
    assert_eq!(names_of(&checked.inputs), ["x"]);
    let ready = Model::decode(&checked.graph[..]).unwrap().graph.unwrap();
    assert_eq!(names(&ready.input), ["x", "W", "b"]);
}

/// A dimension is fixed, named or free, and a port that declares no shape
/// takes any.
#[test]
fn dimensions_are_fixed_named_or_free() {
    let mut graph = linear();
    graph.input = vec![ValueInfo {
        name: "x".into(),
        r#type: Some(Type {
            value: Some(TypeValue::Tensor(TensorType {
                elem_type: FLOAT,
                shape: Some(Shape {
                    dim: vec![
                        Dimension {
                            value: Some(DimensionValue::Value(1)),
                        },
                        Dimension {
                            value: Some(DimensionValue::Param("width".into())),
                        },
                        Dimension { value: None },
                    ],
                }),
            })),
        }),
    }];
    graph.output[0].r#type = Some(Type {
        value: Some(TypeValue::Tensor(TensorType {
            elem_type: FLOAT,
            shape: None,
        })),
    });
    let checked = checked(&model(graph)).unwrap();
    assert_eq!(
        checked.inputs[0].dims,
        Some(vec![Dim::Fixed(1), Dim::Named("width".into()), Dim::Free])
    );
    assert_eq!(checked.outputs[0].dims, None);
}

/// A model's own functions add their domain; any other domain is refused.
#[test]
fn a_domain_is_the_runtimes_or_the_models_own() {
    let mut graph = linear();
    graph.node.push(Node {
        domain: "vendor.ops".into(),
        ..node("Fused", &["y"], &["z"])
    });
    assert_eq!(
        checked(&model(graph.clone())).unwrap_err(),
        Refusal::Domain {
            domain: "vendor.ops".into(),
            op: "Fused".into()
        }
    );
    let mut with_function = model(graph);
    with_function.functions.push(Function {
        name: "Fused".into(),
        node: vec![node("Relu", &["a"], &["b"])],
        domain: "vendor.ops".into(),
    });
    assert!(checked(&with_function).is_ok());
}

/// A tensor anywhere but the initializers that says its data lies elsewhere
/// is refused, however deep: a constant, a subgraph's initializer, a constant
/// inside a subgraph.
#[test]
fn a_tensor_outside_the_initializers_keeps_its_data_inline() {
    let constant = |tensor: Tensor| Node {
        attribute: vec![Attribute {
            name: "value".into(),
            t: Some(tensor),
            ..Attribute::default()
        }],
        ..node("Constant", &[], &["c"])
    };
    let branch = |graph: Graph| Node {
        attribute: vec![Attribute {
            name: "then_branch".into(),
            g: Some(Box::new(graph)),
            ..Attribute::default()
        }],
        ..node("If", &["cond"], &["out"])
    };
    let in_subgraph = Graph {
        initializer: vec![at("hidden", &[2], 0)],
        ..Graph::default()
    };
    let deeper = Graph {
        node: vec![constant(at("deep", &[2], 0))],
        ..Graph::default()
    };
    for (node, tensor) in [
        (constant(at("c", &[2], 0)), "c"),
        (branch(in_subgraph), "hidden"),
        (branch(deeper), "deep"),
    ] {
        let mut graph = linear();
        graph.node.push(node);
        assert_eq!(
            checked(&model(graph)).unwrap_err(),
            Refusal::NotInitializer(tensor.into())
        );
    }
}

/// Every way a weight's place in the data file can be wrong, refused by name.
#[test]
fn a_weight_lies_in_the_data_file_or_is_refused() {
    let w = |entries: &[(&str, &str)]| external("W", FLOAT, &[3, 2], entries);
    let cases = [
        (
            w(&[("location", "*/_ORT_MEM_ADDR_/*"), ("offset", "4096")]),
            Refusal::NotAFile {
                tensor: "W".into(),
                location: "*/_ORT_MEM_ADDR_/*".into(),
            },
        ),
        (
            w(&[("location", "../../etc/passwd")]),
            Refusal::NotAFile {
                tensor: "W".into(),
                location: "../../etc/passwd".into(),
            },
        ),
        (
            w(&[("offset", "0")]),
            Refusal::NotAFile {
                tensor: "W".into(),
                location: String::new(),
            },
        ),
        (
            w(&[("location", "other.onnx.data")]),
            Refusal::Location {
                tensor: "W".into(),
                location: "other.onnx.data".into(),
                expected: DATA.into(),
            },
        ),
        (
            w(&[("location", DATA), ("offset", "16")]),
            Refusal::OutOfFile("W".into()),
        ),
        (
            w(&[("location", DATA), ("offset", "2")]),
            Refusal::Unaligned("W".into()),
        ),
        (
            w(&[("location", DATA), ("length", "20")]),
            Refusal::Length("W".into()),
        ),
        (
            w(&[("location", DATA), ("offset", "eight")]),
            Refusal::Number("W".into()),
        ),
        (
            w(&[("location", DATA), ("basepath", "/")]),
            Refusal::Key {
                tensor: "W".into(),
                key: "basepath".into(),
            },
        ),
        (
            w(&[("location", DATA), ("offset", "0"), ("offset", "8")]),
            Refusal::Key {
                tensor: "W".into(),
                key: "offset".into(),
            },
        ),
        (
            external("W", 8, &[3, 2], &[("location", DATA)]),
            Refusal::Element {
                tensor: "W".into(),
                data_type: 8,
            },
        ),
        (
            external("W", FLOAT, &[-1, 2], &[("location", DATA)]),
            Refusal::Length("W".into()),
        ),
    ];
    for (tensor, refusal) in cases {
        let mut graph = linear();
        graph.initializer[0] = tensor;
        assert_eq!(checked(&model(graph)).unwrap_err(), refusal);
    }
    assert_eq!(
        check(&model(linear()).encode_to_vec(), None).unwrap_err(),
        Refusal::NoDataFile("W".into())
    );
}

/// A data file whose name the caller does not know is the one the first
/// tensor names, and every other tensor is held to it.
#[test]
fn without_its_name_the_data_file_is_the_one_the_first_tensor_names() {
    let unnamed = Some(DataFile {
        name: None,
        len: 32,
    });
    assert!(check(&model(linear()).encode_to_vec(), unnamed).is_ok());

    let mut graph = linear();
    graph.initializer[1] = external(
        "b",
        FLOAT,
        &[2],
        &[("location", "second.data"), ("offset", "24")],
    );
    assert_eq!(
        check(&model(graph).encode_to_vec(), unnamed).unwrap_err(),
        Refusal::Location {
            tensor: "b".into(),
            location: "second.data".into(),
            expected: DATA.into(),
        }
    );
}

/// What else is refused: sparse tensors wherever they are, training
/// information, inputs and outputs that are not f32, a name given twice, and
/// what is not a model at all.
/// Inputs and outputs of any numeric element type are taken, each with its
/// own.
#[test]
fn ports_of_any_numeric_type_are_taken_with_it() {
    let mut m = model(linear());
    let g = m.graph.as_mut().unwrap();
    g.input[0] = value("x", UINT8, &[1, 3]);
    g.output[0] = value("y", INT64, &[1, 2]);
    let checked = checked(&m).unwrap();
    assert_eq!(checked.inputs[0].element, Element::U8);
    assert_eq!(checked.outputs[0].element, Element::I64);
}

/// Every element type has a name of its own, and its name names it.
#[test]
fn an_element_is_named_and_found_by_its_name() {
    for element in Element::ALL {
        assert_eq!(Element::named(element.name()), Some(element));
        assert_eq!(Element::of(element.code()), Some(element));
    }
    assert_eq!(Element::named("bool"), None);
}

#[test]
fn the_rest_of_what_is_refused() {
    fn graph(m: &mut Model) -> &mut Graph {
        m.graph.as_mut().unwrap()
    }
    let with = |change: &dyn Fn(&mut Model)| {
        let mut m = model(linear());
        change(&mut m);
        checked(&m).unwrap_err()
    };
    assert_eq!(
        with(&|m| graph(m).sparse_initializer.push(vec![])),
        Refusal::Sparse
    );
    assert_eq!(
        with(&|m| graph(m).node.push(Node {
            attribute: vec![Attribute {
                sparse_tensor: Some(vec![]),
                ..Attribute::default()
            }],
            ..node("Constant", &[], &["s"])
        })),
        Refusal::Sparse
    );
    assert_eq!(with(&|m| m.training_info.push(vec![])), Refusal::Training);
    assert_eq!(
        with(&|m| graph(m).input[0] = value("x", BOOL, &[1, 3])),
        Refusal::NotNumeric("input", "x".into())
    );
    assert_eq!(
        with(&|m| graph(m).output[0] = value("y", STRING, &[1, 2])),
        Refusal::NotNumeric("output", "y".into())
    );
    assert_eq!(
        with(&|m| graph(m).initializer.push(at("W", &[3, 2], 0))),
        Refusal::Duplicate("W".into())
    );
    assert_eq!(
        with(&|m| graph(m).input.push(value("x", FLOAT, &[1, 3]))),
        Refusal::Duplicate("x".into())
    );
    assert_eq!(with(&|m| m.graph = None), Refusal::NoGraph);
    assert_eq!(
        check(b"\xff\xff", Some(FILE)).unwrap_err(),
        Refusal::Malformed
    );
    assert_eq!(
        check(&vec![0; MAX_GRAPH_BYTES + 1], Some(FILE)).unwrap_err(),
        Refusal::TooLarge(MAX_GRAPH_BYTES + 1)
    );
}
