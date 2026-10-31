use super::*;

use enclavid_inference::fixture;

/// The host's package, its tensors among it, as a project's WIT has it.
const HOST: [(&str, &str); 2] = [
    ("types.wit", include_str!("../../../../wit/host/types.wit")),
    (
        "tensors.wit",
        include_str!("../../../../wit/host/tensors.wit"),
    ),
];

/// A plugin project whose slot, `enclavid-ext:plugin`, declares `models` as
/// `body`, with an empty directory of model files.
struct Project(tempfile::TempDir);

impl Project {
    fn new(body: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let wit = dir.path().join("wit");
        for deps in ["ext", "host"] {
            std::fs::create_dir_all(wit.join("deps").join(deps)).unwrap();
        }
        std::fs::write(
            wit.join("world.wit"),
            "package test:plugin@0.1.0;\n\n\
             world plugin {\n    import enclavid-ext:plugin/models@0.1.0;\n}\n",
        )
        .unwrap();
        std::fs::write(
            wit.join("deps/ext/models.wit"),
            format!(
                "package enclavid-ext:plugin@0.1.0;\n\n\
                 interface models {{\n    \
                 use enclavid:host/tensors@0.1.0.{{tensor-f32, tensor-u8}};\n{body}\n}}\n"
            ),
        )
        .unwrap();
        for (name, text) in HOST {
            std::fs::write(wit.join("deps/host").join(name), text).unwrap();
        }
        std::fs::create_dir(dir.path().join("models")).unwrap();
        Self(dir)
    }

    fn file(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.0.path().join("models").join(name), bytes).unwrap();
    }

    /// `linear`'s graph and data file, under `name`.
    fn linear(&self, name: &str) {
        let (graph, data) = fixture::linear(
            "whatever.bin",
            [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]],
            [0.5, -0.5],
        );
        self.file(&format!("{name}.onnx"), &graph);
        self.file(&format!("{name}.onnx.data"), &data);
    }

    fn check(&self) -> Checked {
        let dir = self.0.path();
        check(&dir.join("wit"), "plugin", &dir.join("models")).unwrap()
    }
}

/// One tensor in, one out, handed out as `age`.
const AGE: &str = "    resource age-model { run: func(x: borrow<tensor-f32>) -> tensor-f32; }\n    \
                   age: func() -> age-model;";

/// A model with its graph and data file, which take and give what its `run`
/// does, is all there is to say.
#[test]
fn a_model_whose_graph_fits_its_run_checks() {
    let project = Project::new(AGE);
    project.linear("age");
    let checked = project.check();
    assert_eq!(checked.errors, Vec::<String>::new());
    assert_eq!(checked.models.len(), 1);
    assert!(checked.models[0].starts_with("age → age-model: f32 in, f32 out"));
}

/// A graph of no weights needs no data file; its outputs are returned as a
/// record or a tuple alike, in the graph's order.
#[test]
fn a_graph_of_its_own_needs_no_data_file() {
    for result in ["parts", "tuple<tensor-f32, tensor-f32, tensor-f32>"] {
        let project = Project::new(&format!(
            "    record parts {{ a: tensor-f32, b: tensor-f32, sum: tensor-f32 }}\n    \
             resource split-model {{ run: func(a: borrow<tensor-f32>, b: borrow<tensor-f32>) -> {result}; }}\n    \
             split: func() -> split-model;"
        ));
        project.file("split.onnx", &fixture::split());
        let checked = project.check();
        assert_eq!(checked.errors, Vec::<String>::new(), "{result}");
        assert!(
            checked.models[0].starts_with("split → split-model: f32, f32 in, f32, f32, f32 out"),
            "{result}: {}",
            checked.models[0]
        );
    }
}

/// A model is passed and returns tensors of the element types its graph
/// takes and gives, whatever they are; another type of either is an error.
#[test]
fn a_tensor_of_another_element_type_than_its_graphs_is_an_error() {
    let widen = |run: &str| {
        let project = Project::new(&format!(
            "    resource widen-model {{ run: {run}; }}\n    widen: func() -> widen-model;"
        ));
        project.file("widen.onnx", &fixture::widen());
        project.check()
    };
    let checked = widen("func(x: borrow<tensor-u8>) -> tensor-f32");
    assert_eq!(checked.errors, Vec::<String>::new());
    assert!(checked.models[0].starts_with("widen → widen-model: u8 in, f32 out"));

    let checked = widen("func(x: borrow<tensor-f32>) -> tensor-u8");
    assert_eq!(checked.errors.len(), 2, "{:?}", checked.errors);
    assert!(
        checked.errors[0].contains(
            "input `x` of its graph is a tensor of u8, and `widen-model.run` passes a `tensor-f32`"
        ),
        "{}",
        checked.errors[0]
    );
    assert!(
        checked.errors[1].contains(
            "output `y` of its graph is a tensor of f32, and `widen-model.run` returns a `tensor-u8`"
        ),
        "{}",
        checked.errors[1]
    );
}

/// A model without its graph, and a file no model is named for, are each an
/// error.
#[test]
fn a_missing_graph_and_a_stray_file_are_errors() {
    let project = Project::new(AGE);
    project.linear("other");
    let checked = project.check();
    assert_eq!(checked.errors.len(), 3, "{:?}", checked.errors);
    assert!(checked.errors[0].contains("model `age`: no graph"));
    assert!(checked.errors[1].contains("other.onnx: no model"));
    assert!(checked.errors[2].contains("other.onnx.data: no model"));
}

/// A graph that takes or gives another number of tensors than its `run` is
/// an error for each.
#[test]
fn a_graph_of_another_arity_than_its_run_is_an_error() {
    let project = Project::new(
        "    resource age-model { run: func(x: borrow<tensor-f32>, y: borrow<tensor-f32>) -> tuple<tensor-f32, tensor-f32>; }\n    \
         age: func() -> age-model;",
    );
    project.linear("age");
    let checked = project.check();
    assert_eq!(checked.errors.len(), 2, "{:?}", checked.errors);
    assert!(checked.errors[0].contains("takes 1 tensor(s), and `age-model.run` passes 2"));
    assert!(checked.errors[1].contains("gives 1 tensor(s), and `age-model.run` returns 2"));
}

/// A graph whose data file is shorter than its weights reach is refused as
/// the model's process refuses it.
#[test]
fn a_graph_past_its_data_file_is_an_error() {
    let project = Project::new(AGE);
    project.linear("age");
    project.file("age.onnx.data", &[0; 8]);
    let checked = project.check();
    assert_eq!(checked.errors.len(), 1, "{:?}", checked.errors);
    assert!(checked.errors[0].contains("age.onnx:"));
}

/// `run`s of shapes the host serves none of: tensors it does not borrow, or
/// that are not the host's, past the bound, or returned as anything but a
/// tensor, a tuple or a record of them.
#[test]
fn a_run_of_another_shape_is_an_error() {
    let many = (0..=MAX_RUN_TENSORS)
        .map(|i| format!("x{i}: borrow<tensor-f32>"))
        .collect::<Vec<_>>()
        .join(", ");
    for body in [
        "resource age-model { run: func(x: list<f32>) -> tensor-f32; } age: func() -> age-model;",
        "resource age-model { run: func(x: tensor-f32) -> tensor-f32; } age: func() -> age-model;",
        "resource age-model { run: func(x: borrow<tensor-f32>); } age: func() -> age-model;",
        "resource age-model { run: func(x: borrow<tensor-f32>) -> tuple<tensor-f32>; } age: func() -> age-model;",
        "resource age-model { run: func(x: borrow<tensor-f32>) -> option<tensor-f32>; } age: func() -> age-model;",
        "record out { y: tensor-f32, why: string }
         resource age-model { run: func(x: borrow<tensor-f32>) -> out; } age: func() -> age-model;",
        &format!("resource age-model {{ run: func({many}) -> tensor-f32; }} age: func() -> age-model;"),
        "resource tensor-i64 { constructor(); }
         resource age-model { run: func(x: borrow<tensor-i64>) -> tensor-f32; } age: func() -> age-model;",
    ] {
        let project = Project::new(body);
        project.linear("age");
        let errors = project.check().errors;
        assert!(
            errors.iter().any(|e| e.starts_with("`[method]age-model.run`: a `run` borrows")),
            "{body}: {errors:?}"
        );
    }
}

/// Slots of shapes the host serves no models of: each an error.
#[test]
fn a_slot_of_another_shape_is_an_error() {
    for body in [
        "resource age-model { } age: func() -> age-model;",
        "resource age-model { run: func(x: borrow<tensor-f32>) -> tensor-f32; } unused: func(n: u32) -> age-model;",
        "resource age-model { run: func(x: borrow<tensor-f32>) -> tensor-f32; reset: func(); } age: func() -> age-model;",
        "resource age-model { run: func(x: borrow<tensor-f32>) -> tensor-f32; }
         resource unused { run: func(x: borrow<tensor-f32>) -> tensor-f32; }
         age: func() -> age-model;",
    ] {
        let project = Project::new(body);
        project.linear("age");
        assert!(!project.check().errors.is_empty(), "{body}");
    }
}
