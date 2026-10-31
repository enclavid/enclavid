//! A composition's models: each slot's `models` and the model files its
//! artifact carries — what compiles, what the compile hands the executor for
//! it, and what it refuses. Components are built from WIT alone, against the
//! host's tensors.

use enclavid_inference::graph::MAX_GRAPH_BYTES;
use engine_compiler::{BundleParts, Compiler};
use engine_types::compile::{Artifact, CompileFault, InterfaceName};
use engine_types::composition::{ModelFile, ModelImport, ModelLayer, PluginInstance};
use engine_types::limits::{MAX_MODEL_FILE_BYTES, MAX_MODELS, MAX_RUN_TENSORS};
use wit_component::{ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata};
use wit_parser::{ManglingAndAbi, Resolve};

const API: &str = "package test:api@0.1.0 { interface api { ping: func(); } }";

/// A component of the one world `wit` declares, its functions doing nothing,
/// built against the host's package.
fn component(wit: &str) -> Vec<u8> {
    let mut resolve = Resolve::default();
    resolve
        .push_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../../wit/host"))
        .expect("the host's WIT parses");
    let package = resolve
        .push_str("component.wit", wit)
        .expect("the WIT parses");
    let world = resolve
        .select_world(&[package], None)
        .expect("the one world");
    let mut module = dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8)
        .expect("the metadata");
    ComponentEncoder::default()
        .module(&module)
        .expect("the module")
        .validate(true)
        .encode()
        .expect("the component")
}

/// A slot `slot` whose models interface holds `body`, with the host's tensors
/// of `f32` and `u8` in scope.
fn slot_of(slot: &str, body: &str) -> String {
    format!(
        "package enclavid-ext:{slot}@0.1.0 {{
             interface models {{
                 use enclavid:host/tensors@0.1.0.{{tensor-f32, tensor-u8}};
                 {body}
             }}
         }}"
    )
}

/// A slot `slot` whose models are `functions`, each an `age-model` of one
/// tensor in and one out.
fn slot(slot: &str, functions: &[&str]) -> String {
    let functions: String = functions
        .iter()
        .map(|f| format!("{f}: func() -> age-model;\n"))
        .collect();
    slot_of(
        slot,
        &format!(
            "resource age-model {{ run: func(input: borrow<tensor-f32>) -> tensor-f32; }}\n{functions}"
        ),
    )
}

/// A policy importing the API a plugin exports, and whatever `imports` names.
fn policy(imports: &str, packages: &str) -> Vec<u8> {
    component(&format!(
        "package test:policy;
         world policy {{ import test:api/api@0.1.0; {imports} }}
         {API}
         {packages}"
    ))
}

/// A policy pinned without plugins, importing what `imports` names.
fn lone_policy(imports: &str, packages: &str) -> Vec<u8> {
    component(&format!(
        "package test:policy;
         world policy {{ {imports} }}
         {packages}"
    ))
}

/// A plugin exporting the API, and importing whatever `imports` names.
fn plugin(imports: &str, packages: &str) -> Vec<u8> {
    component(&format!(
        "package test:plugin;
         world plugin {{ {imports} export test:api/api@0.1.0; }}
         {API}
         {packages}"
    ))
}

fn layer(name: &str, sha: u8) -> ModelLayer {
    ModelLayer {
        name: name.into(),
        sha256: [sha; 32],
        length: 1000 + u64::from(sha),
    }
}

/// `policy`, carrying `policy_layers`, with one plugin carrying its own,
/// compiled; or the fault the compile refuses it for.
fn compile(
    policy: Vec<u8>,
    policy_layers: Vec<ModelLayer>,
    plugin: Option<(Vec<u8>, Vec<ModelLayer>)>,
) -> Result<BundleParts, CompileFault> {
    let plugins = plugin
        .into_iter()
        .map(|(wasm, model_layers)| PluginInstance {
            package: "test:plugin0".into(),
            wasm,
            model_layers,
        })
        .collect();
    Compiler::new()
        .expect("a compiler")
        .compile_to_parts(policy, policy_layers, plugins)
        .map_err(|e| {
            e.downcast_ref::<CompileFault>()
                .unwrap_or_else(|| panic!("a failure that names no fault: {e:?}"))
                .clone()
        })
}

fn refusal(
    policy: Vec<u8>,
    policy_layers: Vec<ModelLayer>,
    plugin: Option<(Vec<u8>, Vec<ModelLayer>)>,
) -> Option<CompileFault> {
    compile(policy, policy_layers, plugin).err()
}

fn name(s: &str) -> InterfaceName {
    InterfaceName::new(s).expect("a legal name")
}

fn the_plugin() -> Artifact {
    Artifact::Plugin("test:plugin0".into())
}

const FACE_AGE_MODELS: &str = "enclavid-ext:face-age/models@0.1.0";

/// The plugin importing the face-age slot `slot_wit` declares, carrying
/// `layers`, beside a policy that imports nothing of it.
fn face_age(slot_wit: &str, layers: Vec<ModelLayer>) -> Result<BundleParts, CompileFault> {
    compile(
        policy("", ""),
        Vec::new(),
        Some((
            plugin(&format!("import {FACE_AGE_MODELS};"), slot_wit),
            layers,
        )),
    )
}

#[test]
fn a_plugins_model_compiles_with_its_graph_and_data_file() {
    let parts = face_age(
        &slot("face-age", &["age"]),
        vec![layer("age.onnx", 7), layer("age.onnx.data", 8)],
    )
    .expect("the model compiles");
    assert_eq!(
        parts.models,
        vec![ModelImport {
            instance_name: FACE_AGE_MODELS.into(),
            function: "age".into(),
            resource: "age-model".into(),
            graph: 0,
            data: Some(1),
        }]
    );
    assert_eq!(
        parts.files,
        vec![
            ModelFile {
                sha256: [7; 32],
                length: 1007,
            },
            ModelFile {
                sha256: [8; 32],
                length: 1008,
            },
        ]
    );
}

/// A graph that holds its weights itself has no data file.
#[test]
fn a_model_of_its_graph_alone_compiles() {
    let parts = face_age(&slot("face-age", &["age"]), vec![layer("age.onnx", 7)])
        .expect("the model compiles");
    assert_eq!(parts.models[0].data, None);
    assert_eq!(parts.files.len(), 1);
}

#[test]
fn the_policys_own_models_compile() {
    let parts = compile(
        lone_policy(
            "import enclavid-ext:policy/models@0.1.0;",
            &slot("policy", &["age"]),
        ),
        vec![layer("age.onnx", 1)],
        None,
    )
    .expect("the policy's models compile");
    assert_eq!(parts.models.len(), 1);
    assert_eq!(parts.models[0].function, "age");
}

/// A `run` of tensors of different element types in, and a tuple or a record
/// of them out.
#[test]
fn a_run_of_several_tensors_compiles() {
    for gives in ["tuple<tensor-f32, tensor-u8, tensor-f32>", "detections"] {
        let parts = face_age(
            &slot_of(
                "face-age",
                &format!(
                    "record detections {{ scores: tensor-f32, mask: tensor-u8 }}
                     resource detector {{
                         run: func(image: borrow<tensor-u8>, scale: borrow<tensor-f32>) -> {gives};
                     }}
                     faces: func() -> detector;"
                ),
            ),
            vec![layer("faces.onnx", 1)],
        )
        .unwrap_or_else(|e| panic!("{gives}: {e}"));
        assert_eq!(parts.models[0].resource, "detector", "{gives}");
    }
}

/// The tensors at their bounds: as many in and out as one message to a
/// model's process carries.
#[test]
fn a_run_at_the_bounds_compiles() {
    let inputs: Vec<String> = (0..MAX_RUN_TENSORS)
        .map(|i| format!("i{i}: borrow<tensor-f32>"))
        .collect();
    let outputs = vec!["tensor-f32"; MAX_RUN_TENSORS].join(", ");
    face_age(
        &slot_of(
            "face-age",
            &format!(
                "resource m {{ run: func({}) -> tuple<{outputs}>; }}
                 big: func() -> m;",
                inputs.join(", ")
            ),
        ),
        vec![layer("big.onnx", 1)],
    )
    .expect("the model compiles");
}

/// Two models handing out one resource share its `run`.
#[test]
fn two_models_of_one_resource_compile() {
    let parts = face_age(
        &slot("face-age", &["age", "age-again"]),
        vec![layer("age.onnx", 1), layer("age-again.onnx", 2)],
    )
    .expect("the models compile");
    let functions: Vec<_> = parts.models.iter().map(|m| m.function.as_str()).collect();
    assert_eq!(functions, ["age", "age-again"]);
    assert!(parts.models.iter().all(|m| m.resource == "age-model"));
    assert_eq!(parts.files.len(), 2);
}

/// Two models of one file — the same digest and length under two names — are
/// one file to hold.
#[test]
fn one_file_under_two_names_is_held_once() {
    let parts = face_age(
        &slot("face-age", &["age", "age-again"]),
        vec![
            layer("age.onnx", 3),
            layer("age.onnx.data", 4),
            layer("age-again.onnx", 3),
            layer("age-again.onnx.data", 4),
        ],
    )
    .expect("the models compile");
    assert_eq!(parts.files.len(), 2);
    assert!(
        parts
            .models
            .iter()
            .all(|m| (m.graph, m.data) == (0, Some(1)))
    );
}

#[test]
fn a_file_no_function_names_is_refused() {
    for extra in ["extra.onnx", "age.bin", "age.onnx.data.more"] {
        assert_eq!(
            face_age(
                &slot("face-age", &["age"]),
                vec![layer("age.onnx", 1), layer(extra, 2)],
            )
            .err(),
            Some(CompileFault::ModelsMismatched(the_plugin())),
            "{extra}"
        );
    }
}

#[test]
fn a_function_without_its_graph_is_refused() {
    assert_eq!(
        face_age(
            &slot("face-age", &["age", "gender"]),
            vec![layer("age.onnx", 1), layer("gender.onnx.data", 2)],
        )
        .err(),
        Some(CompileFault::ModelsMismatched(the_plugin()))
    );
}

#[test]
fn model_files_with_no_models_are_refused() {
    assert_eq!(
        refusal(
            policy("", ""),
            Vec::new(),
            Some((plugin("", ""), vec![layer("age.onnx", 1)])),
        ),
        Some(CompileFault::ModelsMismatched(the_plugin()))
    );
}

#[test]
fn two_files_of_one_name_are_refused() {
    assert_eq!(
        face_age(
            &slot("face-age", &["age"]),
            vec![layer("age.onnx", 1), layer("age.onnx", 2)],
        )
        .err(),
        Some(CompileFault::ModelsMismatched(the_plugin()))
    );
}

/// A slot's models hand out the files of the one artifact that imports them:
/// a second importer is refused, whichever of them carries the files.
#[test]
fn a_slots_models_imported_by_two_artifacts_are_refused() {
    assert_eq!(
        refusal(
            policy(
                &format!("import {FACE_AGE_MODELS};"),
                &slot("face-age", &["age"]),
            ),
            Vec::new(),
            Some((
                plugin(
                    &format!("import {FACE_AGE_MODELS};"),
                    &slot("face-age", &["age"]),
                ),
                vec![layer("age.onnx", 1)],
            )),
        ),
        Some(CompileFault::ModelsShared(name(FACE_AGE_MODELS)))
    );
}

#[test]
fn a_plugin_importing_the_policys_models_is_refused() {
    let import = "enclavid-ext:policy/models@0.1.0";
    assert_eq!(
        refusal(
            policy("", ""),
            Vec::new(),
            Some((
                plugin(&format!("import {import};"), &slot("policy", &["age"])),
                vec![layer("age.onnx", 1)],
            )),
        ),
        Some(CompileFault::Unsatisfied(name(import)))
    );
}

/// Slots of shapes no `run` the host serves has: each refused as the import's
/// mismatch.
#[test]
fn a_slot_of_another_shape_is_refused() {
    let past_inputs: Vec<String> = (0..=MAX_RUN_TENSORS)
        .map(|i| format!("i{i}: borrow<tensor-f32>"))
        .collect();
    let past_inputs = format!(
        "resource age-model {{ run: func({}) -> tensor-f32; }} age: func() -> age-model;",
        past_inputs.join(", ")
    );
    let past_outputs = format!(
        "resource age-model {{ run: func(input: borrow<tensor-f32>) -> tuple<{}>; }} \
         age: func() -> age-model;",
        vec!["tensor-f32"; MAX_RUN_TENSORS + 1].join(", ")
    );
    let shapes = [
        // A run of no tensors, of an owned tensor rather than a borrowed one,
        // of a list rather than a tensor, of nothing back.
        "resource age-model { run: func() -> tensor-f32; } age: func() -> age-model;".to_string(),
        "resource age-model { run: func(input: tensor-f32) -> tensor-f32; } age: func() -> age-model;"
            .into(),
        "resource age-model { run: func(input: list<f32>) -> tensor-f32; } age: func() -> age-model;"
            .into(),
        "resource age-model { run: func(input: borrow<tensor-f32>); } age: func() -> age-model;"
            .into(),
        // A tuple of one, which is one tensor; an option; a record of
        // something else beside the tensors.
        "resource age-model { run: func(input: borrow<tensor-f32>) -> tuple<tensor-f32>; }
         age: func() -> age-model;"
            .into(),
        "resource age-model { run: func(input: borrow<tensor-f32>) -> option<tensor-f32>; }
         age: func() -> age-model;"
            .into(),
        "record out { age: tensor-f32, note: string }
         resource age-model { run: func(input: borrow<tensor-f32>) -> out; }
         age: func() -> age-model;"
            .into(),
        past_inputs,
        past_outputs,
        // A resource without its run, one no function hands out, a method
        // beside run, a constructor, a function taking something, one
        // returning an option.
        "resource age-model { } age: func() -> age-model;".into(),
        "resource age-model { run: func(input: borrow<tensor-f32>) -> tensor-f32; }
         resource unused { run: func(input: borrow<tensor-f32>) -> tensor-f32; }
         age: func() -> age-model;"
            .into(),
        "resource age-model { run: func(input: borrow<tensor-f32>) -> tensor-f32; reset: func(); }
         age: func() -> age-model;"
            .into(),
        "resource age-model { constructor(); run: func(input: borrow<tensor-f32>) -> tensor-f32; }
         age: func() -> age-model;"
            .into(),
        "resource age-model { run: func(input: borrow<tensor-f32>) -> tensor-f32; }
         age: func(scale: u32) -> age-model;"
            .into(),
        "resource age-model { run: func(input: borrow<tensor-f32>) -> tensor-f32; }
         age: func() -> option<age-model>;"
            .into(),
    ];
    for body in shapes {
        assert_eq!(
            face_age(&slot_of("face-age", &body), vec![layer("age.onnx", 1)]).err(),
            Some(CompileFault::Mismatched(name(FACE_AGE_MODELS))),
            "{body}"
        );
    }
}

/// A resource the slot declares itself under a tensor's name is not one of
/// the host's tensors.
#[test]
fn a_tensor_of_the_slots_own_is_not_the_hosts() {
    let own = "package enclavid-ext:face-age@0.1.0 {
                   interface models {
                       resource tensor-f32 { }
                       resource age-model { run: func(input: borrow<tensor-f32>) -> tensor-f32; }
                       age: func() -> age-model;
                   }
               }";
    assert_eq!(
        face_age(own, vec![layer("age.onnx", 1)]).err(),
        Some(CompileFault::Mismatched(name(FACE_AGE_MODELS)))
    );
}

#[test]
fn more_models_than_the_bound_are_refused() {
    let names: Vec<String> = (0..=MAX_MODELS).map(|i| format!("age{i}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let layers = names
        .iter()
        .map(|n| layer(&format!("{n}.onnx"), 1))
        .collect();
    assert_eq!(
        face_age(&slot("face-age", &names), layers).err(),
        Some(CompileFault::TooLarge)
    );
}

#[test]
fn a_graph_past_its_bound_is_refused() {
    let mut big = layer("age.onnx", 1);
    big.length = MAX_GRAPH_BYTES as u64 + 1;
    assert_eq!(
        face_age(&slot("face-age", &["age"]), vec![big]).err(),
        Some(CompileFault::TooLarge)
    );
}

#[test]
fn a_data_file_past_its_bound_is_refused() {
    let mut big = layer("age.onnx.data", 2);
    big.length = MAX_MODEL_FILE_BYTES + 1;
    assert_eq!(
        face_age(&slot("face-age", &["age"]), vec![layer("age.onnx", 1), big]).err(),
        Some(CompileFault::TooLarge)
    );
}

/// A plugin may import a slot's models, and never serve them: its own resource
/// would be what the host hands out as the model.
#[test]
fn a_plugin_exporting_a_slots_models_is_refused() {
    let wasm = component(&format!(
        "package test:plugin;
         world plugin {{ export {FACE_AGE_MODELS}; export test:api/api@0.1.0; }}
         {API}
         {}",
        slot("face-age", &["age"])
    ));
    assert_eq!(
        refusal(policy("", ""), Vec::new(), Some((wasm, Vec::new()))),
        Some(CompileFault::ReservedExport(the_plugin()))
    );
}

/// A plugin may use the host's tensors, and never serve them.
#[test]
fn a_plugin_exporting_the_tensors_is_refused() {
    let wasm = component(&format!(
        "package test:plugin;
         world plugin {{ export enclavid:host/tensors@0.1.0; export test:api/api@0.1.0; }}
         {API}"
    ));
    assert_eq!(
        refusal(policy("", ""), Vec::new(), Some((wasm, Vec::new()))),
        Some(CompileFault::ReservedExport(the_plugin()))
    );
}
