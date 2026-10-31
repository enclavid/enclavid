//! What `enclavid {policy,plugin} validate` checks of a project's models.
//!
//! A component's models are the functions of its slot's `models` interface,
//! `enclavid-ext:<slot>/models`: each takes nothing and returns a resource the
//! slot declares, whose one method `run` borrows a tensor of
//! `enclavid:host/tensors` for each input of the model's graph and returns one
//! for each output — as itself, or a tuple or a record of them. A model is its
//! graph, pushed beside the component as the layer `<function>.onnx`, and
//! where its weights lie apart the data file the graph points into,
//! `<function>.onnx.data`.
//!
//! Checked here, before the push, as the platform holds them later: the slot's
//! shape, and a graph for each function with no file besides — what the
//! compile refuses a composition for — and each graph with its data file as
//! the process that runs the model checks them before it loads it — what a
//! round fails on when it first runs the model, mid-session. And what neither
//! holds a model to until it runs: that its graph takes as many tensors as its
//! `run` passes, each of the element type it is passed, and gives as many
//! back, each of the type it is returned as.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use enclavid_inference::graph::{self, DataFile, Element, Port};
use engine_types::compile::{MODEL_DATA_SUFFIX, MODEL_GRAPH_SUFFIX, MODELS, RUN, TENSORS};
use engine_types::limits::{MAX_MODEL_FILE_BYTES, MAX_MODELS, MAX_RUN_TENSORS};
use wit_parser::{Function, FunctionKind, Handle, Resolve, Type, TypeDefKind, TypeId, TypeOwner};

/// The namespace of the slots.
const EXTENSIONS: &str = "enclavid-ext";

/// What the models of a project came to.
pub struct Checked {
    /// Each model its slot declares, a line about it.
    pub models: Vec<String>,
    /// What is wrong, each a line.
    pub errors: Vec<String>,
}

/// A model as the slot declares it: the element types of the tensors its
/// `run` passes and returns, in order.
struct Declared {
    function: String,
    resource: String,
    inputs: Vec<Element>,
    outputs: Vec<Element>,
}

/// The element types of the tensors a `run` passes, then of those it returns.
type Shape = (Vec<Element>, Vec<Element>);

/// Check the model files in `dir` against the models the slot `slot`
/// declares in the WIT at `wit`.
pub fn check(wit: &Path, slot: &str, dir: &Path) -> Result<Checked> {
    let mut resolve = Resolve::default();
    resolve
        .push_dir(wit)
        .with_context(|| format!("reading the WIT in {}", wit.display()))?;
    let mut checked = Checked {
        models: Vec::new(),
        errors: Vec::new(),
    };
    let declared = declared(&resolve, slot, &mut checked.errors);
    if declared.len() > MAX_MODELS {
        checked.errors.push(format!(
            "`{EXTENSIONS}:{slot}/{MODELS}` declares {} models; a composition imports at \
             most {MAX_MODELS}",
            declared.len()
        ));
    }
    let mut named = BTreeSet::new();
    for model in &declared {
        let graph_name = format!("{}{MODEL_GRAPH_SUFFIX}", model.function);
        let data_name = format!("{}{MODEL_DATA_SUFFIX}", model.function);
        let (graph_path, data_path) = (dir.join(&graph_name), dir.join(&data_name));
        named.insert(graph_name);
        named.insert(data_name);
        let Ok(graph) = std::fs::read(&graph_path) else {
            checked.errors.push(format!(
                "model `{}`: no graph {}",
                model.function,
                graph_path.display()
            ));
            continue;
        };
        let data = std::fs::metadata(&data_path).ok().map(|m| m.len());
        if data.is_some_and(|len| len > MAX_MODEL_FILE_BYTES) {
            checked.errors.push(format!(
                "{}: past the {MAX_MODEL_FILE_BYTES} bytes a model file may hold",
                data_path.display()
            ));
            continue;
        }
        let file = DataFile {
            name: None,
            len: data.unwrap_or(0),
        };
        let graph_checked = match graph::check(&graph, Some(file)) {
            Ok(checked) => checked,
            Err(e) => {
                checked
                    .errors
                    .push(format!("{}: {e}", graph_path.display()));
                continue;
            }
        };
        let run = format!("`{}.{RUN}`", model.resource);
        let (takes, gives) = (graph_checked.inputs.len(), graph_checked.outputs.len());
        if takes != model.inputs.len() {
            checked.errors.push(format!(
                "model `{}`: its graph takes {takes} tensor(s), and {run} passes {}",
                model.function,
                model.inputs.len()
            ));
        } else {
            let passes = format!("{run} passes");
            mismatched(
                &model.function,
                "input",
                &graph_checked.inputs,
                &model.inputs,
                &passes,
            )
            .for_each(|e| checked.errors.push(e));
        }
        if gives != model.outputs.len() {
            checked.errors.push(format!(
                "model `{}`: its graph gives {gives} tensor(s), and {run} returns {}",
                model.function,
                model.outputs.len()
            ));
        } else {
            let returns = format!("{run} returns");
            mismatched(
                &model.function,
                "output",
                &graph_checked.outputs,
                &model.outputs,
                &returns,
            )
            .for_each(|e| checked.errors.push(e));
        }
        checked.models.push(format!(
            "{} → {}: {} in, {} out; graph {} bytes{}",
            model.function,
            model.resource,
            names(&model.inputs),
            names(&model.outputs),
            graph.len(),
            data.map_or(String::new(), |len| format!(", data file {len} bytes")),
        ));
    }
    for (name, path) in files(dir)? {
        if !named.contains(&name) {
            checked.errors.push(format!(
                "{}: no model of `{EXTENSIONS}:{slot}/{MODELS}` is named for it",
                path.display()
            ));
        }
    }
    Ok(checked)
}

/// An error for each of the graph's `ports` whose element type is not what
/// the `run` `does` for it, position by position.
fn mismatched<'a>(
    function: &'a str,
    side: &'a str,
    ports: &'a [Port],
    elements: &'a [Element],
    does: &'a str,
) -> impl Iterator<Item = String> + 'a {
    ports
        .iter()
        .zip(elements)
        .filter(|(port, element)| port.element != **element)
        .map(move |(port, element)| {
            format!(
                "model `{function}`: {side} `{}` of its graph is a tensor of {}, and {does} \
                 a `tensor-{}` for it",
                port.name,
                port.element.name(),
                element.name()
            )
        })
}

/// The names of `elements`, comma-separated.
fn names(elements: &[Element]) -> String {
    elements
        .iter()
        .map(|e| e.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The models the slot `slot` declares, in their order, with what is wrong of
/// its shape pushed to `errors`: every resource needs its `run` and a function
/// handing it out, and nothing else of the interface may need serving.
fn declared(resolve: &Resolve, slot: &str, errors: &mut Vec<String>) -> Vec<Declared> {
    let Some(package) = resolve
        .packages
        .iter()
        .find(|(_, package)| package.name.namespace == EXTENSIONS && package.name.name == slot)
        .map(|(id, _)| id)
    else {
        return Vec::new();
    };
    let Some(&interface) = resolve.packages[package].interfaces.get(MODELS) else {
        return Vec::new();
    };
    let interface = &resolve.interfaces[interface];
    let resources: Vec<(&str, TypeId)> = interface
        .types
        .iter()
        .filter(|(_, id)| matches!(resolve.types[**id].kind, TypeDefKind::Resource))
        .map(|(name, id)| (name.as_str(), *id))
        .collect();
    let mut runs: Vec<(TypeId, Shape)> = Vec::new();
    let mut models = Vec::new();
    for function in interface.functions.values() {
        match function.kind {
            FunctionKind::Freestanding => match handed_out(resolve, function, &resources) {
                Some((resource, id)) => models.push((function.name.clone(), resource, id)),
                None => errors.push(format!(
                    "`{}`: a model's function takes nothing and returns a resource of the slot",
                    function.name
                )),
            },
            FunctionKind::Method(id) if function.name.ends_with(&format!(".{RUN}")) => {
                match run_shape(resolve, function) {
                    Some(shape) => runs.push((id, shape)),
                    None => errors.push(format!(
                        "`{}`: a `{RUN}` borrows 1 to {MAX_RUN_TENSORS} tensors of `{TENSORS}` \
                         and returns one, or a tuple of 2 to {MAX_RUN_TENSORS} or a record of \
                         1 to {MAX_RUN_TENSORS} of them",
                        function.name
                    )),
                }
            }
            _ => errors.push(format!(
                "`{}`: a model's resource has one method, `{RUN}`, and nothing else",
                function.name
            )),
        }
    }
    let mut declared = Vec::new();
    for (name, id) in &resources {
        let shape = runs.iter().find(|(run, _)| run == id).map(|(_, s)| s);
        let handing: Vec<_> = models.iter().filter(|(_, _, m)| m == id).collect();
        match (shape, handing.is_empty()) {
            (None, _) => errors.push(format!("resource `{name}` has no `{RUN}`")),
            (_, true) => errors.push(format!("resource `{name}`: no function hands it out")),
            (Some((inputs, outputs)), false) => {
                declared.extend(handing.iter().map(|(function, resource, _)| Declared {
                    function: function.clone(),
                    resource: (*resource).to_owned(),
                    inputs: inputs.clone(),
                    outputs: outputs.clone(),
                }));
            }
        }
    }
    declared
}

/// The resource `function` hands out, if it takes nothing and returns an
/// owned resource of the slot's.
fn handed_out<'r>(
    resolve: &Resolve,
    function: &Function,
    resources: &[(&'r str, TypeId)],
) -> Option<(&'r str, TypeId)> {
    if !function.params.is_empty() {
        return None;
    }
    let Some(Type::Id(mut id)) = function.result else {
        return None;
    };
    if let TypeDefKind::Handle(Handle::Own(resource)) = resolve.types[id].kind {
        id = resource;
    }
    resources.iter().copied().find(|(_, r)| *r == id)
}

/// The element types of the tensors a `run` passes and returns: after its
/// receiver, it borrows one to [`MAX_RUN_TENSORS`] of the host's tensors, and
/// returns one, or a tuple of two to [`MAX_RUN_TENSORS`] or a record of one to
/// [`MAX_RUN_TENSORS`] of them.
fn run_shape(resolve: &Resolve, function: &Function) -> Option<Shape> {
    let params = function.params.get(1..)?;
    if !(1..=MAX_RUN_TENSORS).contains(&params.len()) {
        return None;
    }
    let inputs = params
        .iter()
        .map(|p| tensor(resolve, &p.ty, true))
        .collect::<Option<Vec<_>>>()?;
    let result = function.result.as_ref()?;
    let outputs = match tensor(resolve, result, false) {
        Some(element) => vec![element],
        None => {
            let types: Vec<&Type> = match defined(resolve, result)? {
                TypeDefKind::Tuple(tuple) if tuple.types.len() >= 2 => tuple.types.iter().collect(),
                TypeDefKind::Record(record) => record.fields.iter().map(|f| &f.ty).collect(),
                _ => return None,
            };
            if types.len() > MAX_RUN_TENSORS {
                return None;
            }
            types
                .into_iter()
                .map(|ty| tensor(resolve, ty, false))
                .collect::<Option<Vec<_>>>()?
        }
    };
    Some((inputs, outputs))
}

/// What `ty` is defined as, through any aliases.
fn defined<'r>(resolve: &'r Resolve, ty: &Type) -> Option<&'r TypeDefKind> {
    let mut ty = *ty;
    while let Type::Id(id) = ty {
        match &resolve.types[id].kind {
            TypeDefKind::Type(next) => ty = *next,
            kind => return Some(kind),
        }
    }
    None
}

/// The element type of the host's tensor `ty` is a handle to — a borrowed one
/// where `borrowed`, an owned one where not.
fn tensor(resolve: &Resolve, ty: &Type, borrowed: bool) -> Option<Element> {
    let Type::Id(id) = *ty else {
        return None;
    };
    match resolve.types[id].kind {
        TypeDefKind::Handle(Handle::Borrow(resource)) if borrowed => host_tensor(resolve, resource),
        TypeDefKind::Handle(Handle::Own(resource)) if !borrowed => host_tensor(resolve, resource),
        TypeDefKind::Resource if !borrowed => host_tensor(resolve, id),
        TypeDefKind::Type(next) => tensor(resolve, &next, borrowed),
        _ => None,
    }
}

/// The element type of the host's tensor the resource `id` is, through any
/// aliases: a `tensor-<element>` of [`TENSORS`]. `None` for any other resource,
/// one the project declares itself under the same name included.
fn host_tensor(resolve: &Resolve, mut id: TypeId) -> Option<Element> {
    while let TypeDefKind::Type(Type::Id(next)) = resolve.types[id].kind {
        id = next;
    }
    let ty = &resolve.types[id];
    let TypeOwner::Interface(owner) = ty.owner else {
        return None;
    };
    if resolve.id_of(owner).as_deref() != Some(TENSORS) {
        return None;
    }
    Element::named(ty.name.as_deref()?.strip_prefix("tensor-")?)
}

/// The model files in `dir` — every `.onnx` and `.onnx.data` — by name; none
/// where there is no `dir`.
fn files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading {}", dir.display()))?
            .path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(MODEL_GRAPH_SUFFIX) || name.ends_with(MODEL_DATA_SUFFIX) {
            files.push((name.to_owned(), path.clone()));
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests;
