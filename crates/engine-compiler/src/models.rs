//! The models a composition imports, held to what the host serves: each slot's
//! models, `enclavid-ext:<slot>/models`, a function for each model of the one
//! artifact that imports the slot, returning a resource the slot declares,
//! whose one method `run` borrows the host's tensors and gives tensors back.
//!
//! A slot's models are the artifact's that imports them: the one artifact
//! whose own component imports the slot, before any fusion, carries the files
//! its functions hand out. So a function hands out a model of the artifact
//! that imports it, and no other's, whatever another declares.

use std::collections::{HashMap, HashSet};

use enclavid_inference::graph::{Element, MAX_GRAPH_BYTES};
use enclavid_inference::protocol::MAX_TENSORS;
use wac_graph::types::{
    DefinedType, FuncType, InterfaceId, ItemKind, Package, ResourceId, Type, Types, ValueType,
};

use enclavid_embedded::POLICY_SLOT;
use engine_types::compile::{
    Artifact, CompileFault, MODEL_DATA_SUFFIX, MODEL_GRAPH_SUFFIX, MODELS, RUN, TENSORS,
};
use engine_types::composition::{ModelFile, ModelImport, ModelLayer};
use engine_types::limits::{MAX_MODEL_FILE_BYTES, MAX_MODELS, MAX_RUN_TENSORS};

use crate::compose::{defined, extension, needs_serving, same_interface};

const _: () = assert!(
    MAX_RUN_TENSORS as u64 == MAX_TENSORS as u64,
    "a run's tensors are what one message to a model's process carries"
);

/// Each slot whose models a composition's artifacts import, with the one
/// artifact that imports it and the model files that artifact carries.
/// Refused: a slot two artifacts import, as [`CompileFault::ModelsShared`], and
/// the policy's slot imported by a plugin, as [`CompileFault::Unsatisfied`] —
/// what the policy's slot hands out is the policy's.
pub(crate) fn owners<'a>(
    artifacts: &[(&'a Artifact, Vec<String>, &'a [ModelLayer])],
) -> Result<HashMap<String, (&'a Artifact, &'a [ModelLayer])>, CompileFault> {
    let mut owners: HashMap<String, (&Artifact, &[ModelLayer])> = HashMap::new();
    for (artifact, imports, layers) in artifacts {
        let (artifact, layers) = (*artifact, *layers);
        for name in imports {
            let Some((slot, MODELS, _)) = extension(name) else {
                continue;
            };
            if slot == POLICY_SLOT && *artifact != Artifact::Policy {
                return Err(CompileFault::about(name, CompileFault::Unsatisfied));
            }
            match owners.get(slot) {
                Some((owner, _)) if *owner != artifact => {
                    return Err(CompileFault::about(name, CompileFault::ModelsShared));
                }
                Some(_) => {}
                None => {
                    owners.insert(slot.to_owned(), (artifact, layers));
                }
            }
        }
    }
    Ok(owners)
}

/// A model as a slot declares it: its function, and the resource the function
/// hands out.
struct SlotModel<'t> {
    function: &'t str,
    resource: &'t str,
}

/// A model of the composition, before its files are found: the artifact that
/// imports its slot, the slot's import, and the model as the slot declares it.
struct Declared<'a> {
    artifact: &'a Artifact,
    instance_name: &'a str,
    model: SlotModel<'a>,
}

/// The models of the fused `package`, held to what the host serves, and the
/// files they are, each once.
///
/// Every slot's models are resources the slot declares, each with one method,
/// `run`, borrowing one to [`MAX_RUN_TENSORS`] tensors of the host's and
/// giving one back, or a tuple or a record of up to as many; and functions
/// taking nothing and returning a resource of those, one for each model. An
/// import of another shape — a resource no function hands out, a function of
/// another type, anything else that needs serving — is refused as
/// [`CompileFault::Mismatched`]: no round of it could be linked.
///
/// Every artifact's model files are its functions' and nothing else: for each
/// function `f`, a graph `f.onnx` and, if the graph points into one, a data
/// file `f.onnx.data`. A function without its graph, a file no function is
/// for, or two files of one name, is refused as the artifact's
/// [`CompileFault::ModelsMismatched`]. More than [`MAX_MODELS`] models, a graph
/// past [`MAX_GRAPH_BYTES`] or a data file past [`MAX_MODEL_FILE_BYTES`], is
/// [`CompileFault::TooLarge`].
pub(crate) fn declared(
    types: &Types,
    package: &Package,
    owners: &HashMap<String, (&Artifact, &[ModelLayer])>,
    artifacts: &[(&Artifact, &[ModelLayer])],
) -> Result<(Vec<ModelImport>, Vec<ModelFile>), CompileFault> {
    let mut declared = Vec::new();
    for (name, kind) in &types[package.ty()].imports {
        let Some((slot, MODELS, _)) = extension(name) else {
            continue;
        };
        let mismatched = || CompileFault::about(name, CompileFault::Mismatched);
        let (Some(&(artifact, _)), ItemKind::Instance(interface)) = (owners.get(slot), kind) else {
            return Err(mismatched());
        };
        for model in slot_models(types, *interface).ok_or_else(mismatched)? {
            declared.push(Declared {
                artifact,
                instance_name: name,
                model,
            });
        }
    }
    if declared.len() > MAX_MODELS {
        return Err(CompileFault::TooLarge);
    }

    let mut files: Vec<ModelFile> = Vec::new();
    let mut index = |layer: &ModelLayer| {
        let file = ModelFile {
            sha256: layer.sha256,
            length: layer.length,
        };
        let at = files
            .iter()
            .position(|known| *known == file)
            .unwrap_or_else(|| {
                files.push(file);
                files.len() - 1
            });
        at as u32
    };
    let mut models = Vec::new();
    for &(artifact, layers) in artifacts {
        let mismatched = || CompileFault::ModelsMismatched(artifact.clone());
        let names: HashSet<&str> = layers.iter().map(|layer| layer.name.as_str()).collect();
        if names.len() != layers.len() {
            return Err(mismatched());
        }
        let layer = |name: String| layers.iter().find(|layer| layer.name == name);
        let mut used = 0;
        for declared in declared.iter().filter(|model| model.artifact == artifact) {
            let model = &declared.model;
            let graph =
                layer(format!("{}{MODEL_GRAPH_SUFFIX}", model.function)).ok_or_else(mismatched)?;
            let data = layer(format!("{}{MODEL_DATA_SUFFIX}", model.function));
            if graph.length > MAX_GRAPH_BYTES as u64
                || data.is_some_and(|data| data.length > MAX_MODEL_FILE_BYTES)
            {
                return Err(CompileFault::TooLarge);
            }
            used += 1 + usize::from(data.is_some());
            models.push(ModelImport {
                instance_name: declared.instance_name.to_owned(),
                function: model.function.to_owned(),
                resource: model.resource.to_owned(),
                graph: index(graph),
                data: data.map(&mut index),
            });
        }
        if used != layers.len() {
            return Err(mismatched());
        }
    }
    Ok((models, files))
}

/// The models a slot's `interface` declares, `None` for a slot of another
/// shape.
fn slot_models(types: &Types, interface: InterfaceId) -> Option<Vec<SlotModel<'_>>> {
    let exports = &types[interface].exports;
    let resources: HashMap<ResourceId, &str> = exports
        .iter()
        .filter_map(|(name, kind)| match kind {
            ItemKind::Type(Type::Resource(id)) if types[*id].alias.is_none() => {
                Some((*id, name.as_str()))
            }
            _ => None,
        })
        .collect();
    let mut runs: HashSet<ResourceId> = HashSet::new();
    let mut models = Vec::new();
    for (name, kind) in exports {
        match kind {
            ItemKind::Type(Type::Resource(id)) if resources.contains_key(id) => {}
            ItemKind::Func(func) => {
                let func = &types[*func];
                if let Some(method) = name.strip_prefix("[method]") {
                    let (resource, RUN) = method.split_once('.')? else {
                        return None;
                    };
                    let (&id, _) = resources.iter().find(|(_, name)| **name == resource)?;
                    if !runs_on(types, func, id) {
                        return None;
                    }
                    runs.insert(id);
                } else if name.starts_with('[') {
                    return None;
                } else {
                    let id = handed_out(func)?;
                    models.push((name.as_str(), id));
                }
            }
            kind if !needs_serving(types, kind) => {}
            _ => return None,
        }
    }
    let handed: HashSet<ResourceId> = models.iter().map(|&(_, id)| id).collect();
    if handed.len() != resources.len() || runs.len() != resources.len() {
        return None;
    }
    models
        .into_iter()
        .map(|(function, id)| {
            Some(SlotModel {
                function,
                resource: resources.get(&id)?,
            })
        })
        .collect()
}

/// The resource a slot's function hands out: it takes nothing and returns an
/// owned handle.
fn handed_out(func: &FuncType) -> Option<ResourceId> {
    match func.result {
        Some(ValueType::Own(id)) if func.params.is_empty() && !func.is_async => Some(id),
        _ => None,
    }
}

/// Whether `func` is a `run` of `resource`: a borrow of it, then one to
/// [`MAX_RUN_TENSORS`] borrowed tensors of the host's, returning an owned
/// tensor of the host's, or a tuple of two to as many or a record of one to as
/// many of them.
fn runs_on(types: &Types, func: &FuncType, resource: ResourceId) -> bool {
    let mut params = func.params.values();
    let receiver = matches!(params.next(), Some(ValueType::Borrow(id)) if *id == resource);
    let takes = (1..=MAX_RUN_TENSORS).contains(&params.len())
        && params
            .all(|ty| matches!(ty, ValueType::Borrow(id) if host_tensor(types, *id).is_some()));
    let tensor =
        |ty: &ValueType| matches!(ty, ValueType::Own(id) if host_tensor(types, *id).is_some());
    let gives = match &func.result {
        Some(ty) if tensor(ty) => true,
        Some(ty) => match defined(types, ty) {
            Some(DefinedType::Tuple(tys)) => {
                (2..=MAX_RUN_TENSORS).contains(&tys.len()) && tys.iter().all(tensor)
            }
            Some(DefinedType::Record(record)) => {
                (1..=MAX_RUN_TENSORS).contains(&record.fields.len())
                    && record.fields.values().all(tensor)
            }
            _ => false,
        },
        None => false,
    };
    receiver && takes && gives && !func.is_async
}

/// The element type of the host's tensor the resource `id` is, through any
/// aliases: a `tensor-<element>` of [`TENSORS`]. `None` for any other resource,
/// one a component declares itself under the same name included.
fn host_tensor(types: &Types, id: ResourceId) -> Option<Element> {
    let alias = types[id].alias.as_ref()?;
    let from_tensors = alias.owner.is_some_and(|owner| {
        types[owner]
            .id
            .as_deref()
            .is_some_and(|owner| same_interface(owner, TENSORS))
    });
    if from_tensors {
        let element = types[alias.source].name.strip_prefix("tensor-")?;
        return Element::named(element);
    }
    host_tensor(types, alias.source)
}
