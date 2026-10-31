//! The models a composition imports, served: each slot's models,
//! `enclavid-ext:<slot>/models`, a function for each model, returning a
//! resource the slot declares, whose `run` borrows the host's tensors and
//! gives tensors back.
//!
//! A model runs in a process of its own beside the round's. The first time
//! the round calls a model's function, the host has that process started
//! ([`ModelStarter`]) and hands the component a handle to the model; a second
//! call hands out another handle to the same process. A `run` writes its
//! tensors to the process and reads the graph's outputs back, off the round's
//! thread, so the process keeps answering whoever drives it.
//!
//! A `run` is served as whatever its slot declares it to be — tensors of any
//! element types in, a tensor or a tuple or a record of them out — so it is
//! registered by its type rather than by a Rust signature: only handles cross
//! as values, and a tensor's elements cross once, through its constructor and
//! its `data`. Each resource of a slot is a type of its own to the host, so a
//! handle of one reaches no other's `run`. Every failure — tensors the graph
//! does not take, a tensor back of another type than the `run` returns, a
//! model its process did not load, a process that does not answer — traps the
//! round, as every failure of the host's does.

use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use enclavid_inference::protocol::{self, Request, Tensor};
use wasmtime::StoreContextMut;
use wasmtime::component::types::Type;
use wasmtime::component::{Linker, ResourceAny, ResourceDynamic, ResourceType, Val};

use engine_types::composition::ModelImport;

use crate::state::HostState;
use crate::tensors::{lift, mint};

/// Where a round's models run: each in a process of its own.
pub trait ModelStarter: Send + Sync {
    /// Start the process the composition's model `index` runs in, and hand
    /// back the socket to it. Asked once per model a round.
    fn start(
        &self,
        index: u32,
    ) -> Pin<Box<dyn Future<Output = wasmtime::Result<File>> + Send + '_>>;
}

/// The sockets to the processes of the models a round has started, by model.
#[derive(Default)]
pub(crate) struct Started(HashMap<u32, Arc<Mutex<File>>>);

/// Register each slot's models in the instance the fused composition imports
/// the slot as: each resource once, as a type of its own, with its `run`; and
/// a function per [`ModelImport`], which starts its model's process and hands
/// out a handle to it — its model's index, which the handle's `run` reaches its
/// process by.
pub(crate) fn register_models(
    linker: &mut Linker<HostState>,
    models: &[ModelImport],
) -> wasmtime::Result<()> {
    // Each slot, with each of its resources and the models that hand it out.
    type Resources<'m> = Vec<(&'m str, Vec<u32>)>;
    let mut slots: Vec<(&str, Resources<'_>)> = Vec::new();
    for (index, import) in models.iter().enumerate() {
        let index = u32::try_from(index)?;
        let resources = match slots
            .iter_mut()
            .position(|(instance, _)| *instance == import.instance_name)
        {
            Some(at) => &mut slots[at].1,
            None => {
                slots.push((&import.instance_name, Vec::new()));
                &mut slots.last_mut().expect("just pushed").1
            }
        };
        match resources
            .iter_mut()
            .find(|(resource, _)| *resource == import.resource)
        {
            Some((_, of)) => of.push(index),
            None => resources.push((&import.resource, vec![index])),
        }
    }
    let mut ty = 0u32;
    for (instance, resources) in slots {
        let mut root = linker.root();
        let mut slot = root.instance(instance)?;
        for (resource, of) in resources {
            // A handle is its model's index and nothing else: the process it
            // reaches is the round's, and goes with the round.
            slot.resource(resource, ResourceType::host_dynamic(ty), |_, _| Ok(()))?;
            let run = format!("[method]{resource}.{}", engine_types::compile::RUN);
            let served: Arc<[u32]> = Arc::from(of.clone());
            slot.func_new_async(&run, move |store, func, params, results| {
                let served = served.clone();
                Box::new(async move {
                    let result = func
                        .results()
                        .next()
                        .ok_or_else(|| wasmtime::Error::msg("a run that returns nothing"))?;
                    results[0] = run_model(store, ty, &served, params, result).await?;
                    Ok(())
                })
            })?;
            for index in of {
                let function = &models[index as usize].function;
                slot.func_wrap_async(function, move |mut store, (): ()| {
                    Box::new(async move {
                        started(&mut store, index).await?;
                        Ok((ResourceDynamic::new_own(index, ty),))
                    })
                })?;
            }
            ty += 1;
        }
    }
    Ok(())
}

/// The socket to model `index`'s process: the one the round started, or the
/// process started now.
async fn started(
    store: &mut StoreContextMut<'_, HostState>,
    index: u32,
) -> wasmtime::Result<Arc<Mutex<File>>> {
    if let Some(socket) = store.data().started.0.get(&index) {
        return Ok(socket.clone());
    }
    let starter = store.data().models.clone();
    let socket = Arc::new(Mutex::new(starter.start(index).await?));
    store.data_mut().started.0.insert(index, socket.clone());
    Ok(socket)
}

/// A `run` of a resource of type `ty`: the model its handle names — one of
/// `served`, or the round traps — run over the tensors `params` borrow, in its
/// process and off the round's thread, and what it gives back made the
/// `result` the `run` returns.
async fn run_model(
    mut store: StoreContextMut<'_, HostState>,
    ty: u32,
    served: &[u32],
    params: &[Val],
    result: Type,
) -> wasmtime::Result<Val> {
    let (model, inputs) = params
        .split_first()
        .ok_or_else(|| wasmtime::Error::msg("a run of no model"))?;
    let model = handle(model)?.try_into_resource_dynamic(&mut store)?;
    if model.ty() != ty || !served.contains(&model.rep()) {
        return Err(wasmtime::Error::msg(
            "a handle of no model of this resource",
        ));
    }
    let inputs = inputs
        .iter()
        .map(|input| lift(&mut store, handle(input)?))
        .collect::<wasmtime::Result<Vec<_>>>()?;
    let socket = store
        .data()
        .started
        .0
        .get(&model.rep())
        .cloned()
        .ok_or_else(|| wasmtime::Error::msg("a model the round has not started"))?;
    let request = Request { model: 0, inputs };
    let answer = tokio::task::spawn_blocking(move || {
        let mut socket = socket.lock().unwrap_or_else(|e| e.into_inner());
        protocol::write_request(&mut *socket, &request)?;
        protocol::read_answer(&mut *socket).map_err(wasmtime::Error::new)
    })
    .await??;
    let mut outputs = answer.map_err(wasmtime::Error::new)?.into_iter();
    let given = give(&mut store, result, &mut outputs)?;
    if outputs.next().is_some() {
        return Err(wasmtime::Error::msg(
            "the graph gave more outputs than its run returns",
        ));
    }
    Ok(given)
}

/// The resource handle `value` is.
fn handle(value: &Val) -> wasmtime::Result<ResourceAny> {
    match value {
        Val::Resource(handle) => Ok(*handle),
        _ => Err(wasmtime::Error::msg("a run's parameter is not a handle")),
    }
}

/// `outputs`, as many as `ty` takes, made the value of `ty`: a tensor of the
/// host's, or a tuple or a record of them, in their order.
fn give(
    store: &mut StoreContextMut<'_, HostState>,
    ty: Type,
    outputs: &mut impl Iterator<Item = Tensor>,
) -> wasmtime::Result<Val> {
    let mut next = || {
        outputs.next().ok_or_else(|| {
            wasmtime::Error::msg("the graph gave fewer outputs than its run returns")
        })
    };
    Ok(match ty {
        Type::Own(resource) => Val::Resource(mint(store, resource, next()?)?),
        Type::Tuple(tuple) => Val::Tuple(
            tuple
                .types()
                .map(|ty| one(store, ty, next()?))
                .collect::<wasmtime::Result<_>>()?,
        ),
        Type::Record(record) => Val::Record(
            record
                .fields()
                .map(|field| Ok((field.name.to_string(), one(store, field.ty, next()?)?)))
                .collect::<wasmtime::Result<_>>()?,
        ),
        _ => return Err(wasmtime::Error::msg("a run that returns no tensors")),
    })
}

/// `tensor` as the one tensor of the host's `ty` is.
fn one(
    store: &mut StoreContextMut<'_, HostState>,
    ty: Type,
    tensor: Tensor,
) -> wasmtime::Result<Val> {
    match ty {
        Type::Own(resource) => Ok(Val::Resource(mint(store, resource, tensor)?)),
        _ => Err(wasmtime::Error::msg(
            "a run that returns something beside tensors",
        )),
    }
}
