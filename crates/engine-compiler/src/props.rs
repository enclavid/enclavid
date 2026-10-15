//! The props a composition declares: the interface it imports [`POLICY_PROPS`]
//! as, held to what the host serves. The executor reads a session's props
//! against the type `get` returns, off the component itself, before any round.

use wac_graph::types::{DefinedType, ItemKind, Package, PrimitiveType, Types, ValueType};

use engine_types::compile::{CompileFault, POLICY_PROPS};

use crate::compose::{needs_serving, same_interface};

/// The one function the host serves in [`POLICY_PROPS`].
const GET: &str = "get";

/// Whether the props a composition declares, if it imports [`POLICY_PROPS`],
/// are what the host serves: `get`, taking nothing and returning a value — not
/// a resource, a stream or a future — and nothing else in the interface that
/// needs serving. An import of it as anything else is refused as
/// [`CompileFault::Mismatched`]: no round of it could be linked.
pub(crate) fn declared(types: &Types, package: &Package) -> Result<(), CompileFault> {
    let Some((name, interface)) = types[package.ty()]
        .imports
        .iter()
        .find(|(name, _)| same_interface(name, POLICY_PROPS))
    else {
        return Ok(());
    };
    let mismatched = || CompileFault::about(name, CompileFault::Mismatched);
    let ItemKind::Instance(interface) = interface else {
        return Err(mismatched());
    };
    for (export, kind) in &types[*interface].exports {
        let served = match kind {
            ItemKind::Func(func) if export == GET => {
                let get = &types[*func];
                get.params.is_empty()
                    && !get.is_async
                    && get.result.is_some_and(|returns| is_value(types, &returns))
            }
            kind => !needs_serving(types, kind),
        };
        if !served {
            return Err(mismatched());
        }
    }
    Ok(())
}

/// Whether `ty` is a value — of any shape, through any aliases — rather than a
/// resource handle, a stream, a future or an error context.
fn is_value(types: &Types, ty: &ValueType) -> bool {
    match ty {
        ValueType::Primitive(PrimitiveType::ErrorContext)
        | ValueType::Own(_)
        | ValueType::Borrow(_) => false,
        ValueType::Primitive(_) => true,
        ValueType::Defined(id) => match &types[*id] {
            DefinedType::Alias(ty) => is_value(types, ty),
            DefinedType::Stream(_) | DefinedType::Future(_) => false,
            _ => true,
        },
    }
}
