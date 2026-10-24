//! The slots a composition's texts come through — the `embedded-slot:`
//! imports each component's embedding named after its catalog — held to what
//! the host serves: [`LOCALIZED`], taking the component's `key` enum and
//! returning an owned `localized-ref`. The cases of `key` are the catalog's
//! texts — the check embedding ran, run again against the slot as fused.

use enclavid_embedded::Catalog;
use enclavid_embedded::keys;
use wac_graph::types::{DefinedType, FuncType, ItemKind, Package, Types, ValueType};

use engine_types::compile::{Artifact, CompileFault, LOCALIZED};
use engine_types::composition::EmbeddedImport;

use crate::compose::{defined, is_host_resource, needs_serving};

/// The resource a text is minted as.
const LOCALIZED_REF: &str = "localized-ref";

/// Whether every slot of `slots` is, in the fused `package`, what the host
/// serves, its catalog's texts what its keys declare. A slot of another shape
/// is refused as [`CompileFault::Mismatched`]: no round of it could be linked.
/// A catalog its keys do not fit — a text no key names, a key with no text —
/// is refused as the [`CompileFault::CatalogInvalid`] of the artifact that
/// imports the slot.
pub(crate) fn declared(
    types: &Types,
    package: &Package,
    slots: &[(Artifact, &EmbeddedImport, &Catalog)],
) -> Result<(), CompileFault> {
    let imports = &types[package.ty()].imports;
    for (artifact, slot, texts) in slots {
        let name = &slot.instance_name;
        let mismatched = || CompileFault::about(name, CompileFault::Mismatched);
        let Some(ItemKind::Instance(interface)) = imports.get(name.as_str()) else {
            return Err(mismatched());
        };
        let mut keys = None;
        for (export, kind) in &types[*interface].exports {
            match kind {
                ItemKind::Func(func) if export == LOCALIZED => {
                    keys = Some(slot_keys(types, &types[*func]).ok_or_else(mismatched)?);
                }
                kind if !needs_serving(types, kind) => {}
                _ => return Err(mismatched()),
            }
        }
        let fits = |keys: &[String]| {
            keys::check(keys, texts)
                .iter()
                .all(|problem| problem.warning)
        };
        if keys.is_some_and(|keys| !fits(&keys)) {
            return Err(CompileFault::CatalogInvalid(artifact.clone()));
        }
    }
    Ok(())
}

/// The keys a slot's [`LOCALIZED`] takes, if it is what the host serves: one
/// parameter, an enum, and an owned `localized-ref` returned.
fn slot_keys(types: &Types, func: &FuncType) -> Option<Vec<String>> {
    if func.is_async || func.params.len() != 1 {
        return None;
    }
    if !matches!(func.result, Some(ValueType::Own(id)) if is_host_resource(types, id, LOCALIZED_REF))
    {
        return None;
    }
    let (_, key) = func.params.first()?;
    let DefinedType::Enum(cases) = defined(types, key)? else {
        return None;
    };
    Some(cases.0.iter().cloned().collect())
}
