//! The disclosure fields a policy declares: the interface it imports
//! [`POLICY_DISCLOSURE_FIELDS`] as, held to what the host serves —
//! [`DISCLOSURE_FIELD`], taking its `key` and returning an owned
//! `disclosure-field-ref` — and the cases of its `key` to the disclosure
//! fields the composition's catalogs declare, the set the consent screen
//! counts.

use std::collections::HashSet;

use wac_graph::types::{DefinedType, FuncType, ItemKind, Package, Types, ValueType};

use engine_types::compile::{Artifact, CompileFault, DISCLOSURE_FIELD, POLICY_DISCLOSURE_FIELDS};

use crate::compose::{defined, is_host_resource, needs_serving, same_interface};

/// The resource a disclosure field is minted as.
const DISCLOSURE_FIELD_REF: &str = "disclosure-field-ref";

/// Whether the disclosure fields a composition declares, if it imports
/// [`POLICY_DISCLOSURE_FIELDS`], are what the host serves: [`DISCLOSURE_FIELD`]
/// of an enum, and nothing else in the interface that needs serving. An
/// import of it as anything else is refused as [`CompileFault::Mismatched`]:
/// no round of it could be linked. A case no catalog declares as a disclosure
/// field — a policy whose embedding did not write its list — is refused as the
/// policy's [`CompileFault::CatalogInvalid`].
pub(crate) fn declared(
    types: &Types,
    package: &Package,
    fields: &HashSet<&str>,
) -> Result<(), CompileFault> {
    let Some((name, interface)) = types[package.ty()]
        .imports
        .iter()
        .find(|(name, _)| same_interface(name, POLICY_DISCLOSURE_FIELDS))
    else {
        return Ok(());
    };
    let mismatched = || CompileFault::about(name, CompileFault::Mismatched);
    let ItemKind::Instance(interface) = interface else {
        return Err(mismatched());
    };
    let mut cases = Vec::new();
    for (export, kind) in &types[*interface].exports {
        match kind {
            ItemKind::Func(func) if export == DISCLOSURE_FIELD => {
                cases = field_keys(types, &types[*func]).ok_or_else(mismatched)?;
            }
            kind if !needs_serving(types, kind) => {}
            _ => return Err(mismatched()),
        }
    }
    if cases.iter().any(|case| !fields.contains(case)) {
        return Err(CompileFault::CatalogInvalid(Artifact::Policy));
    }
    Ok(())
}

/// The cases of the `key` [`DISCLOSURE_FIELD`] takes, if it is what the host
/// serves: one parameter, an enum, and an owned `disclosure-field-ref`
/// returned.
fn field_keys<'t>(types: &'t Types, func: &FuncType) -> Option<Vec<&'t str>> {
    if func.is_async || func.params.len() != 1 {
        return None;
    }
    if !matches!(func.result, Some(ValueType::Own(id)) if is_host_resource(types, id, DISCLOSURE_FIELD_REF))
    {
        return None;
    }
    let (_, key) = func.params.first()?;
    match defined(types, key)? {
        DefinedType::Enum(cases) => Some(cases.0.iter().map(String::as_str).collect()),
        _ => None,
    }
}
