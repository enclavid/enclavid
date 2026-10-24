//! The icons a composition imports — [`engine_types::icons::INTERFACE`], on its
//! version's track — held to what the host serves: one function per icon of
//! [`NAMES`], each minting that icon's `icon-ref`.

use wac_graph::types::{ItemKind, Package, Types, ValueType};

use engine_types::compile::CompileFault;
use engine_types::icons::{INTERFACE, NAMES};

use crate::compose::{is_host_resource, needs_serving, same_interface};

/// The resource the host mints for an icon.
const ICON_REF: &str = "icon-ref";

/// Whether every import of the icons a composition has is what the host
/// serves: functions named for icons of [`NAMES`], taking nothing and returning
/// an owned `icon-ref` of the host's types, and nothing else in the interface
/// that needs serving. An import of them as anything else — an icon the host
/// has not got, as one built against a later version may name, or a handle of
/// another resource — is refused as [`CompileFault::Mismatched`]: no round of
/// it could be linked.
pub(crate) fn declared(types: &Types, package: &Package) -> Result<(), CompileFault> {
    for (name, kind) in &types[package.ty()].imports {
        if !same_interface(name, INTERFACE) {
            continue;
        }
        let mismatched = || CompileFault::about(name, CompileFault::Mismatched);
        let ItemKind::Instance(interface) = kind else {
            return Err(mismatched());
        };
        for (export, kind) in &types[*interface].exports {
            let served = match kind {
                ItemKind::Func(func) => {
                    let icon = &types[*func];
                    NAMES.contains(&export.as_str())
                        && icon.params.is_empty()
                        && matches!(icon.result, Some(ValueType::Own(id)) if is_host_resource(types, id, ICON_REF))
                        && !icon.is_async
                }
                kind => !needs_serving(types, kind),
            };
            if !served {
                return Err(mismatched());
            }
        }
    }
    Ok(())
}
