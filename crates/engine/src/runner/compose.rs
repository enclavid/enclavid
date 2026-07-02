//! Single-store fusion of a policy with its plugins via `wac-graph`,
//! with strict per-component routing of the applicant-facing embedded
//! imports (i18n / icons).
//!
//! [`fuse`] builds the composition graph by hand rather than using the
//! high-level `wac_graph::plug` helper, because `plug` MERGES every
//! same-named unsatisfied import into one — which is what we want for
//! `disclosure-fields` (option B: DF is merged, first-match, bounded by
//! the visible static-set size) and `enclavid:policy/context`, but NOT
//! for i18n / icons, whose stored value differs per component. For those
//! two, each component's `enclavid:embedded/<iface>` import is routed to
//! a DISTINCT composite import named by that component's catalog
//! content-hash (`embedded-slot:<slug>/<iface>`), so the host can serve
//! each from its own catalog. Byte-identical catalogs share a slug (and
//! thus one import node) — correct, since identical content resolves the
//! same.
//!
//! The result is ONE component (one wasmtime `Store` at run time, so
//! cross-component WIT resources are native handles) plus a manifest of
//! the distinct i18n/icons imports the host `Linker` must register.

use std::collections::HashMap;

use wac_graph::types::{ItemKind, Package};
use wac_graph::{CompositionGraph, EncodeOptions, NodeId, PackageId};

use super::{EmbeddedIface, EmbeddedImport, PluginInstance};
use crate::embedded::{embedded_import_name, load_embedded};

/// Package label for the policy in the composition graph. Only a
/// registration key (its uniqueness against the plugin labels is all
/// that matters) — wac matches by interface name, not this label.
const POLICY_PACKAGE: &str = "enclavid:composed-policy";

/// Fuse `policy_wasm` with `plugins` into one component's bytes plus the
/// manifest of distinct per-component i18n/icons imports.
///
/// Fails loud if a component's bytes aren't a component, if two plugins
/// register under the same `package` id, or if a wac graph operation
/// fails (e.g. a type mismatch on a functional wiring).
pub(crate) fn fuse(
    policy_wasm: &[u8],
    plugins: &[PluginInstance],
) -> wasmtime::Result<(Vec<u8>, Vec<EmbeddedImport>)> {
    let mut graph = CompositionGraph::new();

    let policy_id = register(&mut graph, POLICY_PACKAGE, policy_wasm)?;
    let policy_hash = catalog_hash_of(policy_wasm)?;

    let mut plugin_pkgs: Vec<(PackageId, [u8; 32])> = Vec::with_capacity(plugins.len());
    for plugin in plugins {
        let id = register(&mut graph, &plugin.package, &plugin.wasm)?;
        plugin_pkgs.push((id, catalog_hash_of(&plugin.wasm)?));
    }

    let policy_inst = graph.instantiate(policy_id);
    let plugin_insts: Vec<(NodeId, PackageId, [u8; 32])> = plugin_pkgs
        .iter()
        .map(|(id, hash)| (graph.instantiate(*id), *id, *hash))
        .collect();

    // Strict per-component routing of i18n / icons (policy + plugins).
    let mut manifest: Vec<EmbeddedImport> = Vec::new();
    let mut import_nodes: HashMap<String, NodeId> = HashMap::new();
    route_strict_embedded(&mut graph, policy_inst, policy_id, &policy_hash, &mut import_nodes, &mut manifest)?;
    for (inst, id, hash) in &plugin_insts {
        route_strict_embedded(&mut graph, *inst, *id, hash, &mut import_nodes, &mut manifest)?;
    }

    // Functional wiring: satisfy each policy import that names a plugin
    // interface (not embedded/*, not context) with the plugin that
    // exports it. Unmatched imports bubble up as composite imports
    // (host-served, or an encode-time error if nothing satisfies them).
    let policy_fn_imports: Vec<String> = graph.types()[graph[policy_id].ty()]
        .imports
        .iter()
        .filter(|(name, _)| !is_embedded(name) && !is_context(name))
        .map(|(name, _)| name.clone())
        .collect();
    for import_name in policy_fn_imports {
        let source = plugin_insts.iter().find_map(|(inst, id, _)| {
            graph.types()[graph[*id].ty()]
                .exports
                .contains_key(&import_name)
                .then_some(*inst)
        });
        if let Some(inst) = source {
            let export = graph
                .alias_instance_export(inst, &import_name)
                .map_err(|e| wasmtime::Error::msg(format!("wac: alias export `{import_name}`: {e}")))?;
            graph
                .set_instantiation_argument(policy_inst, &import_name, export)
                .map_err(|e| wasmtime::Error::msg(format!("wac: wire import `{import_name}`: {e}")))?;
        }
    }

    // Re-export the policy's exports as the fused component's exports.
    let policy_exports: Vec<String> = graph.types()[graph[policy_id].ty()]
        .exports
        .keys()
        .cloned()
        .collect();
    for name in policy_exports {
        let export = graph
            .alias_instance_export(policy_inst, &name)
            .map_err(|e| wasmtime::Error::msg(format!("wac: alias policy export `{name}`: {e}")))?;
        graph
            .export(export, &name)
            .map_err(|e| wasmtime::Error::msg(format!("wac: export `{name}`: {e}")))?;
    }

    let bytes = graph
        .encode(EncodeOptions::default())
        .map_err(|e| wasmtime::Error::msg(format!("wac: encode fused component: {e}")))?;
    Ok((bytes, manifest))
}

/// Route one component's i18n / icons imports to distinct composite
/// imports named by its catalog hash. `import_nodes` dedups by name so
/// byte-identical catalogs (same slug) share one import node; the
/// manifest records each distinct import once for the host `Linker`.
fn route_strict_embedded(
    graph: &mut CompositionGraph,
    inst: NodeId,
    pkg_id: PackageId,
    hash: &[u8; 32],
    import_nodes: &mut HashMap<String, NodeId>,
    manifest: &mut Vec<EmbeddedImport>,
) -> wasmtime::Result<()> {
    let strict: Vec<(String, ItemKind, EmbeddedIface)> = graph.types()[graph[pkg_id].ty()]
        .imports
        .iter()
        .filter_map(|(name, kind)| strict_iface(name).map(|iface| (name.clone(), *kind, iface)))
        .collect();
    for (import_name, kind, iface) in strict {
        let instance_name = embedded_import_name(hash, iface.as_str());
        let node = match import_nodes.get(&instance_name) {
            Some(node) => *node,
            None => {
                let node = graph.import(&instance_name, kind).map_err(|e| {
                    wasmtime::Error::msg(format!("wac: create import `{instance_name}`: {e}"))
                })?;
                import_nodes.insert(instance_name.clone(), node);
                manifest.push(EmbeddedImport {
                    instance_name,
                    catalog_hash: *hash,
                    iface,
                });
                node
            }
        };
        graph.set_instantiation_argument(inst, &import_name, node).map_err(|e| {
            wasmtime::Error::msg(format!("wac: route embedded import `{import_name}`: {e}"))
        })?;
    }
    Ok(())
}

/// Register a component's bytes as a package in the graph.
fn register(graph: &mut CompositionGraph, name: &str, wasm: &[u8]) -> wasmtime::Result<PackageId> {
    let pkg = Package::from_bytes(name, None, wasm.to_vec(), graph.types_mut())
        .map_err(|e| wasmtime::Error::msg(format!("wac: parse component `{name}`: {e}")))?;
    graph
        .register_package(pkg)
        .map_err(|e| wasmtime::Error::msg(format!("wac: register `{name}`: {e}")))
}

/// Content-hash of a component's own (top-level) embedded catalog.
fn catalog_hash_of(wasm: &[u8]) -> wasmtime::Result<[u8; 32]> {
    Ok(load_embedded(wasm)?.hash)
}

/// The strict-routed kind of an embedded import name, or `None` for DF
/// / non-embedded imports (which stay merged).
fn strict_iface(name: &str) -> Option<EmbeddedIface> {
    if name.starts_with("enclavid:embedded/i18n") {
        Some(EmbeddedIface::I18n)
    } else if name.starts_with("enclavid:embedded/icons") {
        Some(EmbeddedIface::Icons)
    } else {
        None
    }
}

fn is_embedded(name: &str) -> bool {
    name.starts_with("enclavid:embedded/")
}

fn is_context(name: &str) -> bool {
    name.starts_with("enclavid:policy/context")
}
