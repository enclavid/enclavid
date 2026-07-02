//! Single-store fusion of a policy with its plugins via `wac-graph`,
//! with strict per-component routing of the applicant-facing embedded
//! imports (i18n / icons).
//!
//! [`fuse`] builds the composition graph by hand rather than using the
//! high-level `wac_graph::plug` helper, because `plug` MERGES every
//! same-named unsatisfied import into one — which is what we want for
//! `disclosure-fields` (option B: DF is merged, first-match, bounded by
//! the visible static-set size) and `enclavid:host/session-context`, but NOT
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
use crate::embedded::{
    embedded_import_name, load_embedded, load_embedded_nested, top_level_imports,
};

/// Namespace prefix of a strict per-component embedded import that a
/// pre-fused artifact already carries.
const EMBEDDED_SLOT_PREFIX: &str = "embedded-slot:";

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
        reject_reserved_exports(&graph, id, &plugin.package)?;
        plugin_pkgs.push((id, catalog_hash_of(&plugin.wasm)?));
    }

    let policy_inst = graph.instantiate(policy_id);
    let plugin_insts: Vec<(NodeId, PackageId, [u8; 32])> = plugin_pkgs
        .iter()
        .map(|(id, hash)| (graph.instantiate(*id), *id, *hash))
        .collect();

    // Strict per-component routing of i18n / icons. Route the runtime
    // plugins always; route the socket (policy) ONLY if it isn't already
    // a fused core — a pre-fused core's per-component embedded imports
    // are already `embedded-slot:*` (passed through + re-emitted via
    // `reconstruct_strict_manifest`), and its remaining canonical
    // `enclavid:embedded/*` import is just the `localized-ref` type
    // dependency, which must NOT be re-routed.
    let policy_prefused = top_level_imports(policy_wasm)?
        .iter()
        .any(|n| n.starts_with(EMBEDDED_SLOT_PREFIX));
    let mut manifest: Vec<EmbeddedImport> = Vec::new();
    let mut import_nodes: HashMap<String, NodeId> = HashMap::new();
    if !policy_prefused {
        route_strict_embedded(&mut graph, policy_inst, policy_id, &policy_hash, &mut import_nodes, &mut manifest)?;
    }
    for (inst, id, hash) in &plugin_insts {
        route_strict_embedded(&mut graph, *inst, *id, hash, &mut import_nodes, &mut manifest)?;
    }

    // Functional wiring: satisfy each policy import that names a PLUGIN
    // interface with the plugin that exports it. Host-reserved imports
    // (`is_host_reserved`) are deliberately excluded — they are served by
    // the host `Linker`, never by a plugin, so they bubble up as
    // composite imports. That set covers `enclavid:host/*`,
    // `enclavid:embedded/*`, and a pre-fused (hybrid) core's already
    // routed `embedded-slot:*` imports (reconstructed into the manifest,
    // not plugin-satisfied). Any other unmatched import also bubbles up
    // (host-served, or an encode-time error if nothing satisfies it).
    let policy_fn_imports: Vec<String> = graph.types()[graph[policy_id].ty()]
        .imports
        .iter()
        .filter(|(name, _)| !is_host_reserved(name))
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
/// imports named by its catalog hash.
///
/// wac merges every instance import of the SAME interface into one (it
/// dedups by interface id), so simply renaming the import doesn't split
/// them. To keep per-component imports distinct we give each a **twin
/// interface**: a structural clone of `enclavid:embedded/<iface>` with a
/// distinct id (`embedded-slot:<hash>/<iface>`). The component's
/// canonical import subtype-checks against the twin (func-only, no
/// resources → purely structural), and because the twin's id differs,
/// wac keeps it as its own import. The host `Linker` then serves each
/// twin instance from its own catalog.
///
/// `import_nodes` dedups by name so byte-identical catalogs (same slug)
/// share one import node; the manifest records each once.
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
                let ItemKind::Instance(canonical_id) = kind else {
                    return Err(wasmtime::Error::msg(format!(
                        "embedded import `{import_name}` is not an interface instance",
                    )));
                };
                // Structural twin with a distinct id so wac won't merge it.
                let mut twin = graph.types()[canonical_id].clone();
                twin.id = Some(instance_name.clone());
                let twin_id = graph.types_mut().add_interface(twin);
                let node = graph
                    .import(&instance_name, ItemKind::Instance(twin_id))
                    .map_err(|e| {
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

/// Recover the strict per-catalog i18n / icons imports a PRE-FUSED
/// artifact already carries (static / hybrid consumption). For each
/// top-level `embedded-slot:<slug>/<iface>` import, find the nested
/// catalog whose content-hash reproduces that name, so the host
/// `Linker` can register the instance against the right catalog. An
/// artifact that isn't strict-fused — a lone policy, or a plain-merged
/// fusion — has no such imports and yields an empty manifest.
pub(crate) fn reconstruct_strict_manifest(wasm: &[u8]) -> wasmtime::Result<Vec<EmbeddedImport>> {
    let imports = top_level_imports(wasm)?;
    if !imports.iter().any(|n| n.starts_with(EMBEDDED_SLOT_PREFIX)) {
        return Ok(Vec::new());
    }
    let catalogs = load_embedded_nested(wasm)?;
    let mut manifest = Vec::new();
    for name in imports {
        let Some(iface) = slot_import_iface(&name) else {
            continue;
        };
        let catalog_hash = catalogs
            .iter()
            .map(|c| c.hash)
            .find(|h| embedded_import_name(h, iface.as_str()) == name)
            .ok_or_else(|| {
                wasmtime::Error::msg(format!(
                    "pre-fused artifact imports `{name}` but no nested catalog matches it",
                ))
            })?;
        manifest.push(EmbeddedImport {
            instance_name: name,
            catalog_hash,
            iface,
        });
    }
    Ok(manifest)
}

/// The strict-routed kind of an already-routed `embedded-slot:*` import
/// name, or `None` if it isn't one.
fn slot_import_iface(name: &str) -> Option<EmbeddedIface> {
    if !name.starts_with(EMBEDDED_SLOT_PREFIX) {
        return None;
    }
    if name.ends_with("/i18n") {
        Some(EmbeddedIface::I18n)
    } else if name.ends_with("/icons") {
        Some(EmbeddedIface::Icons)
    } else {
        None
    }
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

/// Interfaces the TEE host `Linker` serves EXCLUSIVELY. A composed
/// plugin may IMPORT one (reading the same host surface the policy does)
/// but must never SATISFY one: wiring a plugin export into a
/// host-reserved import would let the plugin interpose on the session
/// config the policy reads (`enclavid:host/*`), or the applicant-facing
/// text / icons and the consumer disclosure vocabulary
/// (`enclavid:embedded/*`). Kept as ONE predicate so a new host
/// capability under `enclavid:host/` is protected the moment it exists —
/// no second filter to remember, no denylist to drift. `embedded-slot:*`
/// are the synthetic per-catalog twins fusion itself derives from the
/// embedded imports, host-owned by construction.
fn is_host_reserved(name: &str) -> bool {
    name.starts_with("enclavid:host/")
        || name.starts_with("enclavid:embedded/")
        || name.starts_with(EMBEDDED_SLOT_PREFIX)
}

/// Reject a plugin that EXPORTS a host-reserved interface. A plugin may
/// import host capabilities, but exporting one is an attempt to interpose
/// on the host surface — there is no legitimate reason for it, so fail
/// loud rather than silently leaving the export unwired (which the
/// `is_host_reserved` wiring filter would do). Belt-and-suspenders with
/// that filter: the filter stops the policy import from being satisfied
/// by the plugin; this stops the plugin from shipping the export at all.
fn reject_reserved_exports(
    graph: &CompositionGraph,
    pkg_id: PackageId,
    package: &str,
) -> wasmtime::Result<()> {
    for name in graph.types()[graph[pkg_id].ty()].exports.keys() {
        if is_host_reserved(name) {
            return Err(wasmtime::Error::msg(format!(
                "plugin `{package}` exports host-reserved interface `{name}`: a \
                 plugin may import host capabilities but must never export one \
                 (host interfaces are served exclusively by the TEE)",
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_reserved_covers_every_host_served_namespace() {
        // The families the host `Linker` serves exclusively: a plugin may
        // import these but must never satisfy or export one.
        assert!(is_host_reserved("enclavid:host/session-context@0.1.0"));
        // A future host capability under `enclavid:host/` is protected the
        // moment it exists — no edit to this predicate needed.
        assert!(is_host_reserved("enclavid:host/timer@0.1.0"));
        assert!(is_host_reserved("enclavid:embedded/i18n@0.1.0"));
        assert!(is_host_reserved("enclavid:embedded/icons@0.1.0"));
        assert!(is_host_reserved("enclavid:embedded/disclosure-fields@0.1.0"));
        // Synthetic per-catalog twins fusion derives from the embedded
        // imports (`embedded_import_name`): host-owned by construction.
        assert!(is_host_reserved("embedded-slot:h0123456789abcdef/i18n"));
    }

    #[test]
    fn host_reserved_excludes_plugin_and_policy_interfaces() {
        // Plugin exports stay plugin-satisfiable; the policy's own export
        // stays policy-owned. Neither may be mistaken for a host cap.
        assert!(!is_host_reserved("enclavid:well-known/capture@0.1.0"));
        assert!(!is_host_reserved("enclavid:extra/tag@0.1.0"));
        assert!(!is_host_reserved("enclavid:policy/policy@0.1.0"));
        // Load-bearing distinction: the well-known plugin's `disclosure-fields`
        // (helper constructors it EXPORTS) is NOT the host's
        // `enclavid:embedded/disclosure-fields` (the reserved resolver). The
        // package segment is what separates them.
        assert!(!is_host_reserved(
            "enclavid:well-known/disclosure-fields@0.1.0"
        ));
    }
}
