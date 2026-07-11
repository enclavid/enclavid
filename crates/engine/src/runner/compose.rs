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
//! two, each component's `enclavid:host/embedded-<iface>` import is routed
//! to a DISTINCT composite import named by that component's catalog
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
        reject_policy_exclusive_imports(&graph, id, &plugin.package)?;
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
    // `enclavid:host/embedded-*` import is just the `localized-ref` type
    // dependency, which must NOT be re-routed.
    // Read prefused-ness off the imports wac already parsed when it
    // registered the package — no need to walk the component again just
    // for the top-level import names (`policy_fn_imports` below reads the
    // same map).
    let policy_prefused = graph.types()[graph[policy_id].ty()]
        .imports
        .keys()
        .any(|n| n.starts_with(EMBEDDED_SLOT_PREFIX));
    let mut manifest: Vec<EmbeddedImport> = Vec::new();
    let mut import_nodes: HashMap<String, NodeId> = HashMap::new();
    if !policy_prefused {
        route_strict_embedded(&mut graph, policy_inst, policy_id, &policy_hash, &mut import_nodes, &mut manifest)?;
    }
    for (inst, id, hash) in &plugin_insts {
        route_strict_embedded(&mut graph, *inst, *id, hash, &mut import_nodes, &mut manifest)?;
    }

    // Functional wiring: satisfy each import that names a PLUGIN interface
    // with the plugin that exports it — for the POLICY and for every PLUGIN.
    // Plugin→plugin wiring is real: a vision plugin (face-age, face-detect)
    // imports the `enclavid:vision/types` `decoded-frame` that the preprocess
    // plugin OWNS, so its `region` calls must dispatch to preprocess. Without
    // it, the consumer's plugin-interface import bubbles up unsatisfied and
    // the fused component fails validation. Host-reserved imports
    // (`is_host_reserved`) are deliberately excluded — served by the host
    // `Linker`, never a plugin — so they bubble up as composite imports
    // (covers `enclavid:host/*` and a pre-fused core's already-routed
    // `embedded-slot:*`). Any other unmatched import bubbles up too.
    let consumers: Vec<(NodeId, PackageId)> = std::iter::once((policy_inst, policy_id))
        .chain(plugin_insts.iter().map(|(inst, id, _)| (*inst, *id)))
        .collect();
    for (consumer_inst, consumer_id) in consumers {
        let fn_imports: Vec<String> = graph.types()[graph[consumer_id].ty()]
            .imports
            .iter()
            .filter(|(name, _)| !is_host_reserved(name))
            .map(|(name, _)| name.clone())
            .collect();
        for import_name in fn_imports {
            // Find the exporting plugin (never the consumer itself).
            let source = plugin_insts.iter().find_map(|(inst, id, _)| {
                (*id != consumer_id
                    && graph.types()[graph[*id].ty()]
                        .exports
                        .contains_key(&import_name))
                .then_some(*inst)
            });
            if let Some(inst) = source {
                let export = graph
                    .alias_instance_export(inst, &import_name)
                    .map_err(|e| wasmtime::Error::msg(format!("wac: alias export `{import_name}`: {e}")))?;
                graph
                    .set_instantiation_argument(consumer_inst, &import_name, export)
                    .map_err(|e| wasmtime::Error::msg(format!("wac: wire import `{import_name}`: {e}")))?;
            }
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
/// interface**: a structural clone of `enclavid:host/embedded-<iface>`
/// with a distinct id (`embedded-slot:<hash>/<iface>`). The component's
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
    let strict: Vec<(String, ItemKind, EmbeddedIface, String)> = graph.types()[graph[pkg_id].ty()]
        .imports
        .iter()
        .filter_map(|(name, kind)| {
            strict_iface(name).map(|iface| (name.clone(), *kind, iface, iface_version(name)))
        })
        .collect();
    for (import_name, kind, iface, version) in strict {
        // The twin name carries the interface version, so two components
        // with byte-identical catalogs (same slug) but different versions
        // route to DISTINCT twins rather than colliding onto one.
        let instance_name = embedded_import_name(hash, iface.as_str(), &version);
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
                    version,
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
        let Some((iface, version)) = slot_import_parts(&name) else {
            continue;
        };
        let catalog_hash = catalogs
            .iter()
            .map(|c| c.hash)
            .find(|h| embedded_import_name(h, iface.as_str(), &version) == name)
            .ok_or_else(|| {
                wasmtime::Error::msg(format!(
                    "pre-fused artifact imports `{name}` but no nested catalog matches it",
                ))
            })?;
        manifest.push(EmbeddedImport {
            instance_name: name,
            catalog_hash,
            iface,
            version,
        });
    }
    Ok(manifest)
}

/// The `@x.y.z` version of a canonical embedded import name, or empty if
/// unversioned. E.g. `enclavid:host/embedded-i18n@0.1.0` → `"0.1.0"`.
fn iface_version(name: &str) -> String {
    name.rsplit_once('@')
        .map(|(_, v)| v.to_string())
        .unwrap_or_default()
}

/// The `(kind, version)` of an already-routed `embedded-slot:*` import
/// name, or `None` if it isn't one. Inverse of [`embedded_import_name`]:
/// `embedded-slot:<slug>[-<ver>]/<iface>` → `(iface, version)`. The slug
/// is hex (no `-`), so the first `-` in the package segment separates it
/// from the hyphenated version; the version is de-hyphenated back to
/// dotted form.
fn slot_import_parts(name: &str) -> Option<(EmbeddedIface, String)> {
    let rest = name.strip_prefix(EMBEDDED_SLOT_PREFIX)?;
    let (pkg, iface_seg) = rest.rsplit_once('/')?;
    let iface = match iface_seg {
        "i18n" => EmbeddedIface::I18n,
        "icons" => EmbeddedIface::Icons,
        _ => return None,
    };
    let version = match pkg.split_once('-') {
        Some((_slug, ver)) => ver.replace('-', "."),
        None => String::new(),
    };
    Some((iface, version))
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
/// / non-embedded imports (which stay merged). Only `embedded-i18n` and
/// `embedded-icons` are per-component routed; `disclosure-fields` and
/// `session-context` stay merged / host-served as-is.
fn strict_iface(name: &str) -> Option<EmbeddedIface> {
    if name.starts_with("enclavid:host/embedded-i18n") {
        Some(EmbeddedIface::I18n)
    } else if name.starts_with("enclavid:host/embedded-icons") {
        Some(EmbeddedIface::Icons)
    } else {
        None
    }
}

/// Interfaces the TEE host `Linker` serves EXCLUSIVELY. A composed
/// plugin may IMPORT one (reading the same host surface the policy does)
/// but must never SATISFY one: wiring a plugin export into a
/// host-reserved import would let the plugin interpose on the session
/// config the policy reads (`session-context`), the applicant-facing
/// text / icons (`embedded-i18n` / `embedded-icons`), or the consumer
/// disclosure vocabulary (`disclosure-fields`) — all under the reserved
/// `enclavid:host/` package. Kept as ONE prefix check so a new host
/// capability under `enclavid:host/` is protected the moment it exists —
/// no per-interface filter to remember, no denylist to drift.
/// `embedded-slot:*` are the synthetic per-catalog twins fusion itself
/// derives from the `embedded-i18n` / `embedded-icons` imports,
/// host-owned by construction.
fn is_host_reserved(name: &str) -> bool {
    name.starts_with("enclavid:host/") || name.starts_with(EMBEDDED_SLOT_PREFIX)
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

/// Host interfaces only the POLICY may import — served by the host
/// `Linker` but backed by a SINGLE per-store `HostState`, so a plugin
/// importing one would read and clobber the policy's private state.
/// `enclavid:host/storage` is the policy's MUTABLE per-round memory (one
/// `HostState.kv`, no per-component partition — unlike the twin-routed
/// i18n/icons); the read-only shared surfaces (`session-context`,
/// `embedded-*`) are safe for a plugin to import, this is not. The
/// extension point for any future policy-only host capability.
fn is_policy_exclusive(name: &str) -> bool {
    name.starts_with("enclavid:host/storage")
}

/// Reject a plugin that IMPORTS a policy-exclusive host interface (see
/// [`is_policy_exclusive`]). Unlike the read-only host surfaces a plugin
/// may share, `enclavid:host/storage` is the policy's private mutable state
/// backed by one shared `HostState.kv` with no per-component partition —
/// letting a plugin import it would silently share and corrupt the policy's
/// reducer state across the untrusted-plugin boundary. Fail loud at fuse
/// time rather than bubbling the import up to the shared host `Linker`
/// (which the `is_host_reserved` wiring filter would otherwise do).
fn reject_policy_exclusive_imports(
    graph: &CompositionGraph,
    pkg_id: PackageId,
    package: &str,
) -> wasmtime::Result<()> {
    for name in graph.types()[graph[pkg_id].ty()].imports.keys() {
        if is_policy_exclusive(name) {
            return Err(wasmtime::Error::msg(format!(
                "plugin `{package}` imports policy-exclusive interface `{name}`: \
                 `enclavid:host/storage` is the policy's private per-round state \
                 (one shared HostState.kv, no per-component partition), so only the \
                 policy may import it",
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
        assert!(is_host_reserved("enclavid:host/embedded-i18n@0.1.0"));
        assert!(is_host_reserved("enclavid:host/embedded-icons@0.1.0"));
        assert!(is_host_reserved("enclavid:host/embedded-disclosure-fields@0.1.0"));
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
        // `enclavid:host/embedded-disclosure-fields` (the reserved resolver). The
        // package segment is what separates them.
        assert!(!is_host_reserved(
            "enclavid:well-known/disclosure-fields@0.1.0"
        ));
    }

    #[test]
    fn policy_exclusive_is_storage_only() {
        // `storage` is the policy's private MUTABLE state — a plugin
        // importing it would share the one `HostState.kv`, so it is
        // policy-exclusive and rejected at fuse time.
        assert!(is_policy_exclusive("enclavid:host/storage@0.1.0"));
        // The read-only shared host surfaces stay plugin-importable — they
        // are host-reserved (host-served) but NOT policy-exclusive.
        assert!(!is_policy_exclusive("enclavid:host/session-context@0.1.0"));
        assert!(!is_policy_exclusive("enclavid:host/embedded-i18n@0.1.0"));
        // A plugin's own interfaces are never policy-exclusive.
        assert!(!is_policy_exclusive("enclavid:well-known/capture@0.1.0"));
    }
}
