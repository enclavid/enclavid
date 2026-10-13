//! Single-store fusion of a policy with its plugins via `wac-graph`,
//! with strict per-component routing of the applicant-facing embedded
//! imports (i18n / icons).
//!
//! [`fuse`] builds the composition graph by hand rather than using the
//! high-level `wac_graph::plug` helper, because `plug` MERGES every
//! same-named unsatisfied import into one — which is what we want for
//! `disclosure-fields` (option B: DF is merged, first-match, bounded by
//! the visible static-set size) and `enclavid:host-ext/policy-props`, but NOT
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

use wac_graph::types::{ItemKind, Package, Type, Types};
use wac_graph::{
    CompositionGraph, EncodeError, EncodeOptions, InstantiationArgumentError, NodeId, PackageId,
};
use wasmtime_environ::component::alternate_lookup_key;

use engine_types::compile::{Artifact, CompileFault, HOST_INTERFACES};
use engine_types::composition::{EmbeddedIface, EmbeddedImport, PluginInstance};

use crate::decls::unreadable;
use crate::{embedded_import_name, load_embedded, load_embedded_nested, top_level_imports};

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
/// Takes the components whole: the graph keeps them as they are rather than
/// a copy, and they are gone once the fused bytes are made, so a composition
/// is held twice at most here — its components and the component they become.
///
/// Fails loud if a component's bytes aren't a component, if two plugins
/// register under the same `package` id, or if a wac graph operation
/// fails (e.g. a type mismatch on a functional wiring). Where the failure is
/// the composition's, the error carries the [`CompileFault`] saying which.
pub(crate) fn fuse(
    policy_wasm: Vec<u8>,
    plugins: Vec<PluginInstance>,
) -> wasmtime::Result<(Vec<u8>, Vec<EmbeddedImport>)> {
    let mut graph = CompositionGraph::new();

    let policy_id = register(&mut graph, POLICY_PACKAGE, policy_wasm, Artifact::Policy)?;
    let policy_hash = catalog_hash_of(graph[policy_id].bytes(), Artifact::Policy)?;

    let mut plugin_pkgs: Vec<(PackageId, [u8; 32])> = Vec::with_capacity(plugins.len());
    for plugin in plugins {
        let artifact = Artifact::Plugin(plugin.package.clone());
        let id = register(&mut graph, &plugin.package, plugin.wasm, artifact.clone())?;
        reject_reserved_exports(&graph, id, &plugin.package)?;
        plugin_pkgs.push((id, catalog_hash_of(graph[id].bytes(), artifact)?));
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
        route_strict_embedded(
            &mut graph,
            policy_inst,
            policy_id,
            &policy_hash,
            &mut import_nodes,
            &mut manifest,
        )?;
    }
    for (inst, id, hash) in &plugin_insts {
        route_strict_embedded(
            &mut graph,
            *inst,
            *id,
            hash,
            &mut import_nodes,
            &mut manifest,
        )?;
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
                    .map_err(|e| {
                        wasmtime::Error::msg(format!("wac: alias export `{import_name}`: {e}"))
                    })?;
                graph
                    .set_instantiation_argument(consumer_inst, &import_name, export)
                    .map_err(|e| wiring(&import_name, e))?;
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

    let bytes = graph.encode(EncodeOptions::default()).map_err(encoding)?;
    Ok((bytes, manifest))
}

/// A wiring error as the compile answers it: a plugin's export that is not of
/// the type the import names is the composition's, and refuses it.
fn wiring(import_name: &str, e: InstantiationArgumentError) -> wasmtime::Error {
    let mismatched = matches!(e, InstantiationArgumentError::ArgumentTypeMismatch { .. });
    let e = wasmtime::Error::msg(format!("wac: wire import `{import_name}`: {e}"));
    if mismatched {
        e.context(CompileFault::about(import_name, CompileFault::Mismatched))
    } else {
        e
    }
}

/// An encoding error as the compile answers it. Each is the composition's: two
/// components importing one interface as different types, or a fused component
/// that does not validate.
fn encoding(e: EncodeError) -> wasmtime::Error {
    let fault = match &e {
        EncodeError::ImportTypeMergeConflict { import, .. } => {
            CompileFault::about(import, CompileFault::Mismatched)
        }
        EncodeError::ImplicitImportConflict { name, .. } => {
            CompileFault::about(name, CompileFault::Mismatched)
        }
        _ => CompileFault::Invalid,
    };
    wasmtime::Error::msg(format!("wac: encode fused component: {e}")).context(fault)
}

/// The fused composition, refused if it still imports an interface nothing
/// serves: neither the host ([`HOST_INTERFACES`], matched as wasmtime's linker
/// matches a name, and the `embedded-slot:` twins fusion named itself) nor —
/// an interface of types alone, its resources all another's — one that needs
/// nothing served. No round of such a composition could run: the
/// execution-worker's linker refuses it before one does.
///
/// Read as a wac package, which validates everything but the function bodies,
/// and kept as one, so the bytes are compiled from where they are. `plugged`
/// says whether there was a fusion: without one the bytes are the policy's
/// own, and bytes that do not read are the policy not being a component.
pub(crate) fn served(bytes: Vec<u8>, plugged: bool) -> wasmtime::Result<Package> {
    let mut types = Types::default();
    let package = Package::from_bytes("enclavid:fused", None, bytes, &mut types).map_err(|e| {
        let fault = if plugged {
            CompileFault::Invalid
        } else {
            CompileFault::NotAComponent(Artifact::Policy)
        };
        wasmtime::Error::msg(format!("wac: read the fused component: {e}")).context(fault)
    })?;
    for (name, kind) in &types[package.ty()].imports {
        if !name.starts_with(EMBEDDED_SLOT_PREFIX)
            && !served_by_host(name)
            && needs_serving(&types, kind)
        {
            return Err(
                wasmtime::Error::msg(format!("nothing serves the import `{name}`"))
                    .context(CompileFault::about(name, CompileFault::Unsatisfied)),
            );
        }
    }
    Ok(package)
}

/// Whether the host serves `name`: one of [`HOST_INTERFACES`] exactly, or a
/// semver-compatible version of one — the rule wasmtime's linker looks a name
/// up by.
fn served_by_host(name: &str) -> bool {
    let track = alternate_lookup_key(name).map(|(key, _)| key);
    HOST_INTERFACES.iter().any(|host| {
        *host == name
            || track.is_some_and(|track| {
                alternate_lookup_key(host).is_some_and(|(key, _)| key == track)
            })
    })
}

/// Whether an import has to be served to instantiate: a function, a component,
/// a module, a resource of its own, or an interface holding any of those. An
/// interface of value types, and of resources aliased from another, needs
/// nothing — as wasmtime's linker sees it.
fn needs_serving(types: &Types, kind: &ItemKind) -> bool {
    match kind {
        ItemKind::Instance(id) => types[*id]
            .exports
            .values()
            .any(|export| needs_serving(types, export)),
        ItemKind::Type(Type::Resource(id)) => types[*id].alias.is_none(),
        ItemKind::Type(_) | ItemKind::Value(_) => false,
        ItemKind::Func(_) | ItemKind::Component(_) | ItemKind::Module(_) => true,
    }
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
                    ))
                    .context(CompileFault::about(&import_name, CompileFault::Mismatched)));
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
        graph
            .set_instantiation_argument(inst, &import_name, node)
            .map_err(|e| wiring(&import_name, e))?;
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
    let catalogs = load_embedded_nested(wasm).map_err(|e| unreadable(Artifact::Policy, e))?;
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
                .context(CompileFault::CatalogInvalid(Artifact::Policy))
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

/// Register a component's bytes as a package in the graph, which keeps them.
fn register(
    graph: &mut CompositionGraph,
    name: &str,
    wasm: Vec<u8>,
    artifact: Artifact,
) -> wasmtime::Result<PackageId> {
    let pkg = Package::from_bytes(name, None, wasm, graph.types_mut()).map_err(|e| {
        wasmtime::Error::msg(format!("wac: parse component `{name}`: {e}"))
            .context(CompileFault::NotAComponent(artifact))
    })?;
    graph
        .register_package(pkg)
        .map_err(|e| wasmtime::Error::msg(format!("wac: register `{name}`: {e}")))
}

/// Content-hash of a component's own (top-level) embedded catalog.
fn catalog_hash_of(wasm: &[u8], artifact: Artifact) -> wasmtime::Result<[u8; 32]> {
    Ok(load_embedded(wasm)
        .map_err(|e| unreadable(artifact, e))?
        .hash)
}

/// The strict-routed kind of an embedded import name, or `None` for DF
/// / non-embedded imports (which stay merged). Only `embedded-i18n` and
/// `embedded-icons` are per-component routed; `disclosure-fields` and
/// `policy-props` stay merged / host-served as-is.
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
/// host-reserved import would let the plugin interpose on the props the
/// policy reads (`enclavid:host-ext/policy-props`), the applicant-facing
/// text / icons (`embedded-i18n` / `embedded-icons`), or the consumer
/// disclosure vocabulary (`disclosure-fields`). Reserved is every interface
/// of `enclavid:host` and of any `enclavid:host-*` package — `host-ext` is
/// the one whose WIT the policy writes itself, since the props' type is its
/// own. Kept as ONE prefix rule so a new host capability in those packages is
/// protected the moment it exists — no per-interface filter to remember, no
/// denylist to drift. `embedded-slot:*` are the synthetic per-catalog twins
/// fusion itself derives from the `embedded-i18n` / `embedded-icons`
/// imports, host-owned by construction.
fn is_host_reserved(name: &str) -> bool {
    if name.starts_with(EMBEDDED_SLOT_PREFIX) {
        return true;
    }
    name.strip_prefix("enclavid:")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(package, _)| package == "host" || package.starts_with("host-"))
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
            ))
            .context(CompileFault::ReservedExport(Artifact::Plugin(
                package.into(),
            ))));
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
        assert!(is_host_reserved("enclavid:host-ext/policy-props@0.1.0"));
        // A future host capability in `enclavid:host` or a `enclavid:host-*`
        // package is protected the moment it exists — no edit to this
        // predicate needed.
        assert!(is_host_reserved("enclavid:host/timer@0.1.0"));
        assert!(is_host_reserved("enclavid:host-next/timer@0.1.0"));
        assert!(is_host_reserved("enclavid:host/embedded-i18n@0.1.0"));
        assert!(is_host_reserved("enclavid:host/embedded-icons@0.1.0"));
        assert!(is_host_reserved(
            "enclavid:host/embedded-disclosure-fields@0.1.0"
        ));
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
        // Only `host` and `host-*` packages, and only in `enclavid`: a package
        // that merely starts with the letters, or another namespace's `host`,
        // stays satisfiable.
        assert!(!is_host_reserved("enclavid:hosting/plan@0.1.0"));
        assert!(!is_host_reserved("acme:host/props@0.1.0"));
    }
}
