//! Single-store fusion of a policy with its plugins via `wac-graph`, and what
//! a fused composition is held to before it is compiled.
//!
//! [`fuse`] wires each import that names a plugin's interface to the plugin
//! that exports it, and nothing more. The host's own interfaces are never
//! wired to a plugin: they bubble up, and the host serves them. Among them
//! are the slots a component's texts come through, which its embedding named
//! after its catalog (`embedded-slot:<slug>-<ver>/i18n`): their names differ
//! wherever catalogs differ, so ANY fusion keeps every component's texts
//! apart without knowing about them — this one, or one a consumer ran with
//! plain `wac` before pinning what it made.
//!
//! The result is ONE component (one wasmtime `Store` at run time, so
//! cross-component WIT resources are native handles).

use std::collections::HashSet;

use enclavid_embedded::Catalog;
use enclavid_embedded::embedded_import_name;
use wac_graph::types::{DefinedType, ItemKind, Package, ResourceId, Type, Types, ValueType};
use wac_graph::{
    CompositionGraph, EncodeError, EncodeOptions, InstantiationArgumentError, NodeId, PackageId,
};
use wasmtime_environ::component::alternate_lookup_key;

use engine_types::compile::{Artifact, CompileFault, HOST_INTERFACES};
use engine_types::composition::{EmbeddedIface, EmbeddedImport, PluginInstance};

use crate::decls::EmbeddedCatalog;
use crate::top_level_imports;
use crate::{disclosure_fields, icons, props, texts};

/// Namespace prefix of the imports a component's texts come through.
const EMBEDDED_SLOT_PREFIX: &str = "embedded-slot:";

/// The interface the resources the host mints belong to.
const HOST_TYPES: &str = "enclavid:host/types@0.1.0";

/// Package label for the policy in the composition graph. Only a
/// registration key (its uniqueness against the plugin labels is all
/// that matters) — wac matches by interface name, not this label.
const POLICY_PACKAGE: &str = "enclavid:composed-policy";

/// Fuse `policy_wasm` with `plugins` into one component's bytes.
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
) -> wasmtime::Result<Vec<u8>> {
    let mut graph = CompositionGraph::new();

    let policy_id = register(&mut graph, POLICY_PACKAGE, policy_wasm, Artifact::Policy)?;
    let mut plugin_ids: Vec<PackageId> = Vec::with_capacity(plugins.len());
    for plugin in plugins {
        let artifact = Artifact::Plugin(plugin.package.clone());
        let id = register(&mut graph, &plugin.package, plugin.wasm, artifact)?;
        reject_reserved_exports(&graph, id, &plugin.package)?;
        plugin_ids.push(id);
    }

    let policy_inst = graph.instantiate(policy_id);
    let plugin_insts: Vec<(NodeId, PackageId)> = plugin_ids
        .iter()
        .map(|id| (graph.instantiate(*id), *id))
        .collect();

    // Functional wiring: satisfy each import that names a PLUGIN interface
    // with the plugin that exports it — for the POLICY and for every PLUGIN.
    // Plugin→plugin wiring is real: a vision plugin (face-age, face-detect)
    // imports the `enclavid:vision/types` `decoded-frame` that the preprocess
    // plugin OWNS, so its `region` calls must dispatch to preprocess. Without
    // it, the consumer's plugin-interface import bubbles up unsatisfied and
    // the fused component fails validation. Host-reserved imports
    // (`is_host_reserved`) are deliberately excluded — served by the host
    // `Linker`, never a plugin — so they bubble up as composite imports
    // (covers `enclavid:host/*` and the `embedded-slot:*` the texts come
    // through). Any other unmatched import bubbles up too.
    let consumers: Vec<(NodeId, PackageId)> = std::iter::once((policy_inst, policy_id))
        .chain(plugin_insts.iter().copied())
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
            let source = plugin_insts.iter().find_map(|(inst, id)| {
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

    graph.encode(EncodeOptions::default()).map_err(encoding)
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

/// The slots `wasm`, one artifact of a composition, takes its texts through:
/// each `embedded-slot:` import it has, with the index in `catalogs` — the
/// artifact's own, every depth — of the catalog the slot is named after. A
/// slot no catalog of the artifact's names is refused: there would be nothing
/// to serve it from but another component's texts.
pub(crate) fn slots(
    wasm: &[u8],
    artifact: &Artifact,
    catalogs: &[EmbeddedCatalog],
) -> wasmtime::Result<Vec<(EmbeddedImport, usize)>> {
    let imports = top_level_imports(wasm)
        .map_err(|e| e.context(CompileFault::NotAComponent(artifact.clone())))?;
    let mut slots = Vec::new();
    for name in imports {
        if !name.starts_with(EMBEDDED_SLOT_PREFIX) {
            continue;
        }
        let named = slot_import_parts(&name).and_then(|(iface, version)| {
            catalogs
                .iter()
                .position(|c| embedded_import_name(&c.hash, iface.as_str(), &version) == name)
                .map(|index| (iface, version, index))
        });
        let Some((iface, version, index)) = named else {
            return Err(wasmtime::Error::msg(format!(
                "the artifact imports `{name}`, which names no catalog of its own",
            ))
            .context(CompileFault::CatalogInvalid(artifact.clone())));
        };
        slots.push((
            EmbeddedImport {
                instance_name: name,
                catalog_hash: catalogs[index].hash,
                iface,
                version,
            },
            index,
        ));
    }
    Ok(slots)
}

/// What a fused composition is held to beside the host's own interfaces.
pub(crate) struct Declared<'a> {
    /// The slots its components' texts come through, each with the artifact
    /// that imports it and the texts of the catalog it is named after.
    pub slots: Vec<(Artifact, &'a EmbeddedImport, &'a Catalog)>,
    /// The disclosure fields its catalogs declare.
    pub disclosure_fields: HashSet<&'a str>,
}

/// The fused composition, refused if it still imports an interface nothing
/// serves: neither the host ([`HOST_INTERFACES`], matched as wasmtime's linker
/// matches a name, and the slots of `declared`) nor — an interface of types
/// alone, its resources all another's — one that needs nothing served. No
/// round of such a composition could run: the execution-worker's linker
/// refuses it before one does. Refused as well: a second import of one of the
/// host's interfaces, at another version on its semver track.
///
/// Read as a wac package, which validates everything but the function bodies,
/// and kept as one, so the bytes are compiled from where they are. What it
/// declares in a shape the host cannot serve is refused too: its props
/// ([`props::declared`]), its icons ([`icons::declared`]), its slots and the
/// texts behind them ([`texts::declared`]), and its disclosure fields
/// ([`disclosure_fields::declared`]). `plugged` says whether there was a
/// fusion: without one the bytes are the policy's own, and bytes that do not
/// read are the policy not being a component.
pub(crate) fn served(
    bytes: Vec<u8>,
    plugged: bool,
    declared: &Declared,
) -> wasmtime::Result<Package> {
    let mut types = Types::default();
    let package = Package::from_bytes("enclavid:fused", None, bytes, &mut types).map_err(|e| {
        let fault = if plugged {
            CompileFault::Invalid
        } else {
            CompileFault::NotAComponent(Artifact::Policy)
        };
        wasmtime::Error::msg(format!("wac: read the fused component: {e}")).context(fault)
    })?;
    let mut hosted: Vec<&str> = Vec::new();
    for (name, kind) in &types[package.ty()].imports {
        let served = if name.starts_with(EMBEDDED_SLOT_PREFIX) {
            declared
                .slots
                .iter()
                .any(|(_, slot, _)| slot.instance_name == *name)
        } else if let Some(host) = host_interface(name) {
            // The host serves an interface from one definition, which the
            // linker gives every import on its semver track. A second import
            // on the track would be served the first one's: refused, so that
            // what `props`, `icons` and `disclosure_fields` check below is
            // every import of their interface.
            if hosted.contains(&host) {
                return Err(wasmtime::Error::msg(format!(
                    "`{name}` imports a second time an interface the host serves once"
                ))
                .context(CompileFault::about(name, CompileFault::Mismatched)));
            }
            hosted.push(host);
            true
        } else {
            !needs_serving(&types, kind)
        };
        if !served {
            return Err(
                wasmtime::Error::msg(format!("nothing serves the import `{name}`"))
                    .context(CompileFault::about(name, CompileFault::Unsatisfied)),
            );
        }
    }
    props::declared(&types, &package).map_err(wasmtime::Error::new)?;
    icons::declared(&types, &package).map_err(wasmtime::Error::new)?;
    texts::declared(&types, &package, &declared.slots).map_err(wasmtime::Error::new)?;
    disclosure_fields::declared(&types, &package, &declared.disclosure_fields)
        .map_err(wasmtime::Error::new)?;
    Ok(package)
}

/// Which of [`HOST_INTERFACES`] the import `name` is, if the host serves it.
fn host_interface(name: &str) -> Option<&'static str> {
    HOST_INTERFACES
        .iter()
        .copied()
        .find(|host| same_interface(name, host))
}

/// Whether an import `name` is the interface `host` serves: `host` exactly, or a
/// semver-compatible version of it — the rule wasmtime's linker looks a name up
/// by.
pub(crate) fn same_interface(name: &str, host: &str) -> bool {
    name == host
        || alternate_lookup_key(name).is_some_and(|(track, _)| {
            alternate_lookup_key(host).is_some_and(|(key, _)| key == track)
        })
}

/// Whether an import has to be served to instantiate: a function, a component,
/// a module, a resource of its own, or an interface holding any of those. An
/// interface of value types, and of resources aliased from another, needs
/// nothing — as wasmtime's linker sees it.
pub(crate) fn needs_serving(types: &Types, kind: &ItemKind) -> bool {
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

/// Whether the resource `id` is, through any aliases, the resource `name` of
/// the host's types interface — one the host mints — rather than another of
/// the host's resources or one a component declares itself.
pub(crate) fn is_host_resource(types: &Types, id: ResourceId, name: &str) -> bool {
    let Some(alias) = &types[id].alias else {
        return false;
    };
    let from_host = alias.owner.is_some_and(|owner| {
        types[owner]
            .id
            .as_deref()
            .is_some_and(|owner| same_interface(owner, HOST_TYPES))
    });
    (from_host && types[alias.source].name == name) || is_host_resource(types, alias.source, name)
}

/// The type `ty` defines, through any aliases; `None` for a primitive or a
/// handle.
pub(crate) fn defined<'t>(types: &'t Types, ty: &ValueType) -> Option<&'t DefinedType> {
    match ty {
        ValueType::Defined(id) => match &types[*id] {
            DefinedType::Alias(ty) => defined(types, ty),
            other => Some(other),
        },
        ValueType::Primitive(_) | ValueType::Own(_) | ValueType::Borrow(_) => None,
    }
}

/// The `(kind, version)` of an `embedded-slot:*` import name, or `None` if it
/// isn't one. Inverse of [`embedded_import_name`]:
/// `embedded-slot:<slug>[-<ver>]/<iface>` → `(iface, version)`. The slug
/// is hex (no `-`), so the first `-` in the package segment separates it
/// from the hyphenated version; the version is de-hyphenated back to
/// dotted form.
fn slot_import_parts(name: &str) -> Option<(EmbeddedIface, String)> {
    let rest = name.strip_prefix(EMBEDDED_SLOT_PREFIX)?;
    let (pkg, iface_seg) = rest.rsplit_once('/')?;
    let iface = match iface_seg {
        "i18n" => EmbeddedIface::I18n,
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

/// Interfaces the TEE host `Linker` serves EXCLUSIVELY. A composed
/// plugin may IMPORT one (reading the same host surface the policy does)
/// but must never SATISFY one: wiring a plugin export into a
/// host-reserved import would let the plugin interpose on the props the
/// policy reads (`enclavid:host-ext/policy-props`), the applicant-facing
/// texts and icons (the `embedded-slot:*` slots, `enclavid:host-icons/icons`),
/// or the consumer disclosure vocabulary (`enclavid:host-ext/disclosure-fields`,
/// `enclavid:host/embedded-disclosure-fields`). Reserved is every
/// interface of `enclavid:host` and of any `enclavid:host-*` package —
/// `host-ext` is the one whose WIT the policy writes itself, since the props'
/// and the disclosure fields' types are its own. Kept as ONE prefix rule so a
/// new host capability in those packages is protected the moment it exists —
/// no per-interface filter to remember, no denylist to drift.
///
/// All of `wasi:` is reserved too. The host serves the clocks and randomness
/// as the round's own values, and a plugin satisfying them would hand the
/// policy a clock or a random stream of its own choosing; the rest it serves
/// empty or not at all, so a plugin has no business with any of it.
fn is_host_reserved(name: &str) -> bool {
    if name.starts_with(EMBEDDED_SLOT_PREFIX) || name.starts_with("wasi:") {
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
        assert!(is_host_reserved(
            "enclavid:host-ext/disclosure-fields@0.1.0"
        ));
        // A future host capability in `enclavid:host` or a `enclavid:host-*`
        // package is protected the moment it exists — no edit to this
        // predicate needed.
        assert!(is_host_reserved("enclavid:host/timer@0.1.0"));
        assert!(is_host_reserved("enclavid:host-next/timer@0.1.0"));
        assert!(is_host_reserved("enclavid:host-icons/icons@0.1.0"));
        assert!(is_host_reserved(
            "enclavid:host/embedded-disclosure-fields@0.1.0"
        ));
        // The slots a component's texts come through, named at embedding.
        assert!(is_host_reserved("embedded-slot:h0123456789abcdef/i18n"));
        // Every `wasi:` interface: the served clocks and randomness, and the
        // ones nothing serves.
        assert!(is_host_reserved("wasi:clocks/wall-clock@0.2.12"));
        assert!(is_host_reserved("wasi:random/random@0.2.0"));
        assert!(is_host_reserved("wasi:filesystem/types@0.2.12"));
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
        // A component's own `i18n`, before its embedding renames it to a slot,
        // is its own interface: nothing serves it, and the compile refuses it
        // as unsatisfied rather than letting a plugin serve it.
        assert!(!is_host_reserved("enclavid:well-known/i18n@0.1.0"));
        // Only `host` and `host-*` packages, and only in `enclavid`: a package
        // that merely starts with the letters, or another namespace's `host`,
        // stays satisfiable.
        assert!(!is_host_reserved("enclavid:hosting/plan@0.1.0"));
        assert!(!is_host_reserved("acme:host/props@0.1.0"));
    }

    #[test]
    fn a_slot_name_reads_back_as_its_kind_and_version() {
        let hash = [7u8; 32];
        for version in ["0.1.0", ""] {
            let name = embedded_import_name(&hash, "i18n", version);
            assert_eq!(
                slot_import_parts(&name),
                Some((EmbeddedIface::I18n, version.to_string()))
            );
        }
        assert_eq!(slot_import_parts("embedded-slot:h00-0-1-0/icons"), None);
    }
}
