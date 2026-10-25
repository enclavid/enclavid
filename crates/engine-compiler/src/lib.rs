//! `engine-compiler` — the COMPILE half of the engine fleet.
//!
//! Given a policy component and its pinned plugin components (already
//! pulled), [`Compiler`] fuses them into ONE component via `wac-graph`
//! single-store fusion, runs Cranelift codegen, and serializes the result
//! to `cwasm`. The embedded catalogs of every artifact, at every depth
//! ([`load_embedded_nested`]), and the slots the components' texts come
//! through ([`Composition::embedded_imports`]) ride alongside so the
//! executor can rebuild the host `Linker` + ref registry without
//! re-pulling.
//!
//! This is the ONLY crate that carries Cranelift. The execution half
//! ([`engine-executor`](../engine_executor/index.html)) structurally does
//! not depend on it, so the CVM that runs untrusted wasm carries no
//! compiler surface. The two halves share only the plain-data
//! `engine-types` leaf; the serialized `cwasm` bytes are the sole artifact
//! that crosses between them — never a live [`Component`].

mod compose;
mod decls;
mod disclosure_fields;
mod icons;
mod props;
mod texts;

// This role's own supervisor↔child hop. Behind a feature because the pure library
// — used by tests and by the child — stays free of rpc/remoc, and because a crate
// that only wants the Cranelift half should not link a contract it never speaks.
#[cfg(feature = "child-seam")]
mod seam;
#[cfg(feature = "child-seam")]
pub use seam::{
    ChildCompiled, RemoteCompileChild, RemoteCompileChildClient, RemoteCompileChildServerShared,
};

use wac_graph::types::Package;
use wasmtime::component::Component;
use wasmtime::{Config, Engine};

use engine_types::compile::{Artifact, CompileFault};
use engine_types::composition::{EmbeddedImport, PluginInstance};
use engine_types::embedded::ComponentDecls;
use engine_types::limits::MAX_EMBEDDED_SECTION_BYTES;

pub use decls::{
    CatalogRefused, EmbeddedCatalog, load_embedded, load_embedded_nested, top_level_imports,
};
use decls::{embedded_section_bytes, unreadable};
pub use enclavid_embedded::catalog_hash;

/// A fused policy component, the slots its host `Linker` must register,
/// and the catalogs its registry is built from. Returned by
/// [`Compiler::compose`], for tests and tooling that run a composition in
/// the process that compiled it; the fleet's compile output is
/// [`BundleParts`].
pub struct Composition {
    pub component: Component,
    pub embedded_imports: Vec<EmbeddedImport>,
    /// Same as [`BundleParts::catalogs`].
    pub catalogs: Vec<([u8; 32], ComponentDecls)>,
}

/// The serializable output of a compile, in engine-native types (NO rpc
/// dep): the `cwasm` bytes, the slots the components' texts come through,
/// and every catalog of the composition. This is exactly what the wire
/// `CompiledBundle` carries; `engine-compiler-child`, the disposable process
/// that runs the compile, wraps this into that wire type. Keeping it native
/// lets the pure lib produce the whole compile output without depending on
/// the `engine-rpc` contract.
pub struct BundleParts {
    pub cwasm: Vec<u8>,
    pub embedded_imports: Vec<EmbeddedImport>,
    /// `(catalog content-hash, decls)` of every catalog of every artifact,
    /// nested ones included, the policy's first — the registry-builder
    /// inputs.
    pub catalogs: Vec<([u8; 32], ComponentDecls)>,
}

/// The compile engine: owns a wasmtime [`Engine`] configured for Cranelift
/// codegen. A pure function of its inputs (no session state), so one
/// instance is shared across every `(policy, plugin-set)` compile.
pub struct Compiler {
    engine: Engine,
}

impl Compiler {
    pub fn new() -> wasmtime::Result<Self> {
        Ok(Self {
            engine: Engine::new(&engine_config())?,
        })
    }

    /// Compile a policy component from its binary (wasm or wat).
    pub fn compile(&self, bytes: &[u8]) -> wasmtime::Result<Component> {
        Component::new(&self.engine, bytes)
    }

    /// Serialize a compiled component to `cwasm` bytes for the L2
    /// compiled-artifact cache and the compile-boundary reply. The bytes
    /// are only valid on an engine built compatibly (same wasmtime version
    /// / `Config` / target) — the executor deserializes them on a matching
    /// engine and treats an incompatible load as a miss.
    pub fn serialize_component(&self, component: &Component) -> wasmtime::Result<Vec<u8>> {
        component.serialize()
    }

    /// Fuse a policy with plugins into one component's BYTES, wiring each
    /// import a plugin's interface names to that plugin and nothing more —
    /// what any fusion of embedded artifacts makes of them, the compile's own
    /// included. For tests and tooling that pin a composition fused before
    /// the session, as a consumer may with plain `wac`.
    pub fn fuse(
        &self,
        policy_wasm: &[u8],
        plugins: &[PluginInstance],
    ) -> wasmtime::Result<Vec<u8>> {
        compose::fuse(policy_wasm.to_vec(), lent(plugins))
    }

    /// The composition the fleet's compile would make of a policy and its
    /// pinned plugins (see [`compile_to_parts`](Self::compile_to_parts)),
    /// compiled and loaded, ready to run here. For tests and tooling, which
    /// run what they compile in the same process, and copy the components
    /// they lend it.
    ///
    /// This is a build-time step: the caller compiles once per
    /// `(policy, plugin-set)` and reuses the returned [`Composition`]
    /// across every reducer round.
    pub fn compose(
        &self,
        policy_wasm: &[u8],
        plugins: &[PluginInstance],
    ) -> wasmtime::Result<Composition> {
        let prepared = prepare(policy_wasm.to_vec(), lent(plugins))?;
        Ok(Composition {
            component: self.compile(prepared.fused.bytes())?,
            embedded_imports: prepared.embedded_imports,
            catalogs: prepared.catalogs,
        })
    }

    /// The whole compile-boundary output as [`BundleParts`]: read every
    /// artifact's catalogs and the slots its texts come through, fuse, check
    /// (see `prepare`), and Cranelift-compile to `cwasm`. Called by
    /// `engine-compiler-child` — the process the compile-worker spawns — which
    /// wraps the result into the wire `CompiledBundle`, so this orchestration
    /// lives ONCE, in the pure lib.
    ///
    /// Takes the components whole, so each form of the composition is let go
    /// once the next is made: the components once fused, the fused bytes once
    /// compiled. The compile writes its artifact straight into the `cwasm`
    /// bytes; nothing of it is loaded or made runnable here, so there is no
    /// loaded copy to serialize from.
    pub fn compile_to_parts(
        &self,
        policy_wasm: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> wasmtime::Result<BundleParts> {
        let prepared = prepare(policy_wasm, plugins)?;
        let cwasm = self
            .engine
            .precompile_component(prepared.fused.bytes())
            .map_err(|e| e.context(CompileFault::Invalid))?;
        Ok(BundleParts {
            cwasm,
            embedded_imports: prepared.embedded_imports,
            catalogs: prepared.catalogs,
        })
    }
}

/// A composition fused and checked, ready to compile.
struct Prepared {
    fused: Package,
    embedded_imports: Vec<EmbeddedImport>,
    catalogs: Vec<([u8; 32], ComponentDecls)>,
}

/// The composition a policy and its pinned plugins make: every artifact's
/// catalogs, at every depth, since a pre-fused artifact holds several; the
/// catalog each slot is served from (`compose::slots`); the components fused
/// (see `compose::fuse`) — with no plugins, the policy's own bytes — and
/// checked for what nothing would serve (`compose::served`).
///
/// A composition the pinned bytes decide against is refused: the error then
/// carries the [`CompileFault`] saying why, which the child answers as a
/// refusal. Before any section is parsed, one whose embedded sections are past
/// `MAX_EMBEDDED_SECTION_BYTES`; then one whose catalogs break their format, or
/// claim a slot or disclosure fields they may not, one that does not fuse, and
/// one that, fused, still imports what nothing serves or declares props, icons,
/// slots or disclosure fields in a shape the host cannot serve.
fn prepare(policy_wasm: Vec<u8>, plugins: Vec<PluginInstance>) -> wasmtime::Result<Prepared> {
    let components = || {
        std::iter::once((Artifact::Policy, &policy_wasm)).chain(
            plugins
                .iter()
                .map(|p| (Artifact::Plugin(p.package.clone()), &p.wasm)),
        )
    };
    // The cap first, on lengths alone: everything below parses, and what it
    // would parse is what the cap bounds. Summed over the whole composition,
    // because the plugin set is the consumer's to pin.
    let mut section_bytes = 0;
    for (artifact, wasm) in components() {
        section_bytes += embedded_section_bytes(wasm)
            .map_err(|e| e.context(CompileFault::NotAComponent(artifact)))?;
    }
    if section_bytes > MAX_EMBEDDED_SECTION_BYTES {
        return Err(wasmtime::Error::new(CompileFault::CatalogsPastCap));
    }
    let mut artifacts = Vec::with_capacity(1 + plugins.len());
    for (artifact, wasm) in components() {
        let catalogs = load_embedded_nested(wasm).map_err(|e| unreadable(artifact.clone(), e))?;
        artifacts.push((artifact, catalogs));
    }
    let slots = compose::slots(&artifacts)?;

    let plugged = !plugins.is_empty();
    let bytes = if plugged {
        compose::fuse(policy_wasm, plugins)?
    } else {
        policy_wasm
    };
    let declared = compose::Declared {
        slots,
        disclosure_fields: artifacts
            .iter()
            .flat_map(|(_, catalogs)| catalogs)
            .flat_map(|catalog| catalog.decls.disclosure_fields.iter().map(String::as_str))
            .collect(),
    };
    let (fused, embedded_imports) = compose::served(bytes, plugged, &declared)?;
    drop(declared);

    let catalogs = artifacts
        .into_iter()
        .flat_map(|(_, found)| found)
        .map(|c| (c.hash, c.decls))
        .collect();
    Ok(Prepared {
        fused,
        embedded_imports,
        catalogs,
    })
}

/// Owned copies of the plugins a caller lends, for the entry points that
/// borrow rather than take.
fn lent(plugins: &[PluginInstance]) -> Vec<PluginInstance> {
    plugins
        .iter()
        .map(|p| PluginInstance {
            package: p.package.clone(),
            wasm: p.wasm.clone(),
        })
        .collect()
}

/// The wasmtime [`Config`] both fleet halves build their [`Engine`] from.
/// It MUST be identical on the compile and execute sides: `consume_fuel`
/// compiles fuel checks INTO the code, so a mismatch would make a cwasm
/// serialized here fail the executor's compatibility-header check. Kept in
/// the compiler crate (the producer) and mirrored verbatim by the executor.
pub fn engine_config() -> Config {
    let mut config = Config::new();
    config.wasm_component_model(true);
    // Enable fuel accounting so per-Store budgets actually trap out a
    // runaway policy at run time. The flag affects codegen (fuel checks
    // are compiled in), so it must be set HERE, at compile time, to match
    // the executor's engine.
    config.consume_fuel(true);
    config
}
