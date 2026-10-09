//! `engine-compiler` — the COMPILE half of the engine fleet.
//!
//! Given a policy component and its pinned plugin components (already
//! pulled), [`Compiler`] fuses them into ONE component via `wac-graph`
//! single-store fusion, runs Cranelift codegen, and serializes the result
//! to `cwasm`. The parsed embedded catalogs ([`load_embedded`]) and the
//! per-catalog import manifest ([`Composition::embedded_imports`]) ride
//! alongside so the executor can rebuild the host `Linker` + ref registry
//! without re-pulling.
//!
//! This is the ONLY crate that carries Cranelift. The execution half
//! ([`engine-executor`](../engine_executor/index.html)) structurally does
//! not depend on it, so the CVM that runs untrusted wasm carries no
//! compiler surface. The two halves share only the plain-data
//! `engine-types` leaf; the serialized `cwasm` bytes are the sole artifact
//! that crosses between them — never a live [`Component`].

mod compose;
mod decls;
mod hash;

// This role's own supervisor↔child hop. Behind a feature because the pure library
// — used by tests and by the child — stays free of rpc/remoc, and because a crate
// that only wants the Cranelift half should not link a contract it never speaks.
#[cfg(feature = "child-seam")]
mod seam;
#[cfg(feature = "child-seam")]
pub use seam::{
    ChildCompiled, CompileChildService, CompileChildServiceClient, CompileChildServiceServerShared,
};

use wasmtime::component::Component;
use wasmtime::{Config, Engine};

use engine_types::composition::{EmbeddedImport, PluginInstance};
use engine_types::embedded::ComponentDecls;
use engine_types::limits::MAX_EMBEDDED_SECTION_BYTES;

use decls::embedded_section_bytes;
pub use decls::{
    CatalogRefused, EmbeddedCatalog, load_embedded, load_embedded_nested, top_level_imports,
};
pub use hash::{catalog_hash, embedded_import_name, slug};

/// A fused policy component plus the manifest of distinct embedded
/// imports its host `Linker` must register. Returned by
/// [`Compiler::compose`], for tests and tooling that run a composition in
/// the process that compiled it; the fleet's compile output is
/// [`BundleParts`].
pub struct Composition {
    pub component: Component,
    pub embedded_imports: Vec<EmbeddedImport>,
}

/// The serializable output of a compile, in engine-native types (NO rpc
/// dep): the `cwasm` bytes, the per-catalog import manifest, and the parsed
/// per-component catalogs. This is exactly what the wire `CompiledBundle`
/// carries; `engine-compiler-child`, the disposable process that runs the
/// compile, wraps this into that wire type. Keeping it native lets the pure lib
/// produce the whole compile output without depending on the `engine-rpc`
/// contract.
pub struct BundleParts {
    pub cwasm: Vec<u8>,
    pub embedded_imports: Vec<EmbeddedImport>,
    /// Per-component `(catalog content-hash, parsed decls)`, composition
    /// order (policy first) — the registry-builder inputs.
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

    /// Fuse a policy with plugins into a self-contained component's
    /// BYTES — the strict-routed static artifact `enclavid link` would
    /// publish. The embedded manifest is reconstructed from these bytes
    /// at load time (see `compose::reconstruct_strict_manifest`), so
    /// it isn't returned here.
    pub fn fuse(
        &self,
        policy_wasm: &[u8],
        plugins: &[PluginInstance],
    ) -> wasmtime::Result<Vec<u8>> {
        let (bytes, _manifest) = compose::fuse(policy_wasm.to_vec(), lent(plugins))?;
        Ok(bytes)
    }

    /// Fuse a policy with its pinned plugins into ONE component (see
    /// `fused`) and compile it, loaded and ready to run here. For tests and
    /// tooling, which run what they compile in the same process, and copy the
    /// components they lend it; the fleet's compile is
    /// [`compile_to_parts`](Self::compile_to_parts).
    ///
    /// This is a build-time step: the caller compiles once per
    /// `(policy, plugin-set)` and reuses the returned [`Composition`]
    /// across every reducer round.
    pub fn compose(
        &self,
        policy_wasm: &[u8],
        plugins: &[PluginInstance],
    ) -> wasmtime::Result<Composition> {
        let (bytes, embedded_imports) = fused(policy_wasm.to_vec(), lent(plugins))?;
        Ok(Composition {
            component: self.compile(&bytes)?,
            embedded_imports,
        })
    }

    /// The whole compile-boundary output as [`BundleParts`]: parse each
    /// component's embedded catalog (composition order, policy first), fuse
    /// (see `fused`), and Cranelift-compile to `cwasm`. Called by
    /// `engine-compiler-child` — the process the compile-worker spawns — which
    /// wraps the result into the wire `CompiledBundle`, so this orchestration
    /// lives ONCE, in the pure lib.
    ///
    /// Takes the components whole, so each form of the composition is let go
    /// once the next is made: the components once fused, the fused bytes once
    /// compiled. The compile writes its artifact straight into the `cwasm`
    /// bytes; nothing of it is loaded or made runnable here, so there is no
    /// loaded copy to serialize from.
    ///
    /// Refuses, before any section is parsed, a composition whose embedded
    /// sections are past `MAX_EMBEDDED_SECTION_BYTES`, and then one whose
    /// catalogs break their format; the error then carries a [`CatalogRefused`],
    /// which the child answers as a refusal. [`compose`](Self::compose) and
    /// [`fuse`](Self::fuse), which tests and tooling call directly, hold no such
    /// cap.
    pub fn compile_to_parts(
        &self,
        policy_wasm: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> wasmtime::Result<BundleParts> {
        // The cap first, on lengths alone: everything below parses, and what it
        // would parse is what the cap bounds. Summed over the whole composition,
        // because the plugin set is the consumer's to pin.
        let mut section_bytes = embedded_section_bytes(&policy_wasm)?;
        for p in &plugins {
            section_bytes += embedded_section_bytes(&p.wasm)?;
        }
        if section_bytes > MAX_EMBEDDED_SECTION_BYTES {
            return Err(wasmtime::Error::new(CatalogRefused::PastCap));
        }
        let policy_catalog = load_embedded(&policy_wasm)?;
        let mut catalogs = Vec::with_capacity(1 + plugins.len());
        catalogs.push((policy_catalog.hash, policy_catalog.decls));
        for p in &plugins {
            let c = load_embedded(&p.wasm)?;
            catalogs.push((c.hash, c.decls));
        }
        let (bytes, embedded_imports) = fused(policy_wasm, plugins)?;
        let cwasm = self.engine.precompile_component(&bytes)?;
        Ok(BundleParts {
            cwasm,
            embedded_imports,
            catalogs,
        })
    }
}

/// The bytes a composition compiles from, and the manifest of distinct
/// embedded imports its host `Linker` must register. `wac-graph`
/// single-store fusion (see `compose::fuse`) wires every plugin export into
/// the policy's imports; the result runs in one wasmtime `Store`, so
/// cross-component WIT resources are native handles. With no plugins the
/// bytes are the policy's own.
///
/// Three shapes are handled:
///
///   * **Dynamic** — a non-fused policy plus runtime `plugins`:
///     `compose::fuse` routes each component's i18n / icons import
///     to a distinct per-catalog import (the manifest).
///   * **Static** — a pre-fused policy artifact with no runtime
///     plugins: compiled as-is; the manifest is reconstructed from
///     the `embedded-slot:*` imports the artifact already carries
///     (empty for a lone unfused policy, whose canonical embedded
///     imports the host serves first-match).
///   * **Hybrid** — a pre-fused core plus runtime `plugins`: fused
///     again; the core's own routed imports bubble through and are
///     re-emitted alongside the freshly routed runtime ones.
fn fused(
    policy_wasm: Vec<u8>,
    plugins: Vec<PluginInstance>,
) -> wasmtime::Result<(Vec<u8>, Vec<EmbeddedImport>)> {
    // A pre-fused core's own `embedded-slot:*` imports come through fusion
    // untouched, so their entries are read off the core before fusion takes
    // its bytes. Empty for a non-fused policy.
    let mut core_imports = compose::reconstruct_strict_manifest(&policy_wasm)?;
    let (bytes, mut embedded_imports) = if plugins.is_empty() {
        (policy_wasm, Vec::new())
    } else {
        compose::fuse(policy_wasm, plugins)?
    };
    embedded_imports.append(&mut core_imports);
    // Dedup by instance name: a runtime plugin and a baked one can
    // share a catalog (same slug) — register the host instance once.
    let mut seen = std::collections::HashSet::new();
    embedded_imports.retain(|e| seen.insert(e.instance_name.clone()));
    Ok((bytes, embedded_imports))
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
