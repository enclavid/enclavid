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

use wasmtime::component::Component;
use wasmtime::{Config, Engine};

use engine_types::composition::{EmbeddedImport, PluginInstance};

pub use decls::{EmbeddedCatalog, load_embedded, load_embedded_nested, top_level_imports};
pub use hash::{catalog_hash, embedded_import_name, slug};

/// A fused policy component plus the manifest of distinct embedded
/// imports its host `Linker` must register. Returned by
/// [`Compiler::compose`]; the caller serializes `component` to `cwasm`
/// (the process-honest boundary output) and hands the manifest to the
/// executor's run path.
pub struct Composition {
    pub component: Component,
    pub embedded_imports: Vec<EmbeddedImport>,
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
    pub fn fuse(&self, policy_wasm: &[u8], plugins: &[PluginInstance]) -> wasmtime::Result<Vec<u8>> {
        let (bytes, _manifest) = compose::fuse(policy_wasm, plugins)?;
        Ok(bytes)
    }

    /// Fuse a policy with its pinned plugins into ONE component and
    /// compile it. `wac-graph` single-store fusion (see
    /// `compose::fuse`) wires every plugin export into the policy's
    /// imports; the result runs in one wasmtime `Store`, so
    /// cross-component WIT resources are native handles. With no
    /// plugins this is just [`compile`](Self::compile) on the policy
    /// bytes.
    ///
    /// This is a build-time step: the caller compiles once per
    /// `(policy, plugin-set)` and reuses the returned [`Composition`]
    /// across every reducer round.
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
    pub fn compose(
        &self,
        policy_wasm: &[u8],
        plugins: &[PluginInstance],
    ) -> wasmtime::Result<Composition> {
        let (component, mut embedded_imports) = if plugins.is_empty() {
            (
                self.compile(policy_wasm)?,
                compose::reconstruct_strict_manifest(policy_wasm)?,
            )
        } else {
            let (fused, mut manifest) = compose::fuse(policy_wasm, plugins)?;
            // Hybrid pass-through: the core's own `embedded-slot:*`
            // imports came through fusion untouched — add their manifest
            // entries. Empty for a non-fused dynamic policy.
            manifest.extend(compose::reconstruct_strict_manifest(policy_wasm)?);
            (Component::new(&self.engine, &fused)?, manifest)
        };
        // Dedup by instance name: a runtime plugin and a baked one can
        // share a catalog (same slug) — register the host instance once.
        let mut seen = std::collections::HashSet::new();
        embedded_imports.retain(|e| seen.insert(e.instance_name.clone()));
        Ok(Composition {
            component,
            embedded_imports,
        })
    }
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
