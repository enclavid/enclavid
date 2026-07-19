//! `enclavid-engine` — a thin FACADE over the split engine fleet.
//!
//! The engine is split into two crates that share only the plain-data
//! `engine-types` leaf and never a live wasmtime object:
//!
//!   * [`engine_compiler`] — the COMPILE half: fuse a policy + plugins and
//!     run Cranelift codegen to a serializable `cwasm`.
//!   * [`engine_executor`] — the EXECUTE half: deserialize a `cwasm`,
//!     instantiate it, and drive one pure-reducer round. Carries NO
//!     Cranelift (the execution-worker CVM has zero compiler surface).
//!
//! This facade re-exports both at the original `enclavid_engine::*` paths
//! so existing callers (api, tests) are unchanged, and offers [`Runner`] —
//! an in-process convenience that runs BOTH halves on ONE shared wasmtime
//! engine (local / dev / single-CVM). In Plan-A the api orchestrator drops
//! this facade: it drives a RemoteCompiler / RemoteExecutor over rpc, and
//! each worker builds only its own half.

// ---- COMPILE half (engine-compiler) ----
pub use engine_compiler::{
    Compiler, Composition, EmbeddedCatalog, catalog_hash, load_embedded, load_embedded_nested,
    slug, top_level_imports,
};

// ---- EXECUTE half (engine-executor) ----
pub use engine_executor::limits;
pub use engine_executor::{
    Action, CapturedMedia, Component, ComponentDecls, ConsentDisclosure, Decision, DisclosureFields,
    DisclosureFieldsStore, EmbeddedIface, EmbeddedImport, EmbeddedRegistry, EmbeddedRegistryBuilder,
    Event, Executor, Icon, IconStore, Localized, LocalizedStore, MediaResult, MediaStore,
    PluginInstance, Prompt, Prop, RefKind, RefStore, RunError, RunInputs, RunResult, RunStatus,
    SessionChange, SessionListener, SessionMetadata, SessionState, Translation, sanitize_text_value,
};

/// In-process convenience over both fleet halves: holds a [`Compiler`] and
/// an [`Executor`] built on ONE shared wasmtime engine, so a component the
/// compiler produces is directly runnable by the executor (a component is
/// only instantiable on the engine it was compiled on — `Engine::clone`
/// shares the underlying engine). This is the single-process path; the
/// cross-CVM split replaces it with rpc clients whose engines are distinct
/// and bridged only by serialized `cwasm`.
pub struct Runner {
    compiler: Compiler,
    executor: Executor,
}

impl Runner {
    /// Build both halves on one shared engine (the compiler's).
    pub fn new() -> RunResult<Self> {
        let compiler = Compiler::new()?;
        // Same underlying engine as the compiler, so compose output runs
        // here without a serialize/deserialize round-trip.
        let executor = Executor::from_engine(compiler.engine().clone());
        Ok(Self { compiler, executor })
    }

    // ---- compile side → Compiler ----

    /// Compile a policy component from its binary (wasm or wat).
    pub fn compile(&self, bytes: &[u8]) -> RunResult<Component> {
        self.compiler.compile(bytes)
    }

    /// Serialize a compiled component to `cwasm` for the L2 cache /
    /// compile-boundary reply.
    pub fn serialize_component(&self, component: &Component) -> RunResult<Vec<u8>> {
        self.compiler.serialize_component(component)
    }

    /// Fuse a policy + plugins into a self-contained component's bytes.
    pub fn fuse(&self, policy_wasm: &[u8], plugins: &[PluginInstance]) -> RunResult<Vec<u8>> {
        self.compiler.fuse(policy_wasm, plugins)
    }

    /// Fuse + compile a policy with its pinned plugins into one
    /// [`Composition`] — the once-per-`(policy, plugin-set)` build step.
    pub fn compose(
        &self,
        policy_wasm: &[u8],
        plugins: &[PluginInstance],
    ) -> RunResult<Composition> {
        self.compiler.compose(policy_wasm, plugins)
    }

    // ---- execute side → Executor (shares the compiler's engine) ----

    /// Reconstruct a component from `cwasm` bytes. Runs on the shared
    /// engine, so a component `serialize`d by this runner deserializes here.
    pub fn deserialize_component(&self, cwasm: &[u8]) -> RunResult<Component> {
        self.executor.deserialize_component(cwasm)
    }

    /// Drive one reducer round on the compiled `component`.
    pub async fn run(
        &self,
        component: &Component,
        embedded_imports: &[EmbeddedImport],
        session: SessionState,
        event: Event,
        props: Vec<(String, Prop)>,
        inputs: RunInputs,
    ) -> RunResult<(RunStatus, SessionState)> {
        self.executor
            .run(component, embedded_imports, session, event, props, inputs)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full compile→serialize→deserialize round-trip across the
    /// Compiler/Executor split: `compile` codegens on the compiler engine,
    /// `deserialize` reconstructs on the executor engine — which is a clone
    /// of the SAME underlying engine, so the artifact is compatible. Proves
    /// the shared-engine facade holds the two halves together correctly.
    #[test]
    fn serialize_deserialize_component_round_trips() {
        let runner = Runner::new().unwrap();
        // Minimal valid empty component.
        let bytes = wasm_encoder::Component::new().finish();
        let component = runner.compile(&bytes).unwrap();
        let cwasm = runner.serialize_component(&component).unwrap();
        assert!(!cwasm.is_empty(), "serialize produces cwasm bytes");
        let restored = runner.deserialize_component(&cwasm).unwrap();
        // Re-serialize proves the restored component is a live artifact.
        runner.serialize_component(&restored).unwrap();
    }
}
