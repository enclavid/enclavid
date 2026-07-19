//! The COMPILE boundary: fuse + compile a policy + its pinned plugins into a
//! [`CompiledBundle`], behind a [`Compiler`] trait so the compile step can move
//! OUT of process (a compile-worker CVM) later without touching the caller.
//!
//! [`LocalCompiler`] runs the compile in-process on the shared
//! [`Compiler`](engine_compiler::Compiler) today.
//! A future `RemoteCompiler` implements the same trait over remoc's
//! [`CompilerService`](runtime_protocol::CompilerService) — the orchestrator
//! holds an `Arc<dyn Compiler>` and `deserialize`s the returned cwasm bytes via
//! [`bundle_to_entry`], a boundary already PROCESS-HONEST (bytes in, bytes out,
//! no live `Component` crosses it).
//!
//! The [`CompiledBundle`] wire type lives in `runtime-protocol` (it is both the
//! compile RPC return value and the L2 cache bundle, see [`crate::cwasm_cache`])
//! so a cold compile and an L2 hit reconstruct a [`PolicyEntry`] through the one
//! [`bundle_to_entry`] path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use engine_compiler::{Compiler as EngineCompiler, load_embedded};
use engine_executor::{EmbeddedRegistry, Executor as EngineExecutor, PluginInstance};
use runtime_protocol::{CatalogEntry, CompileError, CompiledBundle};

use crate::runtime::PolicyEntry;

/// Reconstruct the in-RAM [`PolicyEntry`] from a serialized [`CompiledBundle`]:
/// `deserialize` the cwasm into a live `Component` on `runner`'s engine and
/// rebuild the embedded registry from the stored catalogs via the same builder
/// the cold path uses (→ byte-identical registry). `None` on a wasmtime
/// toolchain skew / tampered cwasm — an L2 hit treats that as a miss; the cold
/// path (which deserializes bytes it just serialized on the same engine) never
/// hits it in practice.
pub fn bundle_to_entry(bundle: &CompiledBundle, executor: &EngineExecutor) -> Option<Arc<PolicyEntry>> {
    let component = executor.deserialize_component(&bundle.cwasm).ok()?;
    let mut builder = EmbeddedRegistry::builder();
    for c in &bundle.catalogs {
        builder.add_component(c.hash, c.decls.clone());
    }
    Some(Arc::new(PolicyEntry {
        component: Arc::new(component),
        embedded_imports: Arc::new(bundle.embedded_imports.clone()),
        embedded: Arc::new(builder.build()),
    }))
}

/// The COMPILE boundary. Given already-pulled artifact bytes (the orchestrator
/// owns the OCI pull + registry auth), fuse + compile + parse-sections into a
/// [`CompiledBundle`]. Object-safe boxed-future (mirrors
/// [`MediaStore`](engine_executor::MediaStore)) so the impl can be swapped for
/// an out-of-process `RemoteCompiler` (remoc client) behind an `Arc<dyn Compiler>`.
pub trait Compiler: Send + Sync {
    fn compile<'a>(
        &'a self,
        policy_wasm: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Pin<Box<dyn Future<Output = Result<CompiledBundle, CompileError>> + Send + 'a>>;
}

/// In-process compiler: runs fusion + Cranelift on the shared
/// [`Compiler`](engine_compiler::Compiler). The compile is synchronous CPU
/// work (as it is today); a later `RemoteCompiler` moves it to a
/// compile-worker CVM over remoc.
pub struct LocalCompiler {
    compiler: Arc<EngineCompiler>,
}

impl LocalCompiler {
    pub fn new(compiler: Arc<EngineCompiler>) -> Self {
        Self { compiler }
    }
}

impl Compiler for LocalCompiler {
    fn compile<'a>(
        &'a self,
        policy_wasm: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Pin<Box<dyn Future<Output = Result<CompiledBundle, CompileError>> + Send + 'a>> {
        let compiler = self.compiler.clone();
        Box::pin(async move {
            // Parse each component's embedded sections (dropped by compile) in
            // composition order: policy first, then plugins in pinned order —
            // fixes the merged-DF first-match order (mirrors `Compiler::compose`).
            let policy_catalog =
                load_embedded(&policy_wasm).map_err(|e| CompileError(e.to_string()))?;
            let mut catalogs = Vec::with_capacity(1 + plugins.len());
            catalogs.push(CatalogEntry {
                hash: policy_catalog.hash,
                decls: policy_catalog.decls,
            });
            for p in &plugins {
                let c = load_embedded(&p.wasm).map_err(|e| CompileError(e.to_string()))?;
                catalogs.push(CatalogEntry {
                    hash: c.hash,
                    decls: c.decls,
                });
            }
            // Fuse + compile (blocking Cranelift), then serialize to cwasm — the
            // process-honest boundary output (bytes, not a live `Component`).
            let composition = compiler
                .compose(&policy_wasm, &plugins)
                .map_err(|e| CompileError(e.to_string()))?;
            let cwasm = compiler
                .serialize_component(&composition.component)
                .map_err(|e| CompileError(e.to_string()))?;
            Ok(CompiledBundle {
                cwasm,
                embedded_imports: composition.embedded_imports,
                catalogs,
            })
        })
    }
}
