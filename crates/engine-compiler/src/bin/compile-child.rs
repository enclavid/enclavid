//! The `compile-child` deployable: the disposable PER-COMPILE process the
//! `compile-worker` supervisor spawns to run Cranelift over UNTRUSTED wasm.
//!
//! Cranelift compiling attacker-crafted wasm is a wide, complex surface (parser /
//! validator / codegen). Running each compile in a fresh throwaway process
//! confines a compiler-bug exploit to that ONE compile PROCESS — **keyless**,
//! holding no user data (its memory is the attacker's own artifact + Cranelift
//! internals), so the CONFIDENTIALITY blast radius is ~nil; the pool's wall-clock
//! deadline stops a malicious wasm from wedging the worker.
//!
//! What process-disposal does NOT contain is the OUTPUT: the `cwasm` this child
//! emits is trusted downstream and `deserialize`d as native code by the executor.
//! A compiler-toolchain memory-safety escape could therefore emit a malicious cwasm
//! for its OWN composition (the "unvalidated cwasm deserialize" residual). Its reach
//! is bounded: the L2 seal AAD + OCI digest bind each cwasm to the pinned
//! composition (a foreign one won't open), and the deserialize + execution happen in
//! the disposable per-round `session-child` — so a malicious cwasm gets the SAME
//! blast radius as a wasm sandbox escape (one round of one session pinning that same
//! adversary-supplied composition), never a third party's.
//!
//! Lifecycle: adopt the socketpair on fd 0, serve ONE
//! `engine_rpc::CompilerService::compile`, exit when the supervisor drops its
//! client. Multi-threaded runtime + `spawn_blocking` because `compile_to_parts`
//! is a SYNCHRONOUS, CPU-bound, multi-second call — offloading it keeps the remoc
//! reactor answering keepalives so the supervisor's connection survives the
//! compile (unlike the executor's `session-child`, whose run path is already
//! async).

use std::sync::Arc;

use remoc::codec::Ciborium;

use engine_compiler::Compiler;
use engine_rpc::{
    CatalogEntry, CompileError, CompiledBundle, CompilerService, CompilerServiceServerShared,
};
use engine_types::composition::PluginInstance;

/// Holds this process's Cranelift [`Compiler`]; serves ONE compile then exits.
struct Child {
    compiler: Arc<Compiler>,
}

impl CompilerService for Child {
    async fn compile(
        &self,
        policy: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Result<CompiledBundle, CompileError> {
        // Offload the synchronous, CPU-bound Cranelift compile to a blocking
        // thread so the remoc reactor stays live (answers keepalives) — else a
        // multi-second compile could look like a dead transport to the supervisor.
        let compiler = self.compiler.clone();
        let parts =
            tokio::task::spawn_blocking(move || compiler.compile_to_parts(&policy, &plugins))
                .await
                .map_err(|e| CompileError(format!("compile task join failed: {e}")))?
                .map_err(|e| CompileError(e.to_string()))?;
        Ok(CompiledBundle {
            cwasm: parts.cwasm,
            embedded_imports: parts.embedded_imports,
            catalogs: parts
                .catalogs
                .into_iter()
                .map(|(hash, decls)| CatalogEntry { hash, decls })
                .collect(),
        })
    }
}

#[tokio::main]
async fn main() {
    let child = Arc::new(Child {
        compiler: Arc::new(Compiler::new().expect("compile-child: create compiler engine")),
    });

    // The supervisor placed one end of a socketpair on our fd 0; engine-supervisor
    // adopts it, serves `CompilerService`, and returns when the supervisor drops
    // its client (compile done) → we exit. Request buffer 1 — one compile.
    match engine_supervisor::serve_child::<Child, CompilerServiceServerShared<Child, Ciborium>>(
        child, 1,
    )
    .await
    {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("compile-child: {e}");
            std::process::exit(1);
        }
    }
}
