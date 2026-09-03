//! The `engine-compiler-child` deployable: the disposable PER-COMPILE process the
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
//! the disposable per-round `engine-executor-child` — so a malicious cwasm gets the SAME
//! blast radius as a wasm sandbox escape (one round of one session pinning that same
//! adversary-supplied composition), never a third party's.
//!
//! Lifecycle: adopt the socketpair on fd 0, serve ONE
//! `engine_rpc::CompilerService::compile`, exit when the supervisor drops its
//! client. Multi-threaded runtime + `spawn_blocking` because `compile_to_parts`
//! is a SYNCHRONOUS, CPU-bound, multi-second call — offloading it keeps the remoc
//! reactor answering keepalives so the supervisor's connection survives the
//! compile (unlike the executor's `engine-executor-child`, whose run path is already
//! async).

// The contained posture, stated where the compiler can check it. The manifest
// not asking for `safe-logger/device` is the intent; this stops a dependency
// edge from undoing it silently.
//
// Behind a feature because the claim is about ONE cargo invocation — see the
// `contained` feature in this package's manifest for why a whole-workspace build
// is not that, and which two builds pass it.
#[cfg(feature = "contained")]
safe_logger::assert_contained!();

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
    // The contained posture — see `engine-executor-child` for the reasoning. This child
    // holds the consumer's policy bytes rather than an applicant's, but the
    // containment is the same and so is the answer: nothing outward.
    safe_logger::install_contained();

    let child = Arc::new(Child {
        compiler: Arc::new(Compiler::new().expect("engine-compiler-child: create compiler engine")),
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
            // The supervisor nulls this child's stdout and stderr, and the
            // log device is opened O_CLOEXEC so a child never inherits it —
            // this reaches a developer running the child by hand and nobody
            // else. `debug!` on top of that keeps it out of the measured build
            // entirely, so the belt does not depend on the braces.
            safe_logger::debug!("engine-compiler-child: {e}");
            std::process::exit(1);
        }
    }
}
