//! The `compile-worker` deployable: holds this crate's Cranelift-backed
//! [`Compiler`] and serves `rpc::CompilerService` over a byte stream. The
//! orchestrator (api) spawns it and talks to it via a `RemoteCompiler`, so
//! api links NO Cranelift — isolating the compiler here is the whole point
//! of the compile⊥execute split.
//!
//! Transport TODAY: the parent spawns us with piped stdio and frames remoc
//! over (our stdin = read, our stdout = write). ALL logging goes to STDERR
//! so it never corrupts the remoc stream on stdout. Plan-A replaces this
//! with the host vsock-relay rendezvous + RA-TLS.

use std::sync::Arc;

use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;

use engine_compiler::Compiler;
use engine_types::composition::PluginInstance;
use rpc::{
    CatalogEntry, CompileError, CompiledBundle, CompilerService, CompilerServiceClient,
    CompilerServiceServerShared,
};

/// The `rpc::CompilerService` impl: compile `(policy, plugins)` to native
/// [`BundleParts`](engine_compiler::BundleParts), then wrap into the wire
/// [`CompiledBundle`]. All the compile orchestration lives in the lib
/// (`Compiler::compile_to_parts`); this is just the wire wrapper.
struct Service {
    compiler: Compiler,
}

impl CompilerService for Service {
    async fn compile(
        &self,
        policy: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Result<CompiledBundle, CompileError> {
        let parts = self
            .compiler
            .compile_to_parts(&policy, &plugins)
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

/// The base channel carries the `CompilerServiceClient` from us (server) to
/// the orchestrator (client).
type Cli = CompilerServiceClient<Ciborium>;

#[tokio::main]
async fn main() {
    let compiler = Compiler::new().expect("compile-worker: create compiler engine");
    let svc = Arc::new(Service { compiler });

    let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(
        rpc::connection_cfg(),
        tokio::io::stdin(),
        tokio::io::stdout(),
    )
    .await
    .expect("compile-worker: remoc connect over stdio");
    tokio::spawn(conn);

    let (server, client) = CompilerServiceServerShared::<_, Ciborium>::new(svc, 4);
    tx.send(client)
        .await
        .expect("compile-worker: send service client to orchestrator");

    if let Err(e) = server.serve(true).await {
        eprintln!("compile-worker: serve ended: {e}");
    }
}
