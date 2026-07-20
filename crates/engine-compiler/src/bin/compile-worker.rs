//! The `compile-worker` deployable: holds this crate's Cranelift-backed
//! [`Compiler`] and serves `rpc::CompilerService`. It LISTENS on an address;
//! the orchestrator (api) connects to it. The worker is started by
//! INFRASTRUCTURE (docker-compose / k8s), not spawned by api — exactly like
//! the hatch. Isolating the compiler in this separate process/CVM is the
//! whole point of the compile⊥execute split: api links no Cranelift.
//!
//! Transport TODAY: a plain TCP listener (dev); each accepted connection is
//! framed with remoc and the worker sends its service client on the base
//! channel. Plan-A swaps the TCP listener for the host vsock-relay rendezvous
//! + RA-TLS (both peers dial the relay, the host splices).

use std::sync::Arc;

use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::net::{TcpListener, TcpStream};

use engine_compiler::Compiler;
use engine_types::composition::PluginInstance;
use rpc::{
    CatalogEntry, CompileError, CompiledBundle, CompilerService, CompilerServiceClient,
    CompilerServiceServerShared,
};

/// The `rpc::CompilerService` impl: compile `(policy, plugins)` to native
/// [`BundleParts`](engine_compiler::BundleParts), then wrap into the wire
/// [`CompiledBundle`]. All the compile orchestration lives in the lib
/// (`Compiler::compile_to_parts`); this is just the wire wrapper. Shared
/// (`Arc`) across connections — the wasmtime engine compiles concurrently.
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
    // Listen address: first arg or ENCLAVID_COMPILE_WORKER_LISTEN. Fail loud if
    // absent (per the minimal-defaults rule).
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ENCLAVID_COMPILE_WORKER_LISTEN").ok())
        .expect(
            "compile-worker: listen address required (arg1 or \
             ENCLAVID_COMPILE_WORKER_LISTEN, e.g. 127.0.0.1:7001)",
        );

    let svc = Arc::new(Service {
        compiler: Compiler::new().expect("compile-worker: create compiler engine"),
    });

    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("compile-worker: bind {addr}: {e}"));
    eprintln!("compile-worker: listening on {addr}");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let svc = svc.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(stream, svc).await {
                        eprintln!("compile-worker: connection from {peer} ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("compile-worker: accept failed: {e}"),
        }
    }
}

/// Frame one accepted connection with remoc and serve `CompilerService` on it.
async fn serve_conn(stream: TcpStream, svc: Arc<Service>) -> Result<(), String> {
    let (read, write) = stream.into_split();
    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(rpc::connection_cfg(), read, write)
            .await
            .map_err(|e| format!("remoc connect: {e}"))?;
    tokio::spawn(conn);

    let (server, client) = CompilerServiceServerShared::<_, Ciborium>::new(svc, 4);
    tx.send(client)
        .await
        .map_err(|e| format!("send service client: {e}"))?;
    server.serve(true).await.map_err(|e| format!("serve: {e}"))?;
    Ok(())
}
