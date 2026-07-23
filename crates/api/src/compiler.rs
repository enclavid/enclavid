//! The COMPILE boundary: fuse + compile a policy + its pinned plugins into a
//! [`CompiledBundle`]. api NEVER compiles in-process — it always drives a
//! compile-worker over rpc, so the api binary links NO Cranelift.
//!
//! [`Compiler`] wraps the `engine_rpc::CompilerService` client. The worker is a
//! separate process/CVM started by INFRASTRUCTURE (docker-compose / k8s), not
//! by api — exactly like the hatch. api [`connect`](connect_compile_worker)s
//! to it at a configured address (TCP in dev, a vsock-relay rendezvous under
//! RA-TLS in Plan-A). The orchestrator holds the returned cwasm as BYTES via
//! [`bundle_to_entry`] and never deserializes it — the live `Component` is
//! materialized only on the execution-worker (the compile→execute seam is
//! bytes-in, bytes-out both ends).
//!
//! The [`CompiledBundle`] wire type lives in the `engine-rpc` crate (it is the compile
//! RPC return value, the L2 cache bundle — see [`crate::cwasm_cache`] — AND the
//! execution-worker `load_component` payload) so a cold compile and an L2 hit
//! resolve the same bundle the worker deserializes.

use engine_types::composition::PluginInstance;
use remoc::codec::Ciborium;
// `CompilerService` (the remoc trait) is in scope so the generated
// `CompilerServiceClient`'s `.compile()` method resolves.
use engine_rpc::{CompileError, CompiledBundle, CompilerService, CompilerServiceClient};

/// The COMPILE boundary: a client for a compile-worker's `engine_rpc::CompilerService`.
/// Given already-pulled artifact bytes (the orchestrator owns the OCI pull +
/// registry auth), the worker fuses + Cranelift-compiles + parses sections into
/// a [`CompiledBundle`]. The client is a cheap remoc handle (`Send + Sync`);
/// concurrent `/connect` compiles multiplex over the one connection.
pub struct Compiler {
    client: CompilerServiceClient<Ciborium>,
}

impl Compiler {
    pub fn new(client: CompilerServiceClient<Ciborium>) -> Self {
        Self { client }
    }

    /// Compile `(policy, plugins)` on the worker. A transport failure surfaces
    /// as `CompileError` via its `From<remoc::rtc::CallError>`.
    pub async fn compile(
        &self,
        policy_wasm: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Result<CompiledBundle, CompileError> {
        self.client.compile(policy_wasm, plugins).await
    }
}

/// Connect to a compile-worker already listening at `addr` and hand back a
/// [`Compiler`]. The worker is started by infrastructure, not api. Transport
/// TODAY: a direct TCP dial (dev); Plan-A swaps this for the host vsock-relay
/// rendezvous + RA-TLS (both peers dial the relay, the host splices). The
/// worker sends us its service client on the base channel once connected.
pub async fn connect_compile_worker(addr: &str) -> Result<Compiler, String> {
    type Cli = CompilerServiceClient<Ciborium>;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect compile-worker at `{addr}`: {e}"))?;
    // Mutual RA-TLS over the dial (same as the execution-worker): attest the peer's
    // pinned measurement + present our own attested cert.
    let config = enclavid_ra_tls::fleet_client_config()
        .map_err(|e| format!("compile-worker RA-TLS client config: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tls = connector
        .connect(enclavid_ra_tls::server_name(), tcp)
        .await
        .map_err(|e| format!("compile-worker RA-TLS handshake: {e}"))?;
    let (read, write) = tokio::io::split(tls);

    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(engine_rpc::connection_cfg(), read, write)
            .await
            .map_err(|e| format!("compile-worker remoc connect: {e}"))?;
    tokio::spawn(conn);

    let client = rx
        .recv()
        .await
        .map_err(|e| format!("compile-worker recv client: {e}"))?
        .ok_or("compile-worker closed before sending its service client")?;

    Ok(Compiler::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use remoc::rtc::ServerShared;
    use std::sync::Arc;

    // A minimal in-process CompilerService server, so the Compiler client's rpc
    // plumbing is exercised without a real worker (the transport factory
    // `connect_compile_worker` is the thin, hand-reviewed piece).
    struct MockService;

    impl engine_rpc::CompilerService for MockService {
        async fn compile(
            &self,
            policy: Vec<u8>,
            plugins: Vec<PluginInstance>,
        ) -> Result<CompiledBundle, CompileError> {
            if policy == b"boom" {
                return Err(CompileError("intentional".into()));
            }
            Ok(CompiledBundle {
                cwasm: vec![policy.len() as u8, plugins.len() as u8],
                embedded_imports: vec![],
                catalogs: vec![],
            })
        }
    }

    /// The Compiler client drives a CompilerService over an in-memory remoc
    /// duplex: args cross, the typed bundle returns, and the error path
    /// propagates.
    #[tokio::test]
    async fn compiler_round_trips() {
        type Cli = CompilerServiceClient<Ciborium>;
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);

        // Worker end: serve the mock service.
        let server = tokio::spawn(async move {
            let (conn, mut tx, _rx) =
                remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(remoc::Cfg::default(), a_r, a_w)
                    .await
                    .unwrap();
            tokio::spawn(conn);
            let (srv, client) =
                engine_rpc::CompilerServiceServerShared::<_, Ciborium>::new(Arc::new(MockService), 4);
            tx.send(client).await.unwrap();
            srv.serve(true).await.unwrap();
        });

        // Orchestrator end: receive the client, wrap in Compiler.
        let (conn, _tx, mut rx) =
            remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(remoc::Cfg::default(), b_r, b_w)
                .await
                .unwrap();
        tokio::spawn(conn);
        let client = rx.recv().await.unwrap().unwrap();
        let compiler = Compiler::new(client);

        let plugins = vec![PluginInstance { package: "p".into(), wasm: vec![0] }];
        let bundle = compiler.compile(b"hello".to_vec(), plugins).await.unwrap();
        assert_eq!(bundle.cwasm, vec![5u8, 1u8]);

        let err = match compiler.compile(b"boom".to_vec(), vec![]).await {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(format!("{err}").contains("intentional"), "got {err}");

        server.abort();
    }
}
