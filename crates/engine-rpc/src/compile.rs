//! Compile boundary — the `CompilerService` remote trait + its error.
//!
//! Gated behind the `compile` feature: a compile-worker (or the
//! orchestrator's compile client) built with only this feature links the
//! compiler contract + `engine-types`, and NOT the executor contract or
//! `hatch-client` — least-knowledge for its measured image. The compiled
//! artifact it returns ([`CompiledBundle`](crate::CompiledBundle)) is shared
//! with the execute boundary (see `crate::bundle`).

use serde::{Deserialize, Serialize};

use engine_types::composition::PluginInstance;

use crate::CompiledBundle;

/// A compile failure — fusion / codegen / section-parse — or an RPC transport
/// failure absorbed from [`remoc::rtc::CallError`]. Both surface to the
/// orchestrator, which maps them to a 500 (a pure function of pinned config, no
/// applicant input).
#[derive(Debug, Serialize, Deserialize)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "compile failed: {}", self.0)
    }
}
impl std::error::Error for CompileError {}

impl From<remoc::rtc::CallError> for CompileError {
    fn from(err: remoc::rtc::CallError) -> Self {
        CompileError(format!("compile rpc failed: {err}"))
    }
}

/// One compile's inputs on the wire: the consumer's own artifacts, already pulled
/// and digest-verified by the orchestrator against the pinned refs.
///
/// One struct rather than two arguments because that is what a scope can be carried
/// on — `Exposed` wraps a value, and the concerns this crossing raises are raised
/// about the request, not about each field of it. The execute leg's `RunRequest` has
/// the same shape for the same reason.
///
/// `deny_unknown_fields` for the reason `CompiledBundle` carries it: an unknown
/// field means the peer is speaking a contract this image does not have, and
/// failing the decode is the fail-closed answer.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileRequest {
    /// The policy component, as pulled.
    #[serde(with = "serde_bytes")]
    pub policy: Vec<u8>,
    /// The pinned plugin components, in composition order.
    pub plugins: Vec<PluginInstance>,
}

/// The compile boundary as a remote trait. The worker (compile-worker CVM)
/// serves it; the orchestrator reaches it through
/// [`CompilerLeg`](crate::CompilerLeg), never through the generated client, which
/// this crate does not export.
///
/// Given already-pulled artifact bytes (the orchestrator owns the OCI pull +
/// registry auth), the worker fuses + compiles + parses sections into a
/// [`CompiledBundle`](crate::CompiledBundle).
///
/// `&self` so the client is clonable and the server can run compiles in
/// parallel (`CompilerServiceServerShared`).
#[remoc::rtc::remote]
pub trait CompilerService {
    async fn compile(&self, req: CompileRequest) -> Result<CompiledBundle, CompileError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::sample_bundle;
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;
    use std::sync::Arc;
    use tokio::io::split;

    /// A mock worker that echoes the request size into the returned bundle's
    /// cwasm, so the test proves the REQUEST (policy + plugins) and the typed
    /// [`CompiledBundle`] RESPONSE both cross a real remoc connection.
    struct MockCompiler;

    impl CompilerService for MockCompiler {
        async fn compile(&self, req: CompileRequest) -> Result<CompiledBundle, CompileError> {
            if req.policy == b"boom" {
                return Err(CompileError("intentional".into()));
            }
            let mut bundle = sample_bundle();
            // Echo (policy_len, plugin_count) so the caller can assert the args
            // arrived.
            bundle.cwasm = vec![req.policy.len() as u8, req.plugins.len() as u8];
            Ok(bundle)
        }
    }

    type CompilerCli = CompilerServiceClient<Ciborium>;

    /// The compile-boundary gate: a `CompilerServiceClient` calls `compile`
    /// across a remoc `Connect::io` connection (Ciborium codec) over an in-memory
    /// duplex; the typed `CompiledBundle`/`CompileError` cross the wire intact.
    #[tokio::test]
    async fn compiler_service_round_trips_over_remoc() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = split(a);
        let (b_r, b_w) = split(b);

        // Worker end: serve the mock compiler.
        let server_task = tokio::spawn(async move {
            let (conn, mut tx, _rx) =
                remoc::Connect::io::<_, _, CompilerCli, CompilerCli, Ciborium>(
                    remoc::Cfg::default(),
                    a_r,
                    a_w,
                )
                .await
                .unwrap();
            tokio::spawn(conn);
            let (server, client) =
                CompilerServiceServerShared::<_, Ciborium>::new(Arc::new(MockCompiler), 4);
            tx.send(client).await.unwrap();
            server.serve(true).await.unwrap();
        });

        // Orchestrator end: receive the client, call compile.
        let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, CompilerCli, CompilerCli, Ciborium>(
            remoc::Cfg::default(),
            b_r,
            b_w,
        )
        .await
        .unwrap();
        tokio::spawn(conn);
        let client = rx.recv().await.unwrap().unwrap();

        // Success: args arrive, typed bundle returns (incl. embedded_imports +
        // catalogs, proving engine types cross the codec).
        let plugins = vec![
            PluginInstance {
                package: "p1".into(),
                wasm: vec![0],
            },
            PluginInstance {
                package: "p2".into(),
                wasm: vec![0],
            },
        ];
        let bundle = client
            .compile(CompileRequest {
                policy: b"hello".to_vec(),
                plugins,
            })
            .await
            .unwrap();
        assert_eq!(bundle.cwasm, vec![5u8, 2u8]); // policy_len=5, plugins=2
        assert_eq!(bundle.embedded_imports.len(), 1);
        assert_eq!(bundle.catalogs[0].hash, [9u8; 32]);

        // Error path crosses too (match, not unwrap_err — the bundle isn't Debug).
        let err = match client
            .compile(CompileRequest {
                policy: b"boom".to_vec(),
                plugins: vec![],
            })
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("expected compile error"),
        };
        assert!(format!("{err}").contains("intentional"), "got {err}");

        drop(client);
        server_task.abort();
    }
}
