//! Compile boundary — wire types + the `CompilerService` remote trait.
//!
//! Gated behind the `compile` feature: a compile-worker (or the
//! orchestrator's compile client) built with only this feature links the
//! compiler contract + `engine-types`, and NOT the executor contract or
//! `broker-client` — least-knowledge for its measured image.

use serde::{Deserialize, Serialize};

use engine_types::composition::{EmbeddedImport, PluginInstance};
use engine_types::embedded::ComponentDecls;

/// A freshly compiled composition crossing the compile boundary: the
/// wasmtime-serialized fused component (`cwasm`) plus the host-side metadata
/// compile drops (the per-catalog i18n/icons import manifest and the parsed
/// per-component catalogs). This is BOTH the compile RPC return value AND the L2
/// cache bundle (`enclavid-api::cwasm_cache`) — a compile output and a cache
/// entry are the same thing, so a cold compile and an L2 hit reconstruct a
/// `PolicyEntry` through the one `bundle_to_entry` path.
///
/// `deny_unknown_fields` + no `#[serde(default)]` is deliberate: the L2 bundle
/// is written and read by ONE binary version, so any schema drift must
/// fail-closed to a cache miss, never silently default. (The compile RPC itself
/// is between same-version fleet nodes; the same fail-closed shape is correct
/// there too — a version-skewed worker/orchestrator should error, not
/// misinterpret.)
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledBundle {
    /// wasmtime-serialized fused component — the amortized Cranelift codegen.
    pub cwasm: Vec<u8>,
    /// Per-catalog i18n / icons import manifest (lost in compile; needed to
    /// register the host `Linker` instances at run time).
    pub embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs, composition order (policy first) — the
    /// exact registry-builder inputs.
    pub catalogs: Vec<CatalogEntry>,
}

/// One component's `(content_hash, parsed catalog)` — a registry-builder input.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub hash: [u8; 32],
    pub decls: ComponentDecls,
}

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

/// The compile boundary as a remote trait. The worker (compile-worker CVM)
/// serves it over an `Arc<dyn CompilerService>`-equivalent target; the
/// orchestrator holds the generated `CompilerServiceClient` and calls
/// [`compile`](CompilerService::compile) as if local. Given already-pulled
/// artifact bytes (the orchestrator owns the OCI pull + registry auth), the
/// worker fuses + compiles + parses sections into a [`CompiledBundle`].
///
/// `&self` so the client is clonable and the server can run compiles in
/// parallel (`CompilerServiceServerShared`).
#[remoc::rtc::remote]
pub trait CompilerService {
    async fn compile(
        &self,
        policy: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Result<CompiledBundle, CompileError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_types::composition::EmbeddedIface;
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;
    use std::sync::Arc;
    use tokio::io::split;

    fn sample_bundle() -> CompiledBundle {
        let mut decls = ComponentDecls::default();
        decls.disclosure_fields.insert("dob".to_string());
        decls.icons.insert("passport".to_string());
        CompiledBundle {
            cwasm: vec![1, 2, 3, 4],
            embedded_imports: vec![EmbeddedImport {
                instance_name: "embedded-slot:abcd/i18n".to_string(),
                catalog_hash: [7u8; 32],
                iface: EmbeddedIface::I18n,
                version: "0.1.0".to_string(),
            }],
            catalogs: vec![CatalogEntry {
                hash: [9u8; 32],
                decls,
            }],
        }
    }

    fn encode<T: Serialize>(v: &T) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    #[test]
    fn bundle_round_trips() {
        let bytes = encode(&sample_bundle());
        let back: CompiledBundle = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(back.cwasm, vec![1, 2, 3, 4]);
        assert_eq!(back.embedded_imports.len(), 1);
        assert_eq!(back.embedded_imports[0].catalog_hash, [7u8; 32]);
        assert_eq!(back.catalogs.len(), 1);
        assert!(back.catalogs[0].decls.disclosure_fields.contains("dob"));
    }

    /// L2 guard: an EXTRA field (bundle written by a newer binary) must fail to
    /// decode → cache miss / version-skew error, not a silent partial read.
    #[test]
    fn deny_unknown_fields_rejects_extra() {
        #[derive(Serialize)]
        struct BundlePlus {
            cwasm: Vec<u8>,
            embedded_imports: Vec<EmbeddedImport>,
            catalogs: Vec<CatalogEntry>,
            future_field: u32,
        }
        let b = sample_bundle();
        let plus = BundlePlus {
            cwasm: b.cwasm,
            embedded_imports: b.embedded_imports,
            catalogs: b.catalogs,
            future_field: 42,
        };
        assert!(ciborium::from_reader::<CompiledBundle, _>(&encode(&plus)[..]).is_err());
    }

    /// A mock worker that echoes the request size into the returned bundle's
    /// cwasm, so the test proves the REQUEST (policy + plugins) and the typed
    /// [`CompiledBundle`] RESPONSE both cross a real remoc connection.
    struct MockCompiler;

    impl CompilerService for MockCompiler {
        async fn compile(
            &self,
            policy: Vec<u8>,
            plugins: Vec<PluginInstance>,
        ) -> Result<CompiledBundle, CompileError> {
            if policy == b"boom" {
                return Err(CompileError("intentional".into()));
            }
            let mut bundle = sample_bundle();
            // Echo (policy_len, plugin_count) so the caller can assert the args
            // arrived.
            bundle.cwasm = vec![policy.len() as u8, plugins.len() as u8];
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
            let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, CompilerCli, CompilerCli, Ciborium>(
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
            PluginInstance { package: "p1".into(), wasm: vec![0] },
            PluginInstance { package: "p2".into(), wasm: vec![0] },
        ];
        let bundle = client.compile(b"hello".to_vec(), plugins).await.unwrap();
        assert_eq!(bundle.cwasm, vec![5u8, 2u8]); // policy_len=5, plugins=2
        assert_eq!(bundle.embedded_imports.len(), 1);
        assert_eq!(bundle.catalogs[0].hash, [9u8; 32]);

        // Error path crosses too (match, not unwrap_err — the bundle isn't Debug).
        let err = match client.compile(b"boom".to_vec(), vec![]).await {
            Err(e) => e,
            Ok(_) => panic!("expected compile error"),
        };
        assert!(format!("{err}").contains("intentional"), "got {err}");

        drop(client);
        server_task.abort();
    }
}
