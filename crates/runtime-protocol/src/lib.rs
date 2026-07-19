//! Intra-fleet RPC substrate: remote trait calls (remoc `rtc`) over any
//! `AsyncRead + AsyncWrite` byte stream — a host vsock relay today, an RA-TLS
//! tunnel over that relay later. The transport is abstract (remoc's
//! [`Connect::io`](remoc::Connect::io) frames + multiplexes over the raw
//! stream), so the same service definitions work at every stage of the CVM
//! split. CBOR codec ([`remoc::codec::Ciborium`]) keeps the named-field schema
//! evolution `broker-protocol` already relies on across independently-deployed
//! nodes.
//!
//! Chosen over a thin hand-rolled protocol and over tarpc — see the
//! `project_fleet_rpc_substrate` memory: remoc's marginal footprint over the
//! existing tree is one runtime crate, it is no-OpenTelemetry / ciborium /
//! tokio-native, and its native mid-call callbacks (a callback client passed as
//! a method argument, multiplexed by chmux) are exactly what the execute
//! boundary needs without a hand-rolled request-id duplex.
//!
//! Adversarial-peer hardening lives in the connection [`remoc::Cfg`] (pin
//! `chmux::Cfg` limits: `max_ports`, `max_data_size` — RAISE from the 512 KiB
//! default for the compile boundary, cwasm bundles are ~10–15 MiB —
//! `max_received_ports`, `connection_timeout`) plus per-service handler
//! validation (hash-bound media loads, bounded session-change).

use serde::{Deserialize, Serialize};

use enclavid_engine::{ComponentDecls, EmbeddedImport, Event, SessionState};

// ---------------------------------------------------------------------------
// Compile boundary — wire types + service
// ---------------------------------------------------------------------------

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

/// One pinned plugin on the compile wire: package id + raw component bytes. The
/// wire form of the engine's `PluginInstance` (kept here so `runtime-protocol`
/// does not force `PluginInstance` to derive serde); the worker converts back.
#[derive(Serialize, Deserialize)]
pub struct WirePlugin {
    pub package: String,
    pub wasm: Vec<u8>,
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
        plugins: Vec<WirePlugin>,
    ) -> Result<CompiledBundle, CompileError>;
}

// ---------------------------------------------------------------------------
// Execute boundary — run + mid-call callbacks (the bidirectional case)
// ---------------------------------------------------------------------------

/// A run failure or an absorbed RPC transport error.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecError(pub String);

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "run failed: {}", self.0)
    }
}
impl std::error::Error for ExecError {}
impl From<remoc::rtc::CallError> for ExecError {
    fn from(err: remoc::rtc::CallError) -> Self {
        ExecError(format!("run rpc failed: {err}"))
    }
}

/// A callback failure or an absorbed RPC transport error.
#[derive(Debug, Serialize, Deserialize)]
pub struct CallbackError(pub String);

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "callback failed: {}", self.0)
    }
}
impl std::error::Error for CallbackError {}
impl From<remoc::rtc::CallError> for CallbackError {
    fn from(err: remoc::rtc::CallError) -> Self {
        CallbackError(format!("callback rpc failed: {err}"))
    }
}

/// A callback failure surfacing inside a run bubbles up as a run failure — the
/// worker's `?` on a mid-run callback converts here.
impl From<CallbackError> for ExecError {
    fn from(err: CallbackError) -> Self {
        ExecError(format!("callback during run: {}", err.0))
    }
}

/// One reducer round's inputs on the wire.
///
/// `cwasm` / `props` are added with the executor-worker wiring (the worker
/// caches the deserialized component per composition, so cwasm rides only the
/// first run for a composition; `props` needs a serde mirror for the bindgen
/// `Prop`). `session_state` / `event` are the engine's own serde domain types.
#[derive(Serialize, Deserialize)]
pub struct RunRequest {
    pub session_state: SessionState,
    pub event: Event,
}

/// One reducer round's result on the wire.
///
/// The typed `RunStatus` projection (a serde mirror of the borrowed engine enum)
/// is added with the wiring; `done` is the terminal marker used for the
/// bidirectional-pattern proof until then.
#[derive(Serialize, Deserialize)]
pub struct RunReply {
    pub new_state: SessionState,
    pub done: bool,
}

/// The orchestrator-served CALLBACK boundary the keyless execution-worker calls
/// BACK during a run: the worker holds no seal key, so blob rehydration
/// (`media_load`) and state persistence (`session_change`) happen
/// orchestrator-side. A [`CallbackServiceClient`] is passed to the worker as an
/// argument to [`ExecutorService::run`] — remoc multiplexes the callback calls
/// over the SAME connection as the in-flight run, so the key never crosses to
/// the worker and there is no hand-rolled request-id duplex.
#[remoc::rtc::remote]
pub trait CallbackService {
    /// Rehydrate a stored blob by content hash (orchestrator unseals). `None` =
    /// miss (unknown / never-stored ref).
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError>;

    /// Seal + persist the post-round session state. (The consented-disclosure +
    /// captured-media co-commit — the owned form of the engine's borrowed
    /// `SessionChange` — is added with the wiring as additive `#[serde(default)]`
    /// args, keeping this backward-compatible.)
    async fn session_change(&self, new_state: SessionState) -> Result<(), CallbackError>;
}

/// The execute boundary as a remote trait. The execution-worker serves it; the
/// orchestrator calls [`run`](ExecutorService::run), passing a
/// [`CallbackServiceClient`] pointing at its own callback server so the keyless
/// worker can rehydrate media / persist state mid-round without ever holding the
/// seal key.
#[remoc::rtc::remote]
pub trait ExecutorService {
    async fn run(
        &self,
        req: RunRequest,
        callbacks: CallbackServiceClient<remoc::codec::Ciborium>,
    ) -> Result<RunReply, ExecError>;
}

#[cfg(test)]
mod execute_tests {
    use super::*;
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;
    use std::sync::{Arc, Mutex};
    use tokio::io::split;

    /// Orchestrator-side callback target: records the calls it receives and
    /// returns canned media, so the test can assert the worker called BACK with
    /// the right arguments mid-run.
    struct MockCallbacks {
        media_calls: Mutex<Vec<[u8; 32]>>,
        state_calls: Mutex<u32>,
    }

    impl CallbackService for MockCallbacks {
        async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
            self.media_calls.lock().unwrap().push(hash);
            Ok(Some(vec![0xAB, 0xCD]))
        }
        async fn session_change(&self, _new_state: SessionState) -> Result<(), CallbackError> {
            *self.state_calls.lock().unwrap() += 1;
            Ok(())
        }
    }

    /// Worker-side executor: during `run`, calls the passed-in callback client
    /// (media_load + session_change) BACK to the orchestrator, then replies.
    struct MockExecutor;

    impl ExecutorService for MockExecutor {
        async fn run(
            &self,
            req: RunRequest,
            callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunReply, ExecError> {
            let bytes = callbacks.media_load([9u8; 32]).await?;
            if bytes != Some(vec![0xAB, 0xCD]) {
                return Err(ExecError("callback returned wrong media".into()));
            }
            callbacks.session_change(req.session_state.clone()).await?;
            Ok(RunReply {
                new_state: req.session_state,
                done: true,
            })
        }
    }

    type ExecCli = ExecutorServiceClient<Ciborium>;

    /// The bidirectional gate: `run()` crosses to the worker WITH a callback
    /// client argument; the keyless worker invokes `media_load` + `session_change`
    /// BACK to the orchestrator mid-run, all multiplexed over the ONE remoc
    /// connection. This is the pattern that removes the hand-rolled duplex.
    #[tokio::test]
    async fn execute_bidirectional_callbacks_over_remoc() {
        let callbacks = Arc::new(MockCallbacks {
            media_calls: Mutex::new(Vec::new()),
            state_calls: Mutex::new(0),
        });

        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = split(a);
        let (b_r, b_w) = split(b);

        // Worker end: serve the executor.
        let server_task = tokio::spawn(async move {
            let (conn, mut tx, _rx) =
                remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(remoc::Cfg::default(), a_r, a_w)
                    .await
                    .unwrap();
            tokio::spawn(conn);
            let (server, client) =
                ExecutorServiceServerShared::<_, Ciborium>::new(Arc::new(MockExecutor), 4);
            tx.send(client).await.unwrap();
            server.serve(true).await.unwrap();
        });

        // Orchestrator end: receive the executor client, stand up its OWN
        // callback server on the same connection, pass the callback client into
        // run().
        let (conn, _tx, mut rx) =
            remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(remoc::Cfg::default(), b_r, b_w)
                .await
                .unwrap();
        tokio::spawn(conn);
        let exec_client = rx.recv().await.unwrap().unwrap();

        let (cb_server, cb_client) =
            CallbackServiceServerShared::<_, Ciborium>::new(callbacks.clone(), 4);
        tokio::spawn(async move {
            let _ = cb_server.serve(true).await;
        });

        let reply = exec_client
            .run(
                RunRequest {
                    session_state: SessionState::default(),
                    event: Event::Start,
                },
                cb_client,
            )
            .await
            .unwrap();

        assert!(reply.done);
        assert_eq!(callbacks.media_calls.lock().unwrap().as_slice(), &[[9u8; 32]]);
        assert_eq!(*callbacks.state_calls.lock().unwrap(), 1);

        drop(exec_client);
        server_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavid_engine::EmbeddedIface;
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
            plugins: Vec<WirePlugin>,
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
            WirePlugin { package: "p1".into(), wasm: vec![0] },
            WirePlugin { package: "p2".into(), wasm: vec![0] },
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
