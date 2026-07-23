//! The `compile-worker` deployable: the SUPERVISOR of the compile side.
//!
//! It LISTENS for the orchestrator (api) and serves `engine_rpc::CompilerService`
//! — the same api-facing contract as before — but it runs NO Cranelift itself.
//! Per compile it drives a fresh `compile-child` PROCESS (spawned + bounded +
//! deadline-guarded + reaped by the shared [`engine_supervisor::ChildPool`]) and
//! forwards the `(policy, plugins)` to it. Cranelift over UNTRUSTED wasm — a wide
//! surface — runs ONLY in that disposable per-compile child, so a compiler-bug
//! exploit is confined to one compile (no persistent implant that could poison a
//! later tenant's cwasm). Started by INFRASTRUCTURE (docker-compose / k8s),
//! exactly like the hatch and the execution-worker.
//!
//! **Keyless + cacheless.** The compile-worker holds no keys and no in-memory
//! cache: compile RESULTS are cached in api's L2, so this is a pure forwarder.
//! Compared to the execution-worker it is the SIMPLER consumer of the shared
//! supervisor — no bundle L1, no callback relay — which is exactly why it also
//! validates that the engine-supervisor boundary is clean (process plumbing only).
//!
//! The pool's per-compile wall-clock DEADLINE doubles as the compile-worker's
//! availability guard: a malicious wasm can't hang Cranelift forever and wedge
//! the worker (a real gap the direct-compile design had no bound for). A memory
//! cap (RLIMIT_AS on the child) is a natural follow-up.
//!
//! Transport TODAY: a plain TCP listener (dev) to api; Plan-A swaps it for the
//! host vsock-relay rendezvous + RA-TLS. The supervisor↔child hop is a private
//! per-child socketpair (never leaves this host).

use std::sync::Arc;
use std::time::Duration;

use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::net::{TcpListener, TcpStream};
use engine_supervisor::ChildPool;

use engine_rpc::{
    CompileError, CompiledBundle, CompilerService, CompilerServiceClient,
    CompilerServiceServerShared,
};
use engine_types::composition::PluginInstance;

/// Wall-clock ceiling on ONE compile in the child (tunable via
/// `ENCLAVID_COMPILE_DEADLINE_SECS`; enforced by the [`ChildPool`]). Bounds a
/// malicious wasm that would otherwise hang Cranelift and hold a child slot
/// forever — the availability guard the direct-compile design lacked. Generous:
/// a legitimate cold compile of a large fused component is seconds, not minutes.
const DEFAULT_COMPILE_DEADLINE_SECS: u64 = 300;

/// Default cap on concurrent compile children. Cranelift is CPU-bound, so this is
/// modest by design (roughly a core budget); compiles are rare (only L2 misses).
const DEFAULT_MAX_COMPILES: usize = 8;

/// The `engine_rpc::CompilerService` impl served to api: forward each compile to
/// a fresh disposable `compile-child` via the pool. Shared (`Arc`) across api
/// connections.
struct Supervisor {
    pool: ChildPool,
}

impl CompilerService for Supervisor {
    async fn compile(
        &self,
        policy: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Result<CompiledBundle, CompileError> {
        // Drive ONE compile in a fresh disposable child, under the pool's
        // concurrency bound + wall-clock deadline (the pool kills + reaps a wedged
        // child). The closure is the DOMAIN work: forward the compile.
        let outcome = self
            .pool
            // No inherited fds: the compile-child receives its `(policy, plugins)`
            // over the RPC, not by fd (only the executor hands a cwasm memfd down).
            .run(&[], move |client: CompilerServiceClient<Ciborium>| async move {
                client.compile(policy, plugins).await
            })
            .await;

        // The pool returns the closure's domain result verbatim on success; a
        // pool-level failure (spawn error, or the deadline killing a wedged
        // child) becomes a `CompileError` so api surfaces a config-resolution
        // failure (compiles are a pure function of the pinned artifacts).
        match outcome {
            Ok(domain_result) => domain_result,
            Err(pool_err) => Err(CompileError(format!("compile supervisor: {pool_err}"))),
        }
    }
}

/// Locate the `compile-child` binary: `ENCLAVID_COMPILE_CHILD_BIN` if set, else
/// the sibling of this supervisor's own executable (they build + deploy
/// together). Fails loud if neither resolves — per the minimal-defaults rule.
fn child_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ENCLAVID_COMPILE_CHILD_BIN") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::current_exe()
        .expect("compile-worker: resolve current_exe for sibling compile-child path");
    p.set_file_name("compile-child");
    p
}

/// The base channel carries the `CompilerServiceClient` from us (server) to api
/// (client).
type Cli = CompilerServiceClient<Ciborium>;

#[tokio::main]
async fn main() {
    // Fail CLOSED if the kernel's ptrace hardening is too weak to isolate one
    // escaped compile-child from a sibling's memory (see the shared assertion).
    // The compile side is PII-free, but it rides the same disposable-child pool, so
    // it asserts the same invariant — one fix, both workers.
    engine_supervisor::assert_ptrace_hardened();

    // api-facing listen address: first arg or ENCLAVID_COMPILE_WORKER_LISTEN.
    // Fail loud if absent (per the minimal-defaults rule).
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ENCLAVID_COMPILE_WORKER_LISTEN").ok())
        .expect(
            "compile-worker: listen address required (arg1 or \
             ENCLAVID_COMPILE_WORKER_LISTEN, e.g. 127.0.0.1:7001)",
        );

    let max_compiles: usize = std::env::var("ENCLAVID_MAX_COMPILES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_COMPILES);
    let deadline = Duration::from_secs(
        std::env::var("ENCLAVID_COMPILE_DEADLINE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_COMPILE_DEADLINE_SECS),
    );
    let child_exe = child_exe();

    let svc = Arc::new(Supervisor {
        pool: ChildPool::new(child_exe.clone(), max_compiles, deadline),
    });

    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("compile-worker: bind {addr}: {e}"));
    eprintln!(
        "compile-worker (supervisor): listening on {addr}, compile-child={}, \
         max_compiles={max_compiles}, deadline={}s",
        child_exe.display(),
        deadline.as_secs(),
    );

    // Mutual RA-TLS acceptor (minted once at boot): every accepted api connection is
    // wrapped in an attested TLS server that also requires an attested client cert.
    let ratls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        enclavid_ra_tls::fleet_server_config()
            .unwrap_or_else(|e| panic!("compile-worker: RA-TLS server config: {e}")),
    ));

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let svc = svc.clone();
                let ratls = ratls.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(stream, ratls, svc).await {
                        eprintln!("compile-worker: connection from {peer} ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("compile-worker: accept failed: {e}"),
        }
    }
}

/// RA-TLS-accept one api connection, then frame it with remoc and serve `CompilerService`.
async fn serve_conn(
    stream: TcpStream,
    ratls: tokio_rustls::TlsAcceptor,
    svc: Arc<Supervisor>,
) -> Result<(), String> {
    let tls = ratls.accept(stream).await.map_err(|e| format!("RA-TLS accept: {e}"))?;
    let (read, write) = tokio::io::split(tls);
    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(engine_rpc::connection_cfg(), read, write)
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
