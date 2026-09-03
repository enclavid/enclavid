//! The `compile-worker` deployable: the SUPERVISOR of the compile side.
//!
//! It LISTENS for the orchestrator (api) and serves `engine_rpc::CompilerService`
//! — the same api-facing contract as before — but it runs NO Cranelift itself.
//! Per compile it drives a fresh `engine-compiler-child` PROCESS (spawned + bounded +
//! deadline-guarded + reaped by the shared [`engine_supervisor::ChildPool`]) and
//! forwards the `(policy, plugins)` to it. Cranelift over UNTRUSTED wasm — a wide
//! surface — runs ONLY in that disposable per-compile child, so a compiler-bug
//! exploit is confined to one compile (no persistent implant that could poison a
//! later tenant's cwasm). It is started for api, not by it — one instance per
//! guest, brought up at boot.
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
//! Transport to api: a listener under mutual RA-TLS — TCP by default, vsock
//! under that feature, which is what the measured image builds. The
//! supervisor↔child hop is a private per-child socketpair (never leaves this
//! host).

use std::sync::Arc;
use std::time::Duration;

use engine_supervisor::{ChildPool, Hardening};
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;

use engine_rpc::{
    CompileError, CompiledBundle, CompilerService, CompilerServiceClient,
    CompilerServiceServerShared,
};
use engine_types::composition::PluginInstance;
use fleet_transport::LegFailure;
use safe_logger::{debug, info, reason, safe, warn};

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
/// a fresh disposable `engine-compiler-child` via the pool. Shared (`Arc`) across api
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
            // No inherited fds: the engine-compiler-child receives its `(policy, plugins)`
            // over the RPC, not by fd (only the executor hands a cwasm memfd down).
            .run(
                &[],
                move |client: CompilerServiceClient<Ciborium>| async move {
                    client.compile(policy, plugins).await
                },
            )
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

/// Locate the `engine-compiler-child` binary: `ENCLAVID_COMPILER_CHILD_BIN` if set, else
/// the sibling of this supervisor's own executable. They SHIP together — the
/// image installs both into `/bin` — but they are built apart, each package by
/// its own cargo invocation, which is what keeps `engine-compiler-child`'s
/// dependency graph the short one its manifest declares. Fails loud if neither
/// resolves — per the minimal-defaults rule.
fn child_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ENCLAVID_COMPILER_CHILD_BIN") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::current_exe().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "compile-worker: cannot resolve this binary's own path, so the sibling \
             engine-compiler-child cannot be located. Stopping.",
            reason!("a constant about this image's own layout, which the host built")
        )
    });
    p.set_file_name("engine-compiler-child");
    p
}

/// The base channel carries the `CompilerServiceClient` from us (server) to api
/// (client).
type Cli = CompilerServiceClient<Ciborium>;

#[tokio::main]
async fn main() {
    // First, so nothing can speak before the channel exists. Panic locations are
    // on: this binary IS the measured code, and the compile side never sees
    // applicant data.
    safe_logger::install();
    safe_logger::install_panic(true);

    // The health port, up before anything that can be slow. The host polls it to
    // learn when this role has finished coming up — which is what lets it bring
    // the fleet up in order instead of racing it, and what replaced the old
    // "give up after a fixed budget so that silence means broken".
    //
    // Bound FIRST on purpose: everything below can take time (opening stores,
    // minting an attestation), and a port that only appears afterwards cannot
    // report the interval it exists to describe.
    let health = fleet_transport::health::Health::new();
    {
        let health_addr =
            std::env::var("ENCLAVID_COMPILE_WORKER_HEALTH_LISTEN").unwrap_or_else(|e| {
                debug!("{e}");
                safe_logger::error_and_panic!(
                    "compile-worker: ENCLAVID_COMPILE_WORKER_HEALTH_LISTEN is not set. Stopping.",
                    reason!("a constant naming a configuration key the host itself supplied")
                )
            });
        // Bound HERE, on this task, and only the answering loop is spawned:
        // binding inside the spawn would turn a failure into one dead task and
        // a guest that serves with no health port. See `health::bind`.
        let listener = fleet_transport::health::bind(&health_addr).await;
        let health = health.clone();
        tokio::spawn(async move {
            fleet_transport::health::serve(listener, move || health.body()).await
        });
    }

    // Fail CLOSED if the kernel's ptrace hardening is too weak to isolate one
    // escaped engine-compiler-child from a sibling's memory (see the shared assertion).
    // The compile side is PII-free, but it rides the same disposable-child pool, so
    // it asserts the same invariant — one fix, both workers.
    engine_supervisor::assert_ptrace_hardened();

    // api-facing listen address: first arg or ENCLAVID_COMPILE_WORKER_LISTEN.
    // Fail loud if absent (per the minimal-defaults rule).
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ENCLAVID_COMPILE_WORKER_LISTEN").ok())
        .unwrap_or_else(|| {
            safe_logger::error_and_panic!(
                "compile-worker: no listen address — pass one as the first argument or set \
                 ENCLAVID_COMPILE_WORKER_LISTEN. Stopping.",
                reason!("a constant naming a configuration key the host itself supplied")
            )
        });

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
    // Egress seccomp is ALWAYS ON in the build. It is a CONFIDENTIALITY control
    // (keeps a child an escape turns into native code from dialing the host), so it
    // must NOT be disableable by the untrusted host — which provisions the CVM's
    // environment (the same root as the tee_seal_key-from-env gap). It rides the
    // measured image; disabling it is a deliberate rebuild + re-attest, never a
    // runtime knob. The AS limit, by contrast, is availability tuning (a lax value
    // only lets the host OOM its OWN guest), so it stays env-configurable like
    // max_compiles / deadline; `ENCLAVID_COMPILE_AS_LIMIT_BYTES=0` disables it
    // (default 4 GiB — bounds a crafted input ballooning Cranelift's arena).
    let as_bytes = std::env::var("ENCLAVID_COMPILE_AS_LIMIT_BYTES")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(4 * 1024 * 1024 * 1024);
    let hardening = Hardening {
        seccomp_egress: true,
        address_space: (as_bytes != 0).then_some(as_bytes),
    };

    let child_exe = child_exe();

    let svc = Arc::new(Supervisor {
        pool: ChildPool::new(child_exe.clone(), max_compiles, deadline, Some(hardening)),
    });

    let listener = fleet_transport::bind(&addr).await.unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "compile-worker: cannot bind {}. Stopping.",
            safe(&addr, reason!("on the measured command line")),
            reason!("a constant; the address is the host's own configuration")
        )
    });
    info!(
        "compile-worker (supervisor): listening on {}, engine-compiler-child={}, \
         max_compiles={}, deadline={}s",
        safe(&addr, reason!("on the measured command line")),
        safe(
            &child_exe.display(),
            reason!("a location inside the measured image")
        ),
        safe(&max_compiles, reason!("a constant of the measured build")),
        safe(
            &deadline.as_secs(),
            reason!("a constant of the measured build")
        ),
        reason!("a constant, emitted at boot before any policy has been composed")
    );

    // Mutual RA-TLS acceptor (minted once at boot): every accepted api connection is
    // wrapped in an attested TLS server that also requires an attested client cert.
    // This build attests with a software identity the whole dev fleet shares, and
    // pins that same identity: it proves the peer links this source tree, nothing
    // about where the peer runs.
    let ratls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        enclavid_ra_tls::server_config(
            std::sync::Arc::new(enclavid_attestation::MockAttestor::dev_fleet()),
            enclavid_ra_tls::MeasurementPolicy::Pinned(vec![
                enclavid_attestation::DEV_FLEET_MEASUREMENT.to_string(),
            ]),
        )
        .unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "compile-worker: cannot build the RA-TLS server config. Stopping.",
                reason!("a constant reporting a platform state the host provisioned")
            )
        }),
    ));

    // Everything that could fail has succeeded: the stores are open, the listener
    // is bound and the attestation acceptor is minted. From here the host's probe
    // answers healthy — whether that means READY is the host's conclusion to draw,
    // not this role's to claim. See `fleet_transport::health`.
    health.declare_healthy();
    // The loop, the delay after a failed accept and the split between an error
    // that clears itself and one that does not all live in `accept_forever` —
    // four roles wrote that loop four ways and all four omitted the delay.
    fleet_transport::accept_forever(listener, move |stream, peer| {
        let svc = svc.clone();
        let ratls = ratls.clone();
        // Returns as soon as the connection is handed to its own task, so the
        // next accept is not held up behind this one's whole session.
        async move {
            tokio::spawn(async move {
                if let Err(e) = serve_conn(stream, ratls, svc).await {
                    warn!(
                        "compile-worker: connection from {} ended ({})",
                        safe(&peer, reason!("an address the host routed itself")),
                        e,
                        reason!(
                            "constant text; a connection closing is already visible to \
                             whoever carries it"
                        )
                    );
                }
            });
        }
    })
    .await
}

/// RA-TLS-accept one api connection, then frame it with remoc and serve `CompilerService`.
async fn serve_conn(
    stream: fleet_transport::Stream,
    ratls: tokio_rustls::TlsAcceptor,
    svc: Arc<Supervisor>,
) -> Result<(), LegFailure> {
    let tls = ratls.accept(stream).await.map_err(|e| {
        debug!("ra-tls accept: {e}");
        LegFailure::Attest
    })?;
    let (read, write) = tokio::io::split(tls);
    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(engine_rpc::connection_cfg(), read, write)
            .await
            .map_err(|e| {
                debug!("rpc connect: {e}");
                LegFailure::Rpc
            })?;
    tokio::spawn(conn);

    let (server, client) = CompilerServiceServerShared::<_, Ciborium>::new(svc, 4);
    tx.send(client).await.map_err(|e| {
        debug!("send service client: {e}");
        LegFailure::Clients
    })?;
    server.serve(true).await.map_err(|e| {
        debug!("serve: {e}");
        LegFailure::Serve
    })?;
    Ok(())
}
