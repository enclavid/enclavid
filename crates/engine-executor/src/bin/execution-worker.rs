//! The `execution-worker` deployable: the SUPERVISOR of the execute side.
//!
//! It LISTENS for the orchestrator (api) and serves `engine_rpc::ExecutorService`
//! — the same api-facing contract as before — but it runs NO wasm itself. Per
//! reducer round it drives a fresh `session-child` PROCESS (spawned + bounded +
//! deadline-guarded + reaped by the shared [`engine_supervisor::ChildPool`]), primes
//! it with the compiled bundle, drives exactly one round in it, and discards it.
//! Untrusted policy wasm and `Component::deserialize` execute ONLY in that
//! disposable per-round child, behind an OS address-space boundary — so a wasmtime
//! sandbox escape is confined to one round's plaintext (one applicant), with no
//! cross-round persistence and no cross-session bleed. Started by INFRASTRUCTURE
//! (docker-compose / k8s), exactly like the hatch and the compile-worker.
//!
//! **Keyless.** The supervisor holds no `tee_seal_key` and no applicant token.
//! Two hops carry the keyless callbacks:
//!   * api → supervisor: the orchestrator passes a `CallbackServiceClient` into
//!     [`run`](ExecutorService::run) (bundle resolution + blob rehydration + state
//!     persistence, all seal-key-side).
//!   * supervisor → child: the supervisor stands up a [`RelayCallbacks`] (a
//!     narrowed [`ChildCallbacks`], NO `load_component`) that forwards the child's
//!     `media_load` / `session_change` on to the api client — so the untrusted-
//!     wasm child gets blob + state I/O but never the seal key nor the OCI-pull /
//!     compile probe surface.
//!
//! **What is domain vs supervisor.** The generic process plumbing — spawn a
//! disposable child over a socketpair, bound concurrency, enforce the per-round
//! wall-clock DEADLINE (so a wedged child can't leak its slot), kill + reap, and
//! the capability-scoped fd handoff — lives in [`engine_supervisor::ChildPool`],
//! shared with the compile-worker. What stays HERE is the executor's domain: the
//! memfd-backed L1 and the callback relay.
//!
//! **L1.** The supervisor owns the fleet's ONLY in-memory L1, one
//! [`CompositionEntry`] per `composition_key`. The compiled `cwasm` lives there as
//! a single anonymous in-RAM file — a sealed Linux `memfd` in prod, an unlinked
//! tmpfile in dev — held by fd, NOT as heap bytes and NOT as a named file (the two
//! earlier copies collapse into this one). On an L1 miss it PULLS the wire bundle
//! from api via `load_component` (`try_get_with` coalesces concurrent misses into
//! ONE pull), writes the `cwasm` into the memfd, and DROPS the wire `Vec`. Each
//! per-round child then MMAPs it via a read-only fd the supervisor hands it — never
//! a path — so no child can reach another composition's code. A live `Component`
//! never crosses the process boundary; the `Component::deserialize` unsafe sink
//! stays in the disposable child.
//!
//! Transport TODAY: a plain TCP listener (dev) to api; Plan-A swaps it for the
//! host vsock-relay rendezvous + RA-TLS. The supervisor↔child hop is a private
//! per-child socketpair (never leaves this host).

use std::fs::File;
use std::io::Write;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;
use engine_supervisor::ChildPool;

use engine_executor::{SessionState, compat_token};
use engine_rpc::{
    BundleRef, CallbackError, CallbackService, CallbackServiceClient, CatalogEntry, ChildCallbacks,
    ChildCallbacksServerShared, ChildService, ChildServiceClient, CompiledBundle, ConsentDisclosure,
    ExecError, ExecutorService, ExecutorServiceClient, ExecutorServiceServerShared, LoadError,
    RunReply, RunRequest,
};
use engine_types::composition::EmbeddedImport;

/// One composition's compiled artifact, resolved + cached SUPERVISOR-side and the
/// L1's value. The cwasm is a single anonymous in-RAM file held by fd — a sealed
/// Linux `memfd` (no filesystem name, RAM-backed, write-sealed) in prod, an unlinked
/// tmpfile in dev — so it is the FLEET's ONE copy of these bytes: the wire `Vec` from
/// api is written here and dropped. Each per-round child receives a read-only fd to
/// THIS file (never a path); the file's CLOEXEC + the deliberate dup2 in
/// [`engine_supervisor`] mean no child can reach another composition's fd. Freed when
/// the last fd closes — this entry dropping plus any child unmapping.
///
/// The cwasm is plaintext (possible embedded ML weights), but it is NOT scrubbed on
/// drop: SEV-SNP blinds the host to this RAM whether live or freed, and the entry is
/// legitimately resident in the cache for the whole time its composition is in use —
/// so a kernel-level in-guest attacker would read the LIVE copy regardless, and
/// zeroing the freed copy buys almost nothing for a chunk of `unsafe`. (Scrubbing is
/// spent where it pays and is safe: key material via `secrecy`, not bulk plaintext.)
struct CompositionEntry {
    /// The cwasm as an anonymous file (memfd/tmpfile); handed to the child by fd.
    cwasm: File,
    /// `cwasm` byte length — the moka weigher budgets the L1 by RAM, not entries.
    size: u64,
    /// Per-catalog i18n/icons import manifest (registered as strict host `Linker`
    /// instances at prime) — small, so it still rides the `prime` RPC.
    embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs (the registry-builder inputs) — also small.
    catalogs: Vec<CatalogEntry>,
}

/// Why resolving a composition into an L1 entry failed — kept typed so a config
/// resolution status (surfaced to the consumer verbatim) is never confused with a
/// local materialization failure (a fail-safe run error).
enum CompositionInitError {
    /// api's `load_component` returned a config-resolution status (e.g. 410 GONE).
    Load(LoadError),
    /// Writing/sealing the cwasm memfd failed (a local, transient host fault).
    Materialize(String),
}

/// Materialize `bytes` as the anonymous in-RAM file the child MMAPs by fd. On the
/// Linux CVM that is a sealed `memfd`: RAM-backed (never touches disk), nameless,
/// and — once written — WRITE/GROW/SHRINK-sealed so even a compromised
/// same-composition child can't mutate the shared read-only code pages other
/// children map. CLOEXEC, so an unrelated child spawn never inherits it — only
/// [`engine_supervisor`]'s deliberate dup2 hands it to the ONE target child.
#[cfg(target_os = "linux")]
fn anon_cwasm(bytes: &[u8]) -> Result<File, String> {
    let mfd = memfd::MemfdOptions::default()
        .close_on_exec(true)
        .allow_sealing(true)
        .create("enclavid-cwasm")
        .map_err(|e| format!("memfd_create: {e}"))?;
    {
        let mut w: &File = mfd.as_file();
        w.write_all(bytes).map_err(|e| format!("write cwasm memfd: {e}"))?;
    }
    mfd.add_seals(&[
        memfd::FileSeal::SealShrink,
        memfd::FileSeal::SealGrow,
        memfd::FileSeal::SealWrite,
        memfd::FileSeal::SealSeal,
    ])
    .map_err(|e| format!("seal cwasm memfd: {e}"))?;
    Ok(mfd.into_file())
}

/// Dev/test (macOS) fallback: an unlinked tmpfile has the same anonymous, fd-only,
/// refcounted lifetime as a Linux memfd (no name after unlink; no sealing). Never
/// used on the Linux CVM.
#[cfg(not(target_os = "linux"))]
fn anon_cwasm(bytes: &[u8]) -> Result<File, String> {
    let mut f = tempfile::tempfile().map_err(|e| format!("tempfile: {e}"))?;
    f.write_all(bytes).map_err(|e| format!("write cwasm tmpfile: {e}"))?;
    Ok(f)
}

/// The path a child feeds to `deserialize_file` to MMAP the inherited cwasm fd:
/// `/proc/self/fd/N` on Linux, `/dev/fd/N` on macOS — both re-open the fd the
/// supervisor installed at [`engine_supervisor::FIRST_INHERITED_FD`].
#[cfg(target_os = "linux")]
const FD_PATH_PREFIX: &str = "/proc/self/fd/";
#[cfg(not(target_os = "linux"))]
const FD_PATH_PREFIX: &str = "/dev/fd/";

/// Concurrent callback invocations the per-run relay handles. `media_load` /
/// `session_change` are serialized by the round in practice, so a small pool is
/// ample (mirrors the api-side callback server).
const CALLBACK_CONCURRENCY: usize = 4;

/// Wall-clock ceiling on ONE round in the child (tunable via
/// `ENCLAVID_ROUND_DEADLINE_SECS`; enforced by the [`ChildPool`]). A child that
/// WEDGES rather than crashes — an escaped payload that keeps its remoc reactor
/// answering keepalives while parking the `run`, or a hung upstream callback —
/// would otherwise hold its child-slot permit forever and, after `max_children`
/// such rounds, starve the WHOLE worker (the exact whole-worker blast radius this
/// split exists to bound; remoc has a dead-transport timeout but NO per-request
/// deadline). On expiry the pool kills the child and we surface `ExecError::Run`
/// so api returns 5xx and the applicant retries against intact api-side state.
/// Generous so no legitimately slow round (ML inference, OCR) is false-killed.
const DEFAULT_ROUND_DEADLINE_SECS: u64 = 120;

/// Default L1 (memfd cwasm-cache) RAM budget (tunable via
/// `ENCLAVID_BUNDLE_CACHE_BYTES`). The cache is weighed by `cwasm` length so this
/// is a BYTE ceiling, not an entry count: each cwasm is ~10-15 MiB of memfd RAM, so
/// an entry-count cap would nominally admit >100 GB, and an authenticated consumer
/// minting many distinct `composition_key`s could OOM the supervisor (crashing
/// every concurrent in-flight round). 2 GiB holds ~130-200 compositions, far
/// under any deployment box.
const DEFAULT_BUNDLE_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The `engine_rpc::ExecutorService` impl. Shared (`Arc`) across api connections;
/// each round runs in its own child, spawned + bounded + deadline-guarded by
/// [`ChildPool`].
struct Supervisor {
    /// L1: ONE [`CompositionEntry`] per composition — the cwasm as an anonymous
    /// in-RAM fd plus its small registry metadata. Long-lived across sessions +
    /// rounds; the expensive layer (OCI pull + compile + api round-trip) is what
    /// this saves. Replaces the former split byte-cache + tmpfs-file cache: the
    /// cwasm lives ONCE here, delivered to each child by fd.
    compositions: Cache<String, Arc<CompositionEntry>>,
    /// The disposable per-round child pool (spawn + concurrency bound + round
    /// deadline + reap), shared with the compile-worker.
    pool: ChildPool,
}

impl Supervisor {
    /// Resolve the composition's L1 entry, PULLING from api on a miss and
    /// materializing the cwasm into an anonymous fd (dropping the wire `Vec`).
    /// `try_get_with` coalesces concurrent misses for the same key into ONE
    /// `load_component` pull + ONE memfd write; errors aren't cached (a transient
    /// failure retries). A config-resolution status (e.g. 410 GONE) is preserved as
    /// [`ExecError::Config`] so api surfaces it verbatim. Runs supervisor-side,
    /// BEFORE the child is spawned, so a config failure never spends a child slot.
    async fn resolve_composition(
        &self,
        composition_key: &str,
        callbacks: &CallbackServiceClient<Ciborium>,
    ) -> Result<Arc<CompositionEntry>, ExecError> {
        let cb = callbacks.clone();
        let key = composition_key.to_string();
        self.compositions
            .try_get_with(key.clone(), async move {
                let bundle = cb
                    .load_component(key, compat_token())
                    .await
                    .map_err(CompositionInitError::Load)?;
                let CompiledBundle { cwasm, embedded_imports, catalogs } = bundle;
                // Zeroize the transient wire copy on drop: it's plaintext (possible
                // model weights) and, once written into the memfd, a needless second
                // heap copy. (The remoc/ciborium receive buffers upstream stay
                // unscrubbed — outside our control — so SEV-SNP remains the real
                // host-side guarantee; this just removes the copy we own.)
                let cwasm = Zeroizing::new(cwasm);
                let size = cwasm.len() as u64;
                let file = anon_cwasm(&cwasm).map_err(CompositionInitError::Materialize)?;
                // The wire `Vec` drops here (zeroized) — the memfd is now the ONLY copy.
                Ok::<_, CompositionInitError>(Arc::new(CompositionEntry {
                    cwasm: file,
                    size,
                    embedded_imports,
                    catalogs,
                }))
            })
            .await
            .map_err(|arc: Arc<CompositionInitError>| match &*arc {
                CompositionInitError::Load(e) => ExecError::Config {
                    status: e.status,
                    message: e.message.clone(),
                },
                CompositionInitError::Materialize(m) => {
                    ExecError::Run(format!("materialize cwasm: {m}"))
                }
            })
    }
}

impl ExecutorService for Supervisor {
    async fn run(
        &self,
        req: RunRequest,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<RunReply, ExecError> {
        // Resolve the L1 entry (pull from api + materialize the memfd on miss) —
        // domain-side, before any child is spawned.
        let entry = self.resolve_composition(&req.composition_key, &callbacks).await?;
        // Borrow the composition's cwasm fd to hand the child at spawn. `entry`
        // (holding the memfd open) lives across the whole `pool.run().await` below,
        // so the fd is valid at fork/dup2 time; the child's own inherited fd then
        // keeps the memfd alive independently.
        let cwasm_fd = entry.cwasm.as_fd();
        // The child re-opens its inherited fd (`/proc/self/fd/N`) and MMAPs it via
        // `deserialize_file`; the 7-15 MiB never crosses the child hop — only the
        // fd-path + small metadata do.
        let bundle_ref = BundleRef {
            cwasm_path: format!("{FD_PATH_PREFIX}{}", engine_supervisor::FIRST_INHERITED_FD),
            embedded_imports: entry.embedded_imports.clone(),
            catalogs: entry.catalogs.clone(),
        };
        let RunRequest { session_state, event, props, .. } = req;

        // Drive ONE round in a fresh disposable child, under the pool's
        // concurrency bound + wall-clock deadline (the pool kills + reaps a wedged
        // child so it can't leak its slot). The pool installs the cwasm fd at
        // `FIRST_INHERITED_FD` in the child; the closure is the DOMAIN work: prime
        // the child (MMAP the cwasm), stand up the callback relay, run.
        let outcome = self
            .pool
            .run(std::slice::from_ref(&cwasm_fd), move |client: ChildServiceClient<Ciborium>| async move {
                // Prime: the child MMAPs the cwasm via `deserialize_file` on its
                // inherited fd; only the fd-path + small metadata cross the hop.
                client.prime(bundle_ref).await?;

                // Relay: the child's media_load / session_change forward THROUGH
                // here to api's callbacks (the seal-key holder). No `load_component`
                // is exposed to the child.
                let relay = Arc::new(RelayCallbacks { upstream: callbacks });
                let (relay_server, relay_client) =
                    ChildCallbacksServerShared::<_, Ciborium>::new(relay, CALLBACK_CONCURRENCY);
                tokio::spawn(async move {
                    let _ = relay_server.serve(true).await;
                });

                client.run(session_state, event, props, relay_client).await
            })
            .await;

        // The pool returns the closure's domain result verbatim on success; a
        // pool-level failure (spawn error, or the deadline killing a wedged
        // child) becomes a fail-safe `ExecError::Run` (api 5xx → applicant retry).
        match outcome {
            Ok(domain_result) => domain_result,
            Err(pool_err) => Err(ExecError::Run(format!("child supervisor: {pool_err}"))),
        }
    }
}

/// Forwards the child's narrowed callbacks straight to api's full
/// `CallbackService` client. The upstream client method already returns the same
/// `Result<_, CallbackError>` these methods return (remoc folds transport errors
/// into `CallbackError`), so each is a one-line forward.
struct RelayCallbacks {
    upstream: CallbackServiceClient<Ciborium>,
}

impl ChildCallbacks for RelayCallbacks {
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
        self.upstream.media_load(hash).await
    }

    async fn session_change(
        &self,
        state: SessionState,
        disclosures: Vec<ConsentDisclosure>,
        media: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), CallbackError> {
        self.upstream.session_change(state, disclosures, media).await
    }
}

/// Locate the `session-child` binary: `ENCLAVID_SESSION_CHILD_BIN` if set, else
/// the sibling of this supervisor's own executable (they build + deploy
/// together). Fails loud if neither resolves — per the minimal-defaults rule.
fn child_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ENCLAVID_SESSION_CHILD_BIN") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::current_exe()
        .expect("execution-worker: resolve current_exe for sibling session-child path");
    p.set_file_name("session-child");
    p
}

/// The base channel carries the `ExecutorServiceClient` from us (server) to api
/// (client).
type Cli = ExecutorServiceClient<Ciborium>;

#[tokio::main]
async fn main() {
    // Fail CLOSED if the kernel isn't hardened enough to keep one escaped child
    // out of a sibling child's in-flight applicant memory (the per-round isolation
    // rests on this). The real enforcement is the measured CVM image; this makes a
    // regressed image crash here instead of silently losing the guarantee.
    engine_supervisor::assert_ptrace_hardened();

    // api-facing listen address: first arg or ENCLAVID_EXECUTION_WORKER_LISTEN.
    // Fail loud if absent (per the minimal-defaults rule).
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ENCLAVID_EXECUTION_WORKER_LISTEN").ok())
        .expect(
            "execution-worker: listen address required (arg1 or \
             ENCLAVID_EXECUTION_WORKER_LISTEN, e.g. 127.0.0.1:7002)",
        );

    // Hard cap on concurrent per-round children (deployment envelope). Tunable;
    // a sane default keeps memory bounded (one process each).
    let max_children: usize = std::env::var("ENCLAVID_MAX_CHILDREN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let round_deadline = Duration::from_secs(
        std::env::var("ENCLAVID_ROUND_DEADLINE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_ROUND_DEADLINE_SECS),
    );
    let bundle_cache_bytes: u64 = std::env::var("ENCLAVID_BUNDLE_CACHE_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BUNDLE_CACHE_BYTES);

    let child_exe = child_exe();

    let svc = Arc::new(Supervisor {
        // ONE L1: the cwasm memfd + registry metadata per composition. Weigh each
        // entry by its cwasm length so `max_capacity` is a RAM budget, not an entry
        // count (each cwasm is ~10-15 MiB of memfd RAM). Mirrors the api-side
        // MediaCache; closes the consumer-driven OOM. A cwasm past u32::MAX is
        // clamped — it can't occur.
        compositions: Cache::builder()
            .weigher(|_key, v: &Arc<CompositionEntry>| v.size.try_into().unwrap_or(u32::MAX))
            .max_capacity(bundle_cache_bytes)
            .time_to_idle(Duration::from_secs(3600))
            .build(),
        pool: ChildPool::new(child_exe.clone(), max_children, round_deadline),
    });

    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("execution-worker: bind {addr}: {e}"));
    eprintln!(
        "execution-worker (supervisor): listening on {addr}, session-child={}, \
         max_children={max_children}, round_deadline={}s, bundle_cache={} MiB",
        child_exe.display(),
        round_deadline.as_secs(),
        bundle_cache_bytes / (1024 * 1024),
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let svc = svc.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(stream, svc).await {
                        eprintln!("execution-worker: connection from {peer} ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("execution-worker: accept failed: {e}"),
        }
    }
}

/// Frame one accepted api connection with remoc and serve `ExecutorService`.
async fn serve_conn(stream: TcpStream, svc: Arc<Supervisor>) -> Result<(), String> {
    let (read, write) = stream.into_split();
    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(engine_rpc::connection_cfg(), read, write)
            .await
            .map_err(|e| format!("remoc connect: {e}"))?;
    tokio::spawn(conn);

    let (server, client) = ExecutorServiceServerShared::<_, Ciborium>::new(svc, 4);
    tx.send(client)
        .await
        .map_err(|e| format!("send service client: {e}"))?;
    server.serve(true).await.map_err(|e| format!("serve: {e}"))?;
    Ok(())
}
