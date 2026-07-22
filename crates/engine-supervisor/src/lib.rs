//! `engine-supervisor` — disposable per-request child-process isolation for the
//! engine fleet's workers.
//!
//! A worker SUPERVISOR (execution-worker / compile-worker) uses a [`ChildPool`]
//! to run ONE unit of untrusted work — a reducer round, or a Cranelift compile —
//! in a fresh disposable CHILD PROCESS, then discard it. So a compromise of the
//! untrusted work (a wasmtime sandbox escape, or a Cranelift bug tripped by
//! crafted input) is confined to that one throwaway process behind an OS
//! address-space boundary, with no cross-request persistence.
//!
//! ## Split of responsibility
//!
//! This crate owns the SECURITY-LOAD-BEARING, fiddly plumbing so it is written +
//! tested ONCE and both workers ride it:
//!   * [`ChildPool::run`] — acquire a concurrency permit, spawn a fresh child,
//!     hand its service client to the caller's closure, drive it under a
//!     wall-clock DEADLINE (a wedged child can't leak its permit forever), then
//!     kill + reap.
//!   * [`spawn_and_connect`] — socketpair + `Command` + fd handoff on the child's
//!     fd 0 + remoc handshake. `Stdio::from` closes the supervisor's copy of the
//!     child end, so the child's death EOFs the socket promptly.
//!   * [`adopt_fd0`] / [`serve_child`] — the child side: adopt the inherited
//!     socket, remoc-serve one service, exit when the supervisor drops its client.
//!
//! The DOMAIN stays in each worker: which service the child serves, any mid-call
//! callbacks (executor only), and any bundle cache. This crate is a domain-
//! agnostic leaf — it depends on tokio + remoc ONLY, never on `engine-rpc` /
//! `engine-types`, so the orchestrator (api) does not link it.
//!
//! The fork-zygote (warm CoW start) is intended to land in THIS crate later, so
//! both workers gain it without touching their domain code.

use std::future::Future;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use remoc::RemoteSend;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::sync::Semaphore;

/// How long to wait for a child to exit (after its client is dropped / it is
/// killed) before giving up on the reap. `kill_on_drop` backstops it.
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on the child HANDSHAKE (spawn + remoc hello + receiving the child's
/// service client). A well-behaved child completes this in milliseconds over the
/// local socketpair; this only stops a MALFORMED child — one that connects but
/// never sends its client — from parking `run` (and holding its permit) forever,
/// making the "a child can never hold its slot beyond a bounded time" invariant
/// UNCONDITIONAL (the per-request deadline covers the work phase). Not adversary-
/// reachable today — untrusted work runs only after the handshake, inside the
/// deadline — but cheap symmetry.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The remoc connection config the child hop uses. Raises `max_data_size` from
/// chmux's 512 KiB default: a compile bundle's `cwasm` runs ~10-15 MiB, so the
/// default would reject a `prime` outright. (The engine RPC contract raises the
/// same limit on the api hop; this crate is a leaf and can't name that constant,
/// so it keeps its own — the transport tuning for the child hop.)
// `remoc::Cfg` is `#[non_exhaustive]`, so a struct literal (`Cfg { .., ..default }`)
// can't be built from here — the mutate-after-default is the only option.
#[allow(clippy::field_reassign_with_default)]
fn connection_cfg() -> remoc::Cfg {
    let mut cfg = remoc::Cfg::default();
    cfg.max_data_size = 64 * 1024 * 1024;
    // Flush immediately: chmux's default 20 ms `flush_delay` (a throughput
    // coalescing timer) adds ~20 ms per SEND direction to our latency-bound
    // request/response RPC — measured ~40 ms/round-trip. Each side flushes its own
    // sends, so BOTH this (child-serve) side and the engine-rpc (api/supervisor)
    // side must set it. Nothing to coalesce: our writes are whole RPC frames.
    cfg.flush_delay = std::time::Duration::ZERO;
    cfg
}

/// A failure of the SUPERVISOR itself — distinct from the domain call's own error
/// (which the caller's closure returns and maps). Kept separate so a per-request
/// wall-clock deadline (a real availability control) is never confused with a
/// domain compile/run failure.
#[derive(Debug)]
pub enum SupervisorError {
    /// Spawning the child or handshaking with it failed.
    Spawn(String),
    /// The child did not finish the request within the pool's deadline — it was
    /// killed. The caller maps this to its own 5xx-class domain error so the
    /// request fails safe (and, for a keyless worker, is retryable).
    Deadline(Duration),
    /// The pool's concurrency semaphore was closed (worker shutting down).
    Saturated,
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupervisorError::Spawn(m) => write!(f, "spawn child: {m}"),
            SupervisorError::Deadline(d) => {
                write!(f, "child exceeded the {}s round deadline (killed)", d.as_secs())
            }
            SupervisorError::Saturated => write!(f, "child pool is shutting down"),
        }
    }
}
impl std::error::Error for SupervisorError {}

/// Spawns a fresh disposable child process per request, bounds concurrency, and
/// enforces a per-request wall-clock deadline. Cheap to clone-share (`Arc` the
/// pool if serving concurrently); the semaphore is the only shared state.
pub struct ChildPool {
    exe: std::path::PathBuf,
    slots: Arc<Semaphore>,
    deadline: Duration,
}

impl ChildPool {
    /// `exe` is the child binary this pool spawns; `max_children` bounds
    /// concurrent live children (deployment envelope — one process each);
    /// `deadline` is the per-request wall-clock ceiling.
    pub fn new(exe: std::path::PathBuf, max_children: usize, deadline: Duration) -> Self {
        Self {
            exe,
            slots: Arc::new(Semaphore::new(max_children)),
            deadline,
        }
    }

    /// Spawn a fresh child, hand its service client `Cli` to `f`, drive `f` under
    /// the concurrency bound + wall-clock deadline, then kill + reap the child.
    ///
    /// `f` does the DOMAIN work (e.g. `client.prime(bundle).await?;
    /// client.run(..).await`, or `client.compile(..).await`) and returns its own
    /// `Result<T, DomainErr>`; the pool returns that verbatim on success. A
    /// pool-level failure — spawn error, or the deadline elapsing on a WEDGED
    /// child (one keeping its remoc reactor alive while parking the call, or a
    /// hung upstream callback) — is a [`SupervisorError`] the caller maps to its own
    /// fail-safe error. When `f`'s future finishes (or the deadline cancels it)
    /// the client it owns drops, ending the child's serve loop so it exits.
    pub async fn run<Cli, F, Fut, T>(&self, f: F) -> Result<T, SupervisorError>
    where
        Cli: RemoteSend,
        F: FnOnce(Cli) -> Fut,
        Fut: Future<Output = T>,
    {
        // Hold a permit for the whole request; released when this fn returns
        // (success, domain error, or deadline) — so a killed wedged child frees
        // its slot instead of starving the worker.
        let _permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| SupervisorError::Saturated)?;

        // Bound the handshake too, so even a malformed child that connects but
        // never sends its client can't hold the permit forever (on elapse, the
        // dropped future's `child` is killed + reaped by kill_on_drop).
        let (mut child, client) = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            spawn_and_connect::<Cli>(&self.exe),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => return Err(SupervisorError::Spawn(e)),
            Err(_elapsed) => {
                return Err(SupervisorError::Spawn(format!(
                    "child handshake exceeded {}s",
                    CONNECT_TIMEOUT.as_secs()
                )));
            }
        };

        match tokio::time::timeout(self.deadline, f(client)).await {
            Ok(out) => {
                // `f` finished → its `client` dropped → child serve loop ends →
                // the process exits; reap it (kill_on_drop backstops a straggler).
                let _ = tokio::time::timeout(REAP_TIMEOUT, child.wait()).await;
                Ok(out)
            }
            Err(_elapsed) => {
                // Deadline: the timeout dropped `f` (and its client). A wedged
                // child may ignore that, so kill it explicitly and reap.
                let _ = child.start_kill();
                let _ = tokio::time::timeout(REAP_TIMEOUT, child.wait()).await;
                Err(SupervisorError::Deadline(self.deadline))
            }
        }
    }
}

/// Spawn `exe` as a fresh child with one end of a socketpair on its fd 0, frame
/// the supervisor end with remoc (supervisor = client, child = server), and hand
/// back the child handle (`kill_on_drop`) + its service client `Cli` (received on
/// the base channel). Uses the 64 MiB [`connection_cfg`] — a `prime` ships a
/// ~10-15 MiB cwasm.
pub async fn spawn_and_connect<Cli>(exe: &Path) -> Result<(tokio::process::Child, Cli), String>
where
    Cli: RemoteSend,
{
    let (sup_end, child_end) =
        std::os::unix::net::UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    sup_end
        .set_nonblocking(true)
        .map_err(|e| format!("sup_end non-blocking: {e}"))?;

    let mut cmd = tokio::process::Command::new(exe);
    // Hand the child its socketpair end on fd 0 (a socket is bidirectional, so
    // the child reads AND writes it). `Stdio::from` takes ownership of
    // `child_end` and CLOSES the supervisor's copy after spawn, so ONLY the child
    // holds that end — its death then EOFs `sup_end` promptly (no crash-path hang).
    cmd.stdin(std::process::Stdio::from(OwnedFd::from(child_end)));
    // Backstop: an early return / cancelled request SIGKILLs + reaps the child.
    cmd.kill_on_drop(true);
    let child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", exe.display()))?;

    let sup_end =
        tokio::net::UnixStream::from_std(sup_end).map_err(|e| format!("adopt sup_end: {e}"))?;
    let (read, write) = sup_end.into_split();
    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(connection_cfg(), read, write)
            .await
            .map_err(|e| format!("child remoc connect: {e}"))?;
    tokio::spawn(conn);
    let client = rx
        .recv()
        .await
        .map_err(|e| format!("recv child client: {e}"))?
        .ok_or_else(|| "child closed before sending its service client".to_string())?;
    Ok((child, client))
}

/// Adopt fd 0 — the socketpair end the supervisor placed there via
/// `Command::stdin` — as a tokio [`UnixStream`](tokio::net::UnixStream). The
/// child's entry point calls this, then [`serve_child`] (or its own remoc serve).
pub fn adopt_fd0() -> std::io::Result<tokio::net::UnixStream> {
    // SAFETY: fd 0 is the socketpair end the supervisor placed via
    // `Command::stdin(Stdio::from(child_end))`; this process owns it.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(0) };
    std_stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(std_stream)
}

/// The child side: adopt fd 0, frame it with remoc, and serve `service` until the
/// supervisor drops its client (request done) — then return so the process exits.
/// `Srv` is the bindgen `…ServerShared` for the child's remoc trait (e.g.
/// `ChildServiceServerShared<Child, Ciborium>`); `request_buffer` is remoc's
/// per-connection request buffer (1 is fine for a one-request child).
pub async fn serve_child<Target, Srv>(
    service: Arc<Target>,
    request_buffer: usize,
) -> Result<(), String>
where
    Srv: ServerShared<Target, Ciborium>,
    Srv::Client: RemoteSend + Clone,
{
    let stream = adopt_fd0().map_err(|e| format!("adopt fd0: {e}"))?;
    let (read, write) = stream.into_split();
    let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, Srv::Client, Srv::Client, Ciborium>(
        connection_cfg(),
        read,
        write,
    )
    .await
    .map_err(|e| format!("remoc connect: {e}"))?;
    tokio::spawn(conn);

    let (server, client) = Srv::new(service, request_buffer);
    tx.send(client)
        .await
        .map_err(|e| format!("send service client: {e}"))?;
    server.serve(true).await.map_err(|e| format!("serve: {e}"))?;
    Ok(())
}
