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
//!     child end, so the child's death EOFs the socket promptly. It also installs
//!     any caller-supplied fds at deterministic numbers ([`FIRST_INHERITED_FD`]..),
//!     CLOEXEC-cleared so ONLY they survive exec — the capability-scoped handoff the
//!     executor uses to give a child a read-only fd to just ITS cwasm memfd.
//!   * [`adopt_fd0`] / [`serve_child`] — the child side: adopt the inherited
//!     socket, remoc-serve one service, exit when the supervisor drops its client.
//!
//! The DOMAIN stays in each worker: which service the child serves, any mid-call
//! callbacks (executor only), and any bundle cache. This crate is a domain-
//! agnostic leaf — it depends on tokio + remoc + libc ONLY, never on `engine-rpc` /
//! `engine-types`, so the orchestrator (api) does not link it.
//!
//! Fresh `exec` (not `fork`) per request is deliberate: it was measured at ~7.7 ms
//! warm, and the round's real cost sat in transport tuning, not spawn — so a
//! warm-CoW fork-zygote (with its `pidfd` / `close_range` / single-threaded-clone
//! hazards) is not worth its unsafe here.

use std::future::Future;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use remoc::RemoteSend;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::sync::Semaphore;

/// The child fd number the FIRST caller-supplied inherited fd lands on. fds 0/1/2
/// are the socketpair, stdout, and stderr; caller fds start at 3. The
/// execution-worker hands the child its composition's cwasm `memfd` here — the
/// child then `deserialize_file`s `/proc/self/fd/3` — while the compile-worker
/// passes none. Callers that pass N fds get them at `3..3+N`.
pub const FIRST_INHERITED_FD: RawFd = 3;

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
    // Pin the peer-driven port limits well below chmux's defaults (16384 ports /
    // 128 received). The child is UNTRUSTED once its wasm/Cranelift is escaped, and
    // it drives its own end of this socketpair — the default would let a compromised
    // child open thousands of ports to exhaust supervisor memory. Our RPC uses only
    // a handful of concurrent channels (base + prime/run + a few callbacks), so 256
    // is generous headroom while bounding the exhaustion surface.
    cfg.max_ports = 256;
    cfg.max_received_ports = 64;
    cfg
}

/// Boot-time assertion that the kernel's Yama `ptrace_scope` is set strictly enough
/// that a compromised child process CANNOT read a sibling child's memory
/// (`ptrace` / `process_vm_readv` / `/proc/<pid>/mem`, all gated by
/// `PTRACE_MODE_ATTACH`). This is the CODE bridge for the per-round isolation's
/// "an escape reaches one applicant, not all concurrent ones": the real enforcement
/// belongs in the measured CVM image (`kernel.yama.ptrace_scope`), but the workers
/// assert it at boot so a regressed/mis-provisioned image FAILS CLOSED here instead
/// of silently losing sibling isolation.
///
/// The floor is a COMPILE-TIME constant — deliberately NOT env-overridable. This
/// defends against the host, and the host provisions the CVM environment, so a
/// host-tunable knob could lower the floor to make the check vacuous (the same
/// reason the egress seccomp posture is compile-time, not env).
///
/// It is 3 — "no attach" — and the reason is what runs in the guest. `scope=1`
/// leaves an opt-in: a child can `PR_SET_PTRACER_ANY` and let a cooperating sibling
/// attach. `scope=2` restricts attaching to `CAP_SYS_PTRACE`, which sounds like a
/// restriction and is not one here: PID 1 runs `/bin/app` as root, the disposable
/// children inherit that, and [`spawn_and_connect`] changes neither uid nor
/// capabilities — it sets `no_new_privs`, `RLIMIT_AS` and an egress seccomp filter
/// whose default action is Allow, so `ptrace` is not among the syscalls it denies.
/// A child that an escape turns into native code therefore HOLDS `CAP_SYS_PTRACE`,
/// and "admin-only attach" admits it. Only `scope=3` denies everyone, `PTRACE_TRACEME`
/// included, and it cannot be lowered again without a reboot — which in a disposable
/// measured guest is a property rather than a cost.
///
/// Nothing in this workspace calls `ptrace`; the supervisor controls children by
/// spawn, kill and reap. So the floor costs the guest nothing.
///
/// The floor is enforced only under `guest-hardening`, the feature a measured image
/// builds with. `scope=3` is irreversible without a reboot, so it is not something a
/// developer's machine can be asked to set; the axis is compile-time rather than a
/// runtime bypass, exactly as with the attestation backend. No-op off Linux.
#[cfg(all(target_os = "linux", feature = "guest-hardening"))]
pub fn assert_ptrace_hardened() {
    // Fixed, measured floor — NOT env-tunable (see the fn doc).
    const MIN: u32 = 3;
    let path = "/proc/sys/kernel/yama/ptrace_scope";
    match std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    {
        Some(v) if v >= MIN => {
            eprintln!(
                "engine-supervisor: yama ptrace_scope={v} (>= required {MIN}) — sibling-child \
                 memory isolation active"
            );
        }
        Some(v) => panic!(
            "engine-supervisor: yama ptrace_scope={v} < required {MIN}: a compromised child \
             could read a SIBLING child's in-flight applicant memory. The measured image sets \
             `sysctl.kernel.yama.ptrace_scope={MIN}` on its command line; a build that reaches \
             here without it is mis-provisioned."
        ),
        None => panic!(
            "engine-supervisor: cannot read {path} — the Yama LSM is not enabled, so ptrace is \
             unrestricted and cross-sibling child memory reads are possible. Enable Yama and set \
             kernel.yama.ptrace_scope={MIN} in the CVM image."
        ),
    }
}

/// No-op: either this is not Linux — the disposable-child workers only enforce the
/// floor under the guest kernel — or this build did not ask for the floor, which a
/// developer's machine cannot be expected to satisfy because `scope=3` cannot be
/// undone without a reboot.
#[cfg(not(all(target_os = "linux", feature = "guest-hardening")))]
pub fn assert_ptrace_hardened() {}

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
                write!(
                    f,
                    "child exceeded the {}s round deadline (killed)",
                    d.as_secs()
                )
            }
            SupervisorError::Saturated => write!(f, "child pool is shutting down"),
        }
    }
}
impl std::error::Error for SupervisorError {}

/// Post-fork hardening applied to each disposable child. All fields take effect
/// on Linux only (no-ops on the macOS dev host). Each worker constructs its own:
/// the execution-worker (untrusted wasm) and the compile-worker (untrusted
/// Cranelift) both enable `seccomp_egress`; only the compile side sets an
/// `address_space` bound — the execute side caps wasm linear memory via wasmtime
/// `StoreLimits`, and wasmtime reserves large VIRTUAL memory a hard `RLIMIT_AS`
/// would break.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hardening {
    /// Install a seccomp filter denying socket-family egress (+ set
    /// `no_new_privs`), so a child that an escape turns into native code cannot
    /// dial the host (`AF_VSOCK`) or any network — it only ever talks over its
    /// inherited socketpair. A TARGETED egress denylist, not a full syscall
    /// allowlist: the primary containment stays keyless/disposable/ptrace
    /// isolation; this shrinks the exfil surface an escape inherits.
    pub seccomp_egress: bool,
    /// `RLIMIT_AS` ceiling (bytes) for the child, or `None`. `Some` bounds a
    /// runaway — a crafted input ballooning the compiler's arena hits the cap
    /// (mmap fails → compile errors) instead of OOMing the host — on the compile
    /// side; `None` on the execute side.
    pub address_space: Option<u64>,
}

/// The child's egress seccomp BPF: allow by default, `EPERM` the socket-family
/// creation / connect syscalls. Built ONCE (this allocates) in the PARENT and
/// cached, so `pre_exec` only installs it via a raw `seccomp(2)` over the static
/// program — async-signal-safe, no post-fork allocation. Installed while the
/// forked child is single-threaded, so it applies to the process and is inherited
/// by every thread the child spawns after `exec` (tokio's workers) without needing
/// `SECCOMP_FILTER_FLAG_TSYNC`. The children talk ONLY over their inherited
/// socketpair (fd 0) and never create a socket, so this is invisible in normal
/// operation.
#[cfg(target_os = "linux")]
fn egress_seccomp_program() -> &'static seccompiler::BpfProgram {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;

    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule, TargetArch};

    static PROG: OnceLock<seccompiler::BpfProgram> = OnceLock::new();
    PROG.get_or_init(|| {
        let arch = match std::env::consts::ARCH {
            "x86_64" => TargetArch::x86_64,
            "aarch64" => TargetArch::aarch64,
            other => panic!("egress seccomp: unsupported target arch {other}"),
        };
        // Empty rule list on a syscall = match it unconditionally → `match_action`.
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for sys in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_socketpair,
        ] {
            rules.insert(sys as i64, Vec::new());
        }
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow, // syscalls not listed: allowed
            SeccompAction::Errno(libc::EPERM as u32), // listed (blocked): EPERM
            arch,
        )
        .expect("build egress seccomp filter");
        filter
            .try_into()
            .expect("compile egress seccomp filter to BPF")
    })
}

/// Spawns a fresh disposable child process per request, bounds concurrency, and
/// enforces a per-request wall-clock deadline. Cheap to clone-share (`Arc` the
/// pool if serving concurrently); the semaphore is the only shared state.
pub struct ChildPool {
    exe: std::path::PathBuf,
    slots: Arc<Semaphore>,
    deadline: Duration,
    hardening: Option<Hardening>,
}

impl ChildPool {
    /// `exe` is the child binary this pool spawns; `max_children` bounds
    /// concurrent live children (deployment envelope — one process each);
    /// `deadline` is the per-request wall-clock ceiling; `hardening` is the
    /// post-fork sandbox posture applied to each child — `None` = none (dev /
    /// bench / test) (see [`Hardening`]).
    pub fn new(
        exe: std::path::PathBuf,
        max_children: usize,
        deadline: Duration,
        hardening: Option<Hardening>,
    ) -> Self {
        Self {
            exe,
            slots: Arc::new(Semaphore::new(max_children)),
            deadline,
            hardening,
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
    ///
    /// `inherit_fds` are handed to the child at deterministic fd numbers
    /// ([`FIRST_INHERITED_FD`]..) — the execution-worker passes its composition's
    /// cwasm memfd; the compile-worker passes `&[]`. See [`spawn_and_connect`] for
    /// the delivery + the isolation it buys. The borrows must outlive this call
    /// (they are only read up to spawn); the caller keeps them alive.
    pub async fn run<Cli, F, Fut, T>(
        &self,
        inherit_fds: &[BorrowedFd<'_>],
        f: F,
    ) -> Result<T, SupervisorError>
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
            spawn_and_connect::<Cli>(&self.exe, inherit_fds, self.hardening),
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
/// the base channel). Uses the 64 MiB [`connection_cfg`] — a `prime` ships small
/// metadata (the ~10-15 MiB cwasm is delivered out-of-band by fd, see below).
///
/// `inherit_fds` are installed at the child's [`FIRST_INHERITED_FD`].. via a
/// post-fork `dup2`, which clears CLOEXEC so ONLY they — plus fd 0/1/2 — survive
/// `exec`. Every other fd the supervisor holds is CLOEXEC (Rust sets it on all fds
/// it opens, and so does `memfd_create`), so the child inherits NOTHING else: not
/// other compositions' cwasm memfds, not sibling children's sockets. That is the
/// capability-scoping the memfd cwasm delivery relies on — a child gets a readable
/// handle to ITS composition's cwasm and to no other, closing the path-based reach
/// (and TOCTOU) a named tmpfs file would have left open to any same-uid process.
///
/// `hardening` is the child's post-fork sandbox posture (Linux; see [`Hardening`]),
/// or `None` for no hardening (dev / bench / test). stdout/stderr are nulled
/// unconditionally either way; `no_new_privs` / `RLIMIT_AS` / the egress seccomp
/// filter are applied per the `Some` posture.
pub async fn spawn_and_connect<Cli>(
    exe: &Path,
    inherit_fds: &[BorrowedFd<'_>],
    hardening: Option<Hardening>,
) -> Result<(tokio::process::Child, Cli), String>
where
    Cli: RemoteSend,
{
    let (sup_end, child_end) =
        std::os::unix::net::UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    sup_end
        .set_nonblocking(true)
        .map_err(|e| format!("sup_end non-blocking: {e}"))?;

    let mut cmd = tokio::process::Command::new(exe);
    // CODE-enforce the child's keylessness: start it with an EMPTY environment, then
    // re-add only an explicit non-secret allowlist. The child needs nothing from the
    // env (it receives all inputs over the socket), so a misconfigured deployment
    // that put a secret — e.g. a seal key — in the worker's environment can't leak it
    // into the untrusted child via `/proc/self/environ`. Keeps the "disposable child
    // holds no secret" property a property of the CODE, not of deployment discipline.
    cmd.env_clear();
    if let Ok(v) = std::env::var("RUST_BACKTRACE") {
        cmd.env("RUST_BACKTRACE", v); // panic-diagnostics only; not a secret
    }
    // Hand the child its socketpair end on fd 0 (a socket is bidirectional, so
    // the child reads AND writes it). `Stdio::from` takes ownership of
    // `child_end` and CLOSES the supervisor's copy after spawn, so ONLY the child
    // holds that end — its death then EOFs `sup_end` promptly (no crash-path hang).
    cmd.stdin(std::process::Stdio::from(OwnedFd::from(child_end)));
    // Null the child's stdout/stderr. It communicates ONLY over its socketpair
    // (fd 0) so it needs neither, and a child that an escape turns into native code
    // must not be able to write the round's plaintext to the worker's inherited
    // stdio (→ the host). Child diagnostics are dropped by design; a failure still
    // surfaces as the dropped connection / the pool's error.
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    // Backstop: an early return / cancelled request SIGKILLs + reaps the child.
    cmd.kill_on_drop(true);

    // Prepare every pre_exec input in the PARENT so the closure allocates NOTHING.
    // Caller fds land at [`FIRST_INHERITED_FD`]..: `dup2(src, dst)` clears CLOEXEC so
    // they survive exec; if `src` already equals `dst` no dup happens and we clear
    // CLOEXEC directly. Targets 3.. are disjoint from the used 0/1/2, and the only
    // caller today passes exactly one fd, so no source↔target overlap arises (an
    // overlapping N-fd caller would need dup-to-scratch reordering first).
    let mappings: Vec<(RawFd, RawFd)> = inherit_fds
        .iter()
        .enumerate()
        .map(|(i, fd)| (fd.as_raw_fd(), FIRST_INHERITED_FD + i as RawFd))
        .collect();
    #[cfg(target_os = "linux")]
    let as_limit = hardening.and_then(|h| h.address_space);
    #[cfg(target_os = "linux")]
    let seccomp_prog: Option<&'static seccompiler::BpfProgram> = hardening
        .is_some_and(|h| h.seccomp_egress)
        .then(egress_seccomp_program);
    #[cfg(target_os = "linux")]
    let want_no_new_privs = hardening.is_some_and(|h| h.seccomp_egress);
    #[cfg(not(target_os = "linux"))]
    let _ = hardening; // no post-fork hardening off Linux

    // SAFETY: the closure runs post-fork / pre-exec and calls ONLY async-signal-safe
    // syscalls (prctl / setrlimit / seccomp / dup2 / fcntl) over stack data + a
    // static BPF program built in the parent (no allocation, no locks, no panics).
    // The source fds are valid in the forked child (its fd table is a copy of ours
    // at fork) and stay open because the caller keeps the backing objects alive
    // across this call.
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            // ---- Linux post-fork hardening (no-op elsewhere) ----
            #[cfg(target_os = "linux")]
            {
                // `no_new_privs` first: required to load a seccomp filter without
                // privilege, and blocks setuid privilege gain on any later exec.
                if want_no_new_privs && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // `RLIMIT_AS` ceiling (compile side).
                if let Some(bytes) = as_limit {
                    let lim = libc::rlimit {
                        rlim_cur: bytes,
                        rlim_max: bytes,
                    };
                    if libc::setrlimit(libc::RLIMIT_AS, &lim) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                // Egress seccomp: install the pre-built denylist over the static
                // program. `SECCOMP_SET_MODE_FILTER` == 1, flags 0.
                if let Some(prog) = seccomp_prog {
                    let fprog = libc::sock_fprog {
                        len: prog.len() as u16,
                        filter: prog.as_ptr() as *mut libc::sock_filter,
                    };
                    if libc::syscall(libc::SYS_seccomp, 1, 0, &fprog as *const libc::sock_fprog)
                        != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            // ---- caller fd installation (all platforms) ----
            for &(src, dst) in &mappings {
                if src == dst {
                    let flags = libc::fcntl(dst, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(dst, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(src, dst) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", exe.display()))?;

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
    server
        .serve(true)
        .await
        .map_err(|e| format!("serve: {e}"))?;
    Ok(())
}

// Runtime smoke-test for the egress seccomp filter. Linux-only (the filter is
// Linux-only) and can't run on the macOS dev host, so it exists to run on a Linux
// CI / the SEV-SNP CVM — the runtime coverage a cross-compile-check can't give.
#[cfg(all(test, target_os = "linux"))]
mod seccomp_tests {
    use super::*;

    /// The REAL [`egress_seccomp_program`] (the same program + raw install path
    /// `spawn_and_connect` uses), installed in a forked child, must deny `socket()`
    /// with `EPERM` while leaving other syscalls working. Exit codes carry the
    /// verdict back: 42 = socket denied (filter works), 0 = socket SUCCEEDED (filter
    /// not effective → fail), 7 = the environment forbids installing a seccomp filter
    /// at all (restricted CI sandbox) → SKIP, 1 = any other error.
    #[test]
    fn egress_filter_denies_socket_but_stays_functional() {
        // Init the OnceLock in the PARENT so the post-fork child only reads the
        // static program (no allocation after fork in a multi-threaded harness).
        let prog = egress_seccomp_program();

        // SAFETY: the forked child calls ONLY async-signal-safe syscalls over the
        // pre-built static program and always `_exit`s — it never returns into the
        // test harness. The parent reaps it with `waitpid`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(7) }; // can't set no_new_privs → skip
            }
            let fprog = libc::sock_fprog {
                len: prog.len() as u16,
                filter: prog.as_ptr() as *mut libc::sock_filter,
            };
            if unsafe { libc::syscall(libc::SYS_seccomp, 1, 0, &fprog as *const libc::sock_fprog) }
                != 0
            {
                unsafe { libc::_exit(7) }; // seccomp install refused by env → skip
            }
            // Filter is now live. A benign syscall must still work (allow-by-default);
            // `getpid` can't return EPERM, so reaching here already shows non-denied
            // syscalls run. Now the denied one:
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd >= 0 {
                unsafe { libc::close(fd) };
                unsafe { libc::_exit(0) }; // socket SUCCEEDED → filter not effective
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            unsafe { libc::_exit(if errno == libc::EPERM { 42 } else { 1 }) };
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            waited,
            pid,
            "waitpid failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            libc::WIFEXITED(status),
            "seccomp probe child did not exit normally"
        );
        match libc::WEXITSTATUS(status) {
            42 => {} // socket() denied with EPERM — the filter works.
            7 => eprintln!(
                "egress_filter_denies_socket: seccomp install unsupported here — skipping"
            ),
            0 => panic!("socket() SUCCEEDED under the egress filter — seccomp not effective"),
            other => panic!("seccomp probe child exited with unexpected code {other}"),
        }
    }
}
