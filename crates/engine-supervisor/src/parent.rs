//! The PARENT half: everything a supervisor does to a child it owns.
//!
//! Spawn, harden, bound, kill, reap. None of it is reachable from a child — this
//! module is behind the `parent` feature, and the child packages take
//! `default-features = false`. The gate is not decoration: it is what keeps
//! `tokio/process` out of a shipped child build, and with it the runtime's
//! signal driver — the reason a process that spawns nothing used to open a
//! `socketpair` on its way up, and so the reason the egress filter could not
//! deny that syscall.

use std::future::Future;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use remoc::RemoteSend;
use remoc::codec::Ciborium;
use tokio::sync::Semaphore;

use crate::connection_cfg;

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
/// Both outcomes go to the log device rather than to stderr or a panic payload,
/// because on a guest neither of those is readable: stderr is `/dev/null` there,
/// and `install_panic` deliberately never forwards a payload. A load-bearing
/// boot check that reports only `panic at lib.rs:NNN` tells an operator the
/// guest died and nothing about why.
///
/// The value is safe to disclose because the host chose it: it is
/// `sysctl.kernel.yama.ptrace_scope` off the measured command line, so the port
/// carries back a number its reader set.
#[cfg(all(target_os = "linux", feature = "guest-hardening"))]
pub fn assert_ptrace_hardened() {
    use safe_logger::{error, info, reason, safe};

    // Fixed, measured floor — NOT env-tunable (see the fn doc).
    const MIN: u32 = 3;
    let path = "/proc/sys/kernel/yama/ptrace_scope";
    match std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    {
        Some(v) if v >= MIN => {
            info!(
                "engine-supervisor: yama ptrace_scope={} (>= required {}) — sibling-child \
                 memory isolation active",
                safe(
                    &v,
                    reason!("read back from the measured command line the host set")
                ),
                safe(&MIN, reason!("a compile-time constant of this build")),
                reason!("a constant, emitted once at boot before any session exists"),
            );
        }
        Some(v) => {
            error!(
                "engine-supervisor: yama ptrace_scope={} < required {} — a compromised child \
                 could read a SIBLING child's in-flight applicant memory. The measured image \
                 sets it on its command line; this build is mis-provisioned. Stopping.",
                safe(
                    &v,
                    reason!("read back from the measured command line the host set")
                ),
                safe(&MIN, reason!("a compile-time constant of this build")),
                reason!("a constant, emitted once at boot before any session exists"),
            );
            panic!("engine-supervisor: yama ptrace_scope={v} < required {MIN}");
        }
        None => {
            error!(
                "engine-supervisor: cannot read the yama ptrace_scope — the LSM is not enabled, \
                 so ptrace is unrestricted and cross-sibling child memory reads are possible. \
                 Stopping.",
                reason!("a constant, emitted once at boot before any session exists"),
            );
            panic!("engine-supervisor: cannot read {path}");
        }
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
    /// Install a seccomp filter denying egress (+ set `no_new_privs`), so a
    /// child that an escape turns into native code cannot get the round's
    /// plaintext to the host. Three families, because there are three ways out
    /// that need nothing inherited: the socket calls, so it cannot dial the host
    /// (`AF_VSOCK`) or any network; opening anything for writing, so it cannot
    /// reach the serial device by path either; and `ioctl` for any request but
    /// the one the child itself makes, which is what puts `/dev/sev-guest` out of
    /// reach. It only ever talks over its inherited socketpair.
    ///
    /// A TARGETED denylist, not a full syscall allowlist: the primary
    /// containment stays keyless/disposable/ptrace isolation; this shrinks the
    /// exfil surface an escape inherits. See `egress_seccomp_program` in this
    /// module for what each family costs and why it is safe to deny.
    pub seccomp_egress: bool,
    /// `RLIMIT_AS` ceiling (bytes) for the child, or `None`. `Some` bounds a
    /// runaway — a crafted input ballooning the compiler's arena hits the cap
    /// (mmap fails → compile errors) instead of OOMing the host — on the compile
    /// side; `None` on the execute side.
    pub address_space: Option<u64>,
}

/// The child's egress seccomp BPF: allow by default, `EPERM` the three ways out
/// of this process that reach the host — creating a socket, opening anything for
/// writing, and `ioctl` on anything but the child's own socketpair.
///
/// Built ONCE (this allocates) in the PARENT and cached, so `pre_exec` only
/// installs it via a raw `seccomp(2)` over the static program — async-signal-safe,
/// no post-fork allocation. Installed while the forked child is single-threaded,
/// so it applies to the process and is inherited by every thread the child spawns
/// after `exec` (tokio's workers) without needing `SECCOMP_FILTER_FLAG_TSYNC`.
///
/// **Sockets** were the first half: the children talk ONLY over the socketpair
/// the supervisor put on fd 0 before exec, and create none of their own, so
/// denying that family is invisible in normal operation.
///
/// **Write-opens** are the second, and they close a route that needs nothing
/// inherited. `/dev` is devtmpfs, the child shares the worker's mount namespace
/// and uid, and the serial device the host reads is a node with a name — so
/// `openat(AT_FDCWD, "/dev/ttyS0", O_WRONLY)` reaches the host without a
/// descriptor, a socket or an environment variable. The other closures here
/// (`Stdio::null()`, `env_clear`, `O_CLOEXEC`) all guard inheritance, which this
/// walks around.
///
/// Denying WRITE opens rather than all opens is deliberate. A filter cannot see
/// a path: the argument is a pointer, and dereferencing one is exactly what
/// seccomp may not do. But it can see the access mode, and exfiltration needs a
/// writable descriptor. So read-only opens still work — `available_parallelism`
/// reading cgroup files, a runtime reading `/proc/self/maps` — and neither child
/// writes a file in any build (grepped: no `File::create`, no `OpenOptions`,
/// every input and output crosses fd 0).
///
/// **`ioctl`** is the third, and it is the one that reaches a different asset.
/// `/dev/sev-guest` is opened READ-only by the `sev` crate, so the write-open
/// rule never sees it, and everything the device does is an `ioctl` — through it
/// an escaped child could ask the Secure Processor for an attestation report over
/// `report_data` of its choosing, or for a derived key. Denying `ioctl` closes
/// that, and the exception is stated by the rule below rather than here: only
/// `FIONBIO` survives, because `adopt_fd0` sets the inherited socketpair
/// non-blocking as the child's first act after exec.
#[cfg(target_os = "linux")]
fn egress_seccomp_program() -> &'static seccompiler::BpfProgram {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;

    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    /// Match an open whose access mode is not `O_RDONLY`.
    ///
    /// Two rules rather than one "not O_RDONLY", because rules for a syscall are
    /// OR-ed while conditions inside a rule are AND-ed, and the operator set has
    /// no negated mask.
    ///
    /// `Dword` because the kernel truncates `flags` to `int` before looking at
    /// it: the low 32 bits ARE the argument, so nothing can be smuggled past this
    /// in the high half.
    fn deny_write_opens(flags_arg: u8) -> Vec<SeccompRule> {
        [libc::O_WRONLY, libc::O_RDWR]
            .into_iter()
            .map(|mode| {
                let writable = SeccompCondition::new(
                    flags_arg,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(libc::O_ACCMODE as u64),
                    mode as u64,
                )
                .expect("build open-flags condition");
                SeccompRule::new(vec![writable]).expect("build write-open rule")
            })
            .collect()
    }

    static PROG: OnceLock<seccompiler::BpfProgram> = OnceLock::new();
    PROG.get_or_init(|| {
        let arch = match std::env::consts::ARCH {
            "x86_64" => TargetArch::x86_64,
            "aarch64" => TargetArch::aarch64,
            other => panic!("egress seccomp: unsupported target arch {other}"),
        };
        // Empty rule list on a syscall = match it unconditionally → `match_action`.
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        // `socket` is how an addressable endpoint comes into being and
        // `connect`/`bind` are how it is pointed somewhere; without the first
        // there is no `AF_VSOCK` to dial and no network to reach.
        //
        //
        // `socketpair` is here too, and it took two changes to get it back. It
        // came out when a test first spawned a real child under this filter and
        // the child died before its handshake: tokio's signal driver, started
        // because the child shared a package with its supervisor and so inherited
        // `tokio/process`, opens one. `engine-supervisor/parent` took that
        // dependency off the shipped child. But the TEST still spawned a child
        // with it — a test's dev-dependencies unify into the binary its own
        // package builds — so the rule stayed out a second time, until
        // `xtask::child_binary` made the tests spawn the artifact the image
        // builds rather than the one cargo had beside it.
        //
        // It is not the load-bearing rule and never was: a `socketpair` is an
        // anonymous pair connected only to each other, with no address for
        // anything outside the process to reach — a pipe that happens to be
        // sockets. It is here because a process that has no use for a syscall
        // should not be able to make it, and because being able to state that is
        // most of what the child's own package is for.
        for sys in [
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
        ] {
            rules.insert(sys as i64, Vec::new());
        }
        // `openat` carries flags in a register, so the mode is visible.
        rules.insert(libc::SYS_openat as i64, deny_write_opens(2));
        // `openat2` carries them inside a `struct open_how` behind a pointer,
        // which cannot be inspected — so it goes entirely. Nothing in this tree
        // calls it: it is newer than glibc's and musl's `open`, and Rust's std
        // does not use it.
        rules.insert(libc::SYS_openat2 as i64, Vec::new());
        #[cfg(target_arch = "x86_64")]
        {
            // Legacy entry points that aarch64 does not have at all.
            rules.insert(libc::SYS_open as i64, deny_write_opens(1));
            // `creat` is `open` with O_WRONLY|O_CREAT|O_TRUNC baked in, so there
            // is no mode to inspect.
            rules.insert(libc::SYS_creat as i64, Vec::new());
        }
        // `/dev/sev-guest` is driven by ioctl, and the `sev` crate opens it
        // READ-only (sev-8.0.0 src/firmware/guest/mod.rs:60), so the rules above
        // do not reach it. Through it a child could ask the Secure Processor for
        // an attestation report over `report_data` of its choosing — a bearer
        // proof of "I am the measured image", good against the key broker and any
        // RA-TLS peer — or for the derived key that session state is sealed
        // under. Neither is anything a per-round child has business holding:
        // attestation and key derivation happen in the worker, and the child
        // receives its plaintext already opened over fd 0.
        //
        // Everything EXCEPT the one request the runtime needs, rather than a
        // denylist of the SNP request numbers. `_IOWR` encodes the size of a
        // kernel struct, so a struct that grows renumbers the request and a rule
        // keyed on the old number would stop matching — silently, which is the
        // worst way for a control to fail. Inverting it fixes what the child may
        // do instead of guessing what it may not, and needs no SNP constant.
        //
        // `FIONBIO` is `adopt_fd0`'s `set_nonblocking` on the inherited
        // socketpair, the child's first act after exec — measured: denying ioctl
        // outright makes every child die there, before the remoc handshake.
        rules.insert(
            libc::SYS_ioctl as i64,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Ne,
                        libc::FIONBIO as u64,
                    )
                    .expect("build ioctl-request condition"),
                ])
                .expect("build ioctl rule"),
            ],
        );
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
/// the base channel). Uses the crate's 64 MiB `connection_cfg` — a `prime` ships small
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

// Runtime smoke-test for the egress seccomp filter. Linux-only (the filter is
// Linux-only) and can't run on the macOS dev host, so it exists to run on a Linux
// CI / the SEV-SNP CVM — the runtime coverage a cross-compile-check can't give.
#[cfg(all(test, target_os = "linux"))]
mod seccomp_tests {
    use super::*;

    /// The REAL `egress_seccomp_program` (the same program + raw install path
    /// `spawn_and_connect` uses), installed in a forked child, must deny both
    /// `socket()` and `socketpair()` with `EPERM` while leaving other syscalls
    /// working.
    ///
    /// `socketpair` is probed separately because it is the rule with a history —
    /// it was out of the denylist twice, both times because something in the
    /// build gave a child tokio's signal driver. This asserts the rule is ON; the
    /// child-process integration tests assert a real child still starts under it,
    /// and they spawn the image's own build so the two agree.
    ///
    /// Exit codes carry the verdict back: 42 = both denied (filter works), 0 =
    /// `socket` SUCCEEDED, 3 = `socketpair` SUCCEEDED (either → filter not
    /// effective), 7 = the environment forbids installing a seccomp filter at all
    /// (restricted CI sandbox) → SKIP, 1 = any other error.
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
            if errno != libc::EPERM {
                unsafe { libc::_exit(1) };
            }
            // The other family member, and the one that kept falling out.
            let mut sv = [0i32; 2];
            if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) }
                >= 0
            {
                unsafe { libc::close(sv[0]) };
                unsafe { libc::close(sv[1]) };
                unsafe { libc::_exit(3) }; // socketpair SUCCEEDED → rule missing
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
            42 => {} // socket() and socketpair() both denied with EPERM.
            7 => eprintln!(
                "egress_filter_denies_socket: seccomp install unsupported here — skipping"
            ),
            0 => panic!("socket() SUCCEEDED under the egress filter — seccomp not effective"),
            3 => panic!("socketpair() SUCCEEDED under the egress filter — the rule is missing"),
            other => panic!("seccomp probe child exited with unexpected code {other}"),
        }
    }

    /// The other half of the filter: an open for WRITING must be denied, and an
    /// open for READING must not be. Both halves matter — the first is the
    /// containment (a device node is reachable by name, with nothing inherited),
    /// the second is what keeps the child able to start at all, since a runtime
    /// reads cgroup and `/proc` files on its way up.
    ///
    /// The same path is used for both so the only variable is the access mode.
    /// Exit codes: 43 = both correct, 0 = the write open SUCCEEDED (containment
    /// gone), 2 = the read open was DENIED (filter too broad — this is what would
    /// break a child at exec), 7 = seccomp unavailable here → skip, 1 = other.
    #[test]
    fn egress_filter_denies_write_opens_and_allows_read_opens() {
        let prog = egress_seccomp_program();
        let path = c"/dev/null";

        // SAFETY: as above — the child only makes async-signal-safe calls over
        // the pre-built static program and always `_exit`s.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(7) };
            }
            let fprog = libc::sock_fprog {
                len: prog.len() as u16,
                filter: prog.as_ptr() as *mut libc::sock_filter,
            };
            if unsafe { libc::syscall(libc::SYS_seccomp, 1, 0, &fprog as *const libc::sock_fprog) }
                != 0
            {
                unsafe { libc::_exit(7) };
            }
            // Reading must still work: deny this and a child cannot reach `main`.
            let readable = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
            if readable < 0 {
                unsafe { libc::_exit(2) };
            }
            unsafe { libc::close(readable) };

            // Writing must not. This is the route that needs no inherited
            // descriptor: /dev/ttyS0 by name.
            let writable = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY) };
            if writable >= 0 {
                unsafe { libc::close(writable) };
                unsafe { libc::_exit(0) };
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            unsafe { libc::_exit(if errno == libc::EPERM { 43 } else { 1 }) };
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
            "open probe child did not exit normally"
        );
        match libc::WEXITSTATUS(status) {
            43 => {} // write denied, read allowed — both halves hold.
            7 => eprintln!(
                "egress_filter_denies_write_opens: seccomp install unsupported here — skipping"
            ),
            0 => panic!(
                "an O_WRONLY open SUCCEEDED under the egress filter — an escaped child could \
                 reach /dev/ttyS0 by name"
            ),
            2 => panic!(
                "an O_RDONLY open was DENIED — the filter is too broad and would stop a child \
                 from starting"
            ),
            other => panic!("open probe child exited with unexpected code {other}"),
        }
    }

    /// `ioctl` is how `/dev/sev-guest` is reached, and the `sev` crate opens that
    /// device read-only — so the write-open rules do not cover it. A child that
    /// could issue one could mint an attestation report or derive the sealing
    /// key.
    ///
    /// Exit codes: 44 = denied, 0 = the ioctl was permitted (containment gone),
    /// 7 = seccomp unavailable → skip, 1 = other.
    #[test]
    fn egress_filter_denies_ioctl() {
        let prog = egress_seccomp_program();

        // SAFETY: as above — async-signal-safe calls only, always `_exit`s.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(7) };
            }
            let fprog = libc::sock_fprog {
                len: prog.len() as u16,
                filter: prog.as_ptr() as *mut libc::sock_filter,
            };
            if unsafe { libc::syscall(libc::SYS_seccomp, 1, 0, &fprog as *const libc::sock_fprog) }
                != 0
            {
                unsafe { libc::_exit(7) };
            }
            // Any ioctl will do — the filter matches the syscall, not the
            // request. `TCGETS` on fd 0 would ordinarily return either success or
            // ENOTTY; under the filter it must be EPERM.
            let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
            let rc = unsafe { libc::ioctl(0, libc::TCGETS, termios.as_mut_ptr()) };
            if rc >= 0 {
                unsafe { libc::_exit(0) };
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            unsafe { libc::_exit(if errno == libc::EPERM { 44 } else { 1 }) };
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
            "ioctl probe child did not exit normally"
        );
        match libc::WEXITSTATUS(status) {
            44 => {} // denied with EPERM.
            7 => {
                eprintln!("egress_filter_denies_ioctl: seccomp install unsupported here — skipping")
            }
            0 => panic!(
                "ioctl was PERMITTED under the egress filter — an escaped child could reach \
                 /dev/sev-guest"
            ),
            other => panic!("ioctl probe child exited with unexpected code {other}"),
        }
    }
}
