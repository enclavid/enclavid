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
/// restriction and is not one here: PID 1 runs `/bin/app` as root and the disposable
/// children inherit that, so a child that an escape turns into native code HOLDS
/// `CAP_SYS_PTRACE` and "admin-only attach" admits it. Only `scope=3` denies
/// everyone, `PTRACE_TRACEME` included, and it cannot be lowered again without a
/// reboot — which in a disposable measured guest is a property rather than a cost.
///
/// This is now the SECOND control on that axis rather than the only one: the
/// child's syscall allowlist does not include `ptrace`, `process_vm_readv` or
/// `pidfd_getfd`, so a hardened child cannot make the call at all. The floor is
/// still worth asserting, and for a reason worth naming — it covers a child
/// spawned WITHOUT hardening, and it is enforced by the kernel rather than by
/// this process getting its own filter right.
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
    /// Install a syscall ALLOWLIST (+ set `no_new_privs`), so a child that an
    /// escape turns into native code cannot get the round's plaintext to the
    /// host. It keeps what it was measured needing — anonymous memory, its
    /// inherited socketpair, read-only files — and anything else kills the
    /// process. So it cannot create a socket, open anything for writing, submit
    /// an io_uring, mount a filesystem, `ptrace` a sibling, or use System V IPC.
    ///
    /// The name is older than the shape and kept because it is what the field
    /// still buys. See `egress_seccomp_program` in this module for where the list
    /// came from, and for the two holes a denylist left that this closes.
    pub seccomp_egress: bool,
    /// `RLIMIT_AS` ceiling (bytes) for the child, or `None`. `Some` bounds a
    /// runaway — a crafted input ballooning the compiler's arena hits the cap
    /// (mmap fails → compile errors) instead of OOMing the host — on the compile
    /// side; `None` on the execute side.
    pub address_space: Option<u64>,
}
/// The child's syscall ALLOWLIST: everything it is known to need is permitted,
/// and anything else kills the process.
///
/// Built ONCE (this allocates) in the PARENT and cached, so `pre_exec` only
/// installs it via a raw `seccomp(2)` over the static program — async-signal-safe,
/// no post-fork allocation. Installed while the forked child is single-threaded,
/// so it applies to the process and is inherited by every thread the child spawns
/// after `exec` (tokio's workers) without needing `SECCOMP_FILTER_FLAG_TSYNC`.
///
/// # Why an allowlist, after a denylist did not hold
///
/// This began as a targeted denylist — deny the socket family, deny opening
/// anything for writing, deny `ioctl` — with everything else allowed. Each rule
/// was correct and each was worth having, and the shape was still wrong, because
/// a denylist has to name every way of doing a thing and Linux keeps adding more.
/// Two were found:
///
/// * **`io_uring`** submits opens, writes and socket calls as ring entries that
///   kernel workers execute. The task itself only calls `io_uring_setup` and
///   `io_uring_enter`, so a filter watching `openat` and `socket` sees nothing at
///   all. That defeated every rule at once.
/// * **`open_by_handle_at`** is a write-capable open that is not `openat`. With
///   `/dev` mounted `nosuid` but not `nodev`, `name_to_handle_at` on `/dev/ttyS0`
///   followed by `open_by_handle_at(.., O_WRONLY)` reached the host's serial port
///   — the exact channel the write-open rule existed to close.
///
/// Neither was an oversight in the rules; both were the denylist doing what a
/// denylist does. Inverting it makes the omission direction safe: a syscall
/// nobody thought about is denied rather than allowed, and the cost of being
/// wrong is a dead round instead of a silent channel to the host.
///
/// # Where the list comes from
///
/// Measured, not guessed. Both children were traced through their full
/// lifecycles — spawn, prime/compile, one round, exit — for BOTH libc targets,
/// because they disagree in ways that matter: musl calls `open` where glibc calls
/// `openat`, waits in `epoll_pwait` where glibc uses `epoll_wait`, and creates
/// threads with `clone` where glibc uses `clone3`. The guest image is static
/// musl; the tests run the host's glibc build. Both sets are here, so both pass.
///
/// The rest are added by reasoning about paths the trace did not reach, and each
/// is marked below. The riskiest omission would have been `rt_sigreturn`: wasmtime
/// installs a SIGSEGV handler to turn a wasm trap into a Rust error, and a trap is
/// an ORDINARY outcome — fuel exhaustion, an out-of-bounds access, `unreachable`.
/// A filter without it would work in every test and kill the first round whose
/// policy trapped.
///
/// # What this leaves the child
///
/// Its inherited socketpair on fd 0, its read-only cwasm fd, anonymous memory, and
/// read-only files. It cannot create a socket, open anything for writing, submit
/// an io_uring, mount a filesystem, make a device node, `ptrace`, load BPF, or use
/// System V IPC — so it cannot reach the host, and it cannot leave anything behind
/// for the next round.
///
/// `execve` is allowed and cannot be otherwise: the filter is installed before the
/// exec that starts the child, so denying it would stop the child from starting.
/// It buys an escape nothing — a seccomp filter survives `exec`, and
/// `no_new_privs` stops it being dropped, so whatever it execs runs in this same
/// jail.
#[cfg(target_os = "linux")]
fn egress_seccomp_program() -> &'static seccompiler::BpfProgram {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;

    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    /// Everything the two children were measured making, plus what a path the
    /// trace did not reach must have. Allowed unconditionally; the three with
    /// arguments worth inspecting are added separately below.
    ///
    /// Grouped by what the child is doing, because the list is the argument: a
    /// reader should be able to ask "why can it do that?" of every line.
    const ALLOWED: &[libc::c_long] = &[
        // ── Starting up, and stopping ──────────────────────────────────────
        libc::SYS_execve, // installed pre-exec, so this one starts the child
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_arch_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list, // glibc
        libc::SYS_rseq,            // glibc
        libc::SYS_prctl,
        libc::SYS_prlimit64,
        libc::SYS_getrandom,
        libc::SYS_getpid, // reasoned: the abort path
        libc::SYS_gettid,
        // ── Memory. wasmtime reserves and releases a great deal of it ──────
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_madvise, // reasoned: allocator release, wasmtime memory reset
        libc::SYS_memfd_create, // reasoned: wasmtime's copy-on-write images
        libc::SYS_ftruncate, // reasoned: sizing the above
        // ── The one socket it was given, on fd 0 ───────────────────────────
        libc::SYS_read,
        libc::SYS_readv, // reasoned: vectored reads
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg, // reasoned: tokio's other read path
        libc::SYS_sendmsg, // reasoned: tokio's other write path
        libc::SYS_close,
        libc::SYS_fcntl,
        // No socket, socketpair, connect or bind: it creates none of its own,
        // so it can address nothing. That is the whole egress argument.
        // ── Waiting ────────────────────────────────────────────────────────
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait, // musl
        libc::SYS_eventfd2,
        libc::SYS_ppoll,
        libc::SYS_futex,
        libc::SYS_sched_yield, // reasoned: futex/spin fallbacks
        libc::SYS_sched_getaffinity,
        libc::SYS_clock_nanosleep, // reasoned: thread parking
        libc::SYS_nanosleep,       // reasoned: the same, older entry point
        libc::SYS_membarrier,      // reasoned: crossbeam-epoch
        // ── Time. Not always the vDSO: under SEV-SNP the clocksource may not
        //    be vDSO-capable, in which case these become real syscalls ──────
        libc::SYS_clock_gettime, // reasoned
        libc::SYS_clock_getres,  // reasoned
        // ── Threads. The compile child offloads Cranelift to a blocking pool
        //    and needs them; threads inside a process an attacker already owns
        //    give him nothing he did not have ────────────────────────────────
        libc::SYS_clone,  // musl
        libc::SYS_clone3, // glibc
        // ── Files, and only for reading. `open`/`openat` carry a condition ─
        libc::SYS_fstat,
        libc::SYS_newfstatat, // glibc
        libc::SYS_statx,      // glibc
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_readlinkat, // reasoned: the backtrace path
        libc::SYS_getcwd,     // reasoned: std path handling
        // NOT openat2: its flags sit behind a pointer, which a filter may not
        // dereference, so it cannot be checked and must not be allowed.
        // NOT open_by_handle_at / name_to_handle_at: a write-capable open that
        // is not `openat`. This is one of the two holes the denylist had.
        // NOT creat: it is a write-open by definition.
        // ── Signals. wasmtime turns a wasm trap into a Rust error through a
        //    SIGSEGV handler, so the return path is load-bearing ─────────────
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn, // reasoned, and the one that would have hurt
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,          // reasoned: abort() raises SIGABRT at itself
        libc::SYS_restart_syscall, // reasoned: kernel-injected on interruption
    ];

    /// Entry points aarch64 does not have at all, so naming them unconditionally
    /// would not compile there. musl uses `open` and `stat` where glibc uses
    /// `openat` and `statx`, so the guest's own libc needs them; `open` carries
    /// the same read-only condition as `openat`.
    ///
    /// The guest is x86_64 — SEV-SNP — and an aarch64 port would have to revisit
    /// this whole list against that libc rather than just this block.
    #[cfg(target_arch = "x86_64")]
    const ALLOWED_X86_64: &[libc::c_long] = &[
        libc::SYS_stat,
        libc::SYS_access,
        libc::SYS_poll,
        libc::SYS_epoll_wait,
        libc::SYS_readlink,     // reasoned: the backtrace path
        libc::SYS_gettimeofday, // reasoned: see the time group above
    ];

    /// Match an open whose access mode is `O_RDONLY`, and only that.
    ///
    /// The child reads: cgroup files for `available_parallelism`, `/proc/self`
    /// for a backtrace, and the cwasm it was handed. It writes no file in any
    /// build — measured on both libc targets, every `open` and `openat` came
    /// back `O_RDONLY`. Exfiltration needs a writable descriptor, and `/dev` is
    /// mounted without `nodev`, so the serial port the host reads is a node with
    /// a name that anything holding a write-open could reach.
    ///
    /// A filter cannot see the PATH — the argument is a pointer, and
    /// dereferencing one is exactly what seccomp may not do. It can see the
    /// mode, which is enough: this is about the verb, not the object.
    ///
    /// `Dword` because the kernel truncates `flags` to `int` before looking at
    /// it: the low 32 bits ARE the argument, so nothing can be smuggled past
    /// this in the high half. `O_LARGEFILE` and `O_CLOEXEC` ride along on musl
    /// and do not disturb the mask.
    fn read_only_open(flags_arg: u8) -> Vec<SeccompRule> {
        let read_only = SeccompCondition::new(
            flags_arg,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::O_ACCMODE as u64),
            libc::O_RDONLY as u64,
        )
        .expect("build open-flags condition");
        vec![SeccompRule::new(vec![read_only]).expect("build read-open rule")]
    }

    static PROG: OnceLock<seccompiler::BpfProgram> = OnceLock::new();
    PROG.get_or_init(|| {
        let arch = match std::env::consts::ARCH {
            "x86_64" => TargetArch::x86_64,
            "aarch64" => TargetArch::aarch64,
            other => panic!("egress seccomp: unsupported target arch {other}"),
        };

        // Empty rule list on a syscall = match it unconditionally → `match_action`,
        // which is Allow here. A syscall absent from the map falls to the
        // mismatch action, which kills.
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for sys in ALLOWED {
            rules.insert(*sys as i64, Vec::new());
        }
        #[cfg(target_arch = "x86_64")]
        for sys in ALLOWED_X86_64 {
            rules.insert(*sys as i64, Vec::new());
        }

        // `openat` carries flags in a register, so the mode is visible.
        rules.insert(libc::SYS_openat as i64, read_only_open(2));
        #[cfg(target_arch = "x86_64")]
        rules.insert(libc::SYS_open as i64, read_only_open(1));

        // `ioctl` for exactly one request. `adopt_fd0` sets the inherited
        // socketpair non-blocking as the child's first act after exec, and that
        // is the only ioctl either child was measured making.
        //
        // Allowing the one rather than denying the others is what keeps
        // `/dev/sev-guest` out of reach: it is driven purely by ioctl, and
        // through it a child could ask the Secure Processor for an attestation
        // report over `report_data` of its choosing — a bearer proof of "I am the
        // measured image", good against the key broker and any RA-TLS peer — or
        // for the derived key session state is sealed under. Neither is anything
        // a per-round child has business holding: attestation and key derivation
        // happen in the worker, and the child receives its plaintext already
        // opened over fd 0.
        //
        // Naming the one allowed request also survives a struct growing: `_IOWR`
        // encodes the size of a kernel struct, so a filter enumerating the SNP
        // request numbers would stop matching after a kernel update — silently,
        // which is the worst way for a control to fail.
        rules.insert(
            libc::SYS_ioctl as i64,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        libc::FIONBIO as u64,
                    )
                    .expect("build ioctl-request condition"),
                ])
                .expect("build ioctl rule"),
            ],
        );

        let filter = SeccompFilter::new(
            rules,
            // Not listed: KILL THE PROCESS. Loud and fail-closed — an `Errno`
            // would hand the child a failure its own code might paper over, and
            // a control that can be papered over is not one. The supervisor sees
            // the death as a dropped connection and fails the request safely;
            // `SIGSYS` in the exit status is what names the cause.
            SeccompAction::KillProcess,
            SeccompAction::Allow, // listed (and any condition met): allowed
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

// Runtime smoke-test for the egress seccomp filter. Linux-only (the filter is// Runtime smoke-test for the child's syscall allowlist. Linux-only (the filter
// is Linux-only) and can't run on the macOS dev host, so it exists to run on a
// Linux CI / the SEV-SNP CVM — the runtime coverage a cross-compile-check can't
// give.
//
// These assert the SHAPE of the filter — what it kills and what it lets past.
// That a real child survives it is asserted elsewhere, by the two integration
// tests in the child packages that spawn the image's own build and drive a full
// round through it. Both halves are needed: a filter that permits everything
// passes those, and a filter that permits nothing passes these.
#[cfg(all(test, target_os = "linux"))]
mod seccomp_tests {
    use super::*;

    /// Exit codes the probe children use, so a failure names itself.
    const ALLOWED_AND_WORKED: i32 = 42;
    const SECCOMP_UNSUPPORTED: i32 = 7;

    /// Run `probe` in a forked child under the REAL filter (the same program and
    /// the same raw install path `spawn_and_connect` uses) and report how it
    /// ended.
    ///
    /// `Killed` means the filter's mismatch action fired: `SECCOMP_RET_KILL_PROCESS`
    /// delivers SIGSYS and the process never runs another instruction, so a probe
    /// that reaches its own `_exit` proves the syscall was ALLOWED.
    ///
    /// SAFETY: the forked child calls only async-signal-safe syscalls over the
    /// pre-built static program and always `_exit`s — it never returns into the
    /// test harness. The parent reaps it with `waitpid`.
    fn under_filter(probe: impl FnOnce()) -> Outcome {
        // Init the OnceLock in the PARENT so the post-fork child only reads the
        // static program (no allocation after fork in a multi-threaded harness).
        let prog = egress_seccomp_program();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(SECCOMP_UNSUPPORTED) };
            }
            let fprog = libc::sock_fprog {
                len: prog.len() as u16,
                filter: prog.as_ptr() as *mut libc::sock_filter,
            };
            if unsafe { libc::syscall(libc::SYS_seccomp, 1, 0, &fprog as *const libc::sock_fprog) }
                != 0
            {
                unsafe { libc::_exit(SECCOMP_UNSUPPORTED) };
            }
            // The filter is live. Anything the probe calls that is not on the
            // list ends the process here, so reaching the `_exit` below is the
            // assertion.
            probe();
            unsafe { libc::_exit(ALLOWED_AND_WORKED) };
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            waited,
            pid,
            "waitpid failed: {}",
            std::io::Error::last_os_error()
        );
        if libc::WIFSIGNALED(status) {
            let signal = libc::WTERMSIG(status);
            assert_eq!(
                signal,
                libc::SIGSYS,
                "probe died of signal {signal}, not SIGSYS — that is not the filter",
            );
            return Outcome::Killed;
        }
        assert!(
            libc::WIFEXITED(status),
            "probe neither exited nor was signalled"
        );
        match libc::WEXITSTATUS(status) {
            ALLOWED_AND_WORKED => Outcome::Survived,
            SECCOMP_UNSUPPORTED => Outcome::Skipped,
            other => panic!("probe exited with unexpected code {other}"),
        }
    }

    #[derive(PartialEq, Debug)]
    enum Outcome {
        /// The filter killed it: the syscall is not on the list.
        Killed,
        /// It ran to the end: everything it called is allowed.
        Survived,
        /// This environment forbids installing a seccomp filter (restricted CI
        /// sandbox). Nothing was tested.
        Skipped,
    }

    /// Assert a probe is killed, unless the environment cannot install a filter.
    fn assert_killed(what: &str, probe: impl FnOnce()) {
        match under_filter(probe) {
            Outcome::Killed => {}
            Outcome::Skipped => eprintln!("seccomp install unsupported here — skipping {what}"),
            Outcome::Survived => panic!("{what} SURVIVED the allowlist — it must not be reachable"),
        }
    }

    /// Assert a probe runs to completion, unless the environment cannot install
    /// a filter.
    fn assert_survives(what: &str, probe: impl FnOnce()) {
        match under_filter(probe) {
            Outcome::Survived => {}
            Outcome::Skipped => eprintln!("seccomp install unsupported here — skipping {what}"),
            Outcome::Killed => {
                panic!("{what} was KILLED — the allowlist is too tight to start a child")
            }
        }
    }

    /// No socket, of any family. Without one there is no `AF_VSOCK` to dial and
    /// no network to reach, which is the whole egress argument: the child talks
    /// over the socketpair it was handed and creates none of its own.
    #[test]
    fn creating_a_socket_is_fatal() {
        assert_killed("socket(AF_INET)", || {
            let _ = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        });
        assert_killed("socket(AF_VSOCK)", || {
            let _ = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        });
        assert_killed("socketpair", || {
            let mut sv = [0i32; 2];
            let _ =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        });
    }

    /// `io_uring` is the reason this filter is an allowlist. Its operations run
    /// in kernel worker context rather than through the syscall entry, so a
    /// denylist watching `openat` and `socket` never sees the opens, writes and
    /// connects submitted through a ring — it defeated every rule at once. Here
    /// the ring cannot be created in the first place.
    #[test]
    fn io_uring_is_fatal() {
        assert_killed("io_uring_setup", || {
            // Two args: entries, and a pointer to io_uring_params. A null
            // pointer would be EFAULT if it ever got that far; the filter acts
            // on the syscall number, before any argument is read.
            let params = [0u8; 120];
            let _ = unsafe { libc::syscall(libc::SYS_io_uring_setup, 8, params.as_ptr()) };
        });
    }

    /// The other route a denylist left open: a write-capable open that is not
    /// `openat`. `/dev` is mounted without `nodev`, so the serial port the host
    /// reads is a node with a name, and `name_to_handle_at` + `open_by_handle_at`
    /// reached it with the write-open rule none the wiser.
    #[test]
    fn opening_by_file_handle_is_fatal() {
        assert_killed("name_to_handle_at", || {
            let path = c"/dev/null";
            let handle = [0u8; 128];
            let mut mount_id = 0i32;
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_name_to_handle_at,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    handle.as_ptr(),
                    &mut mount_id as *mut i32,
                    0,
                )
            };
        });
        assert_killed("open_by_handle_at", || {
            let handle = [0u8; 128];
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_open_by_handle_at,
                    -1i32,
                    handle.as_ptr(),
                    libc::O_WRONLY,
                )
            };
        });
    }

    /// Changing the filesystem view is how a child would manufacture a target
    /// for anything else: mount somewhere writable, or `mknod` its own device
    /// node. The child is root in the single mount namespace, so nothing but
    /// this stops it.
    #[test]
    fn reshaping_the_filesystem_is_fatal() {
        assert_killed("mount", || {
            let src = c"none";
            let dst = c"/tmp";
            let fstype = c"tmpfs";
            let _ = unsafe {
                libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    fstype.as_ptr(),
                    0,
                    std::ptr::null(),
                )
            };
        });
        assert_killed("mknod", || {
            let path = c"/tmp/enclavid-seccomp-probe-node";
            let _ =
                unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) };
        });
    }

    /// Sibling isolation, in the filter rather than only in the kernel's Yama
    /// floor. A child that cannot make the call does not depend on
    /// `ptrace_scope` being right.
    #[test]
    fn reaching_into_another_process_is_fatal() {
        assert_killed("ptrace", || {
            let _ = unsafe { libc::ptrace(libc::PTRACE_ATTACH, 1, 0, 0) };
        });
        assert_killed("process_vm_readv", || {
            let _ = unsafe { libc::syscall(libc::SYS_process_vm_readv, 1, 0, 0, 0, 0, 0) };
        });
    }

    /// System V IPC outlives a process, and the children are the one thing in
    /// the fleet that must not: a shared segment would carry one round's
    /// plaintext into the next, inside the guest, where no disposal reaches it.
    #[test]
    fn shared_ipc_is_fatal() {
        assert_killed("shmget", || {
            let _ = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
        });
    }

    /// The half that keeps a child alive. Every one of these was measured in a
    /// real child on both libc targets, and a filter that killed them would fail
    /// at exec, in production, on the first round.
    #[test]
    fn what_a_child_actually_does_survives() {
        assert_survives("a read-only open, and reading it", || {
            let path = c"/proc/self/stat";
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
            if fd >= 0 {
                let mut buf = [0u8; 64];
                let _ = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                unsafe { libc::close(fd) };
            }
        });
        assert_survives("anonymous memory", || {
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p != libc::MAP_FAILED {
                unsafe { libc::munmap(p, 4096) };
            }
        });
    }

    /// An open for WRITING must be fatal, and an open for READING must not be —
    /// the same path both ways, so the access mode is the only variable.
    ///
    /// The read half is what keeps a child able to start at all: a runtime reads
    /// cgroup files on its way up, and the executor child mmaps its cwasm by
    /// path. The write half is the containment: `/dev` is devtmpfs and the
    /// serial device the host reads is a node with a name, so
    /// `open("/dev/ttyS0", O_WRONLY)` would reach the host with nothing
    /// inherited — no descriptor, no socket, no environment variable.
    #[test]
    fn opening_for_writing_is_fatal_and_for_reading_is_not() {
        assert_survives("open(/dev/null, O_RDONLY)", || {
            let path = c"/dev/null";
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        });
        assert_killed("open(/dev/null, O_WRONLY)", || {
            let path = c"/dev/null";
            let _ = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY) };
        });
        assert_killed("openat(/dev/null, O_RDWR)", || {
            let path = c"/dev/null";
            let _ = unsafe { libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDWR) };
        });
        // `openat2` puts its flags behind a pointer, which a filter may not
        // dereference — so it cannot be checked, and is not on the list at all.
        assert_killed("openat2", || {
            let path = c"/dev/null";
            let how = [0u64; 3]; // struct open_how { flags, mode, resolve }
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    how.as_ptr(),
                    24usize,
                )
            };
        });
    }

    /// `ioctl` for exactly one request. `/dev/sev-guest` is opened READ-only by
    /// the `sev` crate, so the open rules never reach it, and everything it does
    /// is an `ioctl` — an attestation report over `report_data` of the child's
    /// choosing, or the key session state is sealed under. Allowing only the
    /// request the child itself makes is what puts that out of reach.
    #[test]
    fn ioctl_is_fatal_except_the_one_the_child_makes() {
        assert_survives("ioctl(FIONBIO) on the inherited socket", || {
            // fd 0 in the test harness is not a socket, so this fails with
            // ENOTTY — which is fine: the assertion is that the filter let the
            // call through to the kernel at all.
            let mut on: libc::c_int = 1;
            let _ = unsafe { libc::ioctl(0, libc::FIONBIO, &mut on) };
        });
        assert_killed("ioctl(TCGETS)", || {
            let mut termios = [0u8; 64];
            let _ = unsafe { libc::ioctl(0, libc::TCGETS, termios.as_mut_ptr()) };
        });
    }
}
