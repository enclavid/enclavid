//! The syscall filters of the processes a runner starts, so that one an escape
//! turns into native code cannot get the round's plaintext to the host: an
//! ALLOWLIST each, and in front of it one call refused with an error rather
//! than a kill.
//!
//! Every child a [`ChildRunner`](crate::ChildRunner) spawns runs under the
//! child's; [`spawn_and_connect`](crate::spawn_and_connect) applies them when
//! asked to. Both workers' children need them: the execution-worker's run
//! untrusted wasm, the compile-worker's run Cranelift over untrusted input.
//! The coprocess a child may have beside it runs under narrower ones, its own
//! list: see [`COPROCESS_ALLOWED`].

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::spawn::Filters;

/// The architecture the filters are built for. The guest is x86_64; an aarch64
/// port would have to revisit the lists against its own libc.
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the child's syscall filters are written for x86_64 and aarch64 only");

/// A process's filters, in the order they are installed: [`no_clone3`], then
/// [`allowlist`] — a child's, or a coprocess's.
///
/// Built once each, in the parent, so `pre_exec` only hands static programs to
/// `seccompiler::apply_filter`. Installed while the forked process has one
/// thread, so every thread it starts after `exec` inherits them without
/// `SECCOMP_FILTER_FLAG_TSYNC`.
pub(crate) fn filters(of: Filters) -> &'static [BpfProgram; 2] {
    static CHILD: OnceLock<[BpfProgram; 2]> = OnceLock::new();
    static COPROCESS: OnceLock<[BpfProgram; 2]> = OnceLock::new();
    let built = match of {
        Filters::Child => &CHILD,
        Filters::Coprocess => &COPROCESS,
    };
    built.get_or_init(|| [no_clone3(), allowlist(of)])
}

/// `clone3` answered "not implemented" rather than run. Its flags sit behind a
/// pointer a filter cannot read, so whatever it let through would include a
/// fork, and `CLONE_INTO_CGROUP`, which starts the new process in a group of
/// the caller's choosing. glibc, told it is missing, makes its threads with
/// `clone`, whose flags [`allowlist`] does read.
///
/// A filter of its own because the allowlist has one answer for everything it
/// refuses, and that answer is a kill — which would end a glibc child at its
/// first thread, before it could fall back. Of two filters the kernel takes the
/// stricter answer for each call, so `clone3`, which the allowlist lets through,
/// gets this one's. Installed first: the allowlist has no `seccomp`, so nothing
/// can be installed after it.
fn no_clone3() -> BpfProgram {
    let rules = BTreeMap::from([(libc::SYS_clone3, Vec::new())]);
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS.cast_unsigned()),
        ARCH,
    )
    .expect("build the clone3 filter")
    .try_into()
    .expect("compile the clone3 filter to BPF")
}

/// The allowlist: everything a child is known to need is permitted, and
/// anything else kills the process.
///
/// # Why an allowlist
///
/// A denylist has to name every way of doing a thing, and Linux has more than
/// one. `io_uring` runs opens, writes and socket calls as ring entries kernel
/// workers execute, so a filter watching `openat` and `socket` sees none of
/// them. `open_by_handle_at` is a write-capable open that is not `openat`: with
/// `/dev` mounted without `nodev`, it reaches the serial port the host reads.
/// An allowlist fails the other way — a syscall nobody thought of costs a dead
/// round, not a silent channel to the host.
///
/// # Where the list comes from
///
/// Measured: both children traced through spawn, prime or compile, one round
/// and exit, against glibc. The guest links it statically and the tests
/// dynamically; a static link only drops the loader's own calls.
///
/// Entries marked `reasoned` cover paths the trace did not reach. The one that
/// matters most is `rt_sigreturn`: wasmtime turns a wasm trap into a Rust error
/// through a SIGSEGV handler, and a trap — fuel exhaustion, an out-of-bounds
/// access, `unreachable` — is an ordinary outcome of a round.
///
/// # What this leaves the child
///
/// Its inherited socketpair on fd 0, its write-sealed cwasm fd, anonymous memory,
/// threads, read-only files, and its own resource limits to read. It cannot
/// create a socket, a process or a file, open anything for writing, change a
/// resource limit, submit an io_uring, mount a filesystem, make a device node,
/// `ptrace`, load BPF, or use System V IPC — so it cannot reach the host, and it
/// cannot leave anything behind for the next round: no process outlives it, no
/// file or segment it made remains, and no core of it is written, its core limit
/// being 0 and its own to read only.
///
/// A coprocess is left less: its socket on fd 0, which it blocks on, the
/// descriptors it was handed, read-only files, anonymous memory and threads,
/// and a filter of its own to narrow itself with. No `ioctl` at all, no event
/// loop, and no call that sends or takes a descriptor over its socket — see
/// [`COPROCESS_ALLOWED`].
///
/// `execve` is allowed and cannot be otherwise: the filter is installed before the
/// exec that starts the process, so denying it would stop it from starting. It
/// buys an escape nothing — a seccomp filter survives `exec`, and
/// `no_new_privs` stops it being dropped, so whatever it execs runs in this same
/// jail.
fn allowlist(of: Filters) -> BpfProgram {
    // Empty rule list on a syscall = match it unconditionally → `match_action`,
    // which is Allow here. A syscall absent from the map falls to the mismatch
    // action, which kills. Keyed by `c_long`, which is `i64` on both
    // architectures `ARCH` admits.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let allowed = match of {
        Filters::Child => ALLOWED,
        Filters::Coprocess => COPROCESS_ALLOWED,
    };
    for sys in allowed {
        rules.insert(*sys, Vec::new());
    }
    #[cfg(target_arch = "x86_64")]
    let allowed_x86_64 = match of {
        Filters::Child => ALLOWED_X86_64,
        Filters::Coprocess => COPROCESS_ALLOWED_X86_64,
    };
    #[cfg(target_arch = "x86_64")]
    for sys in allowed_x86_64 {
        rules.insert(*sys, Vec::new());
    }

    // `openat` carries flags in a register, so the mode is visible.
    rules.insert(libc::SYS_openat, read_only_open(2));

    // Threads, never processes. The compile child offloads Cranelift to a
    // blocking pool and the executor child decodes large items on one, and a
    // thread inside a process an escape already owns adds nothing. A process
    // does: a second set of tasks and PIDs, outside what the runner kills by
    // pid. A `clone` without `CLONE_THREAD` is a fork; with it, the kernel
    // insists on a shared address space and signal handlers too. Legacy
    // `clone` reads only the low 32 bits of its flags, where `CLONE_THREAD` is.
    rules.insert(
        libc::SYS_clone,
        vec![
            SeccompRule::new(vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(libc::CLONE_THREAD as u64),
                    libc::CLONE_THREAD as u64,
                )
                .expect("build clone-flags condition"),
            ])
            .expect("build clone rule"),
        ],
    );
    // Let through here so that [`no_clone3`]'s answer is the one it gets: a
    // kill from this filter would outrank it.
    rules.insert(libc::SYS_clone3, Vec::new());

    // `prlimit64` to read this process's own limits and nothing more: glibc's
    // `getrlimit` is `prlimit64(0, resource, NULL, old)`, and nothing a runner
    // starts sets a limit after exec. Setting one would let a child
    // raise what its spawn lowered — its core limit, its task cap — and naming
    // another pid would reach the supervisor's.
    rules.insert(
        libc::SYS_prlimit64,
        vec![
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0)
                    .expect("build prlimit-pid condition"),
                SeccompCondition::new(2, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                    .expect("build prlimit-new-limit condition"),
            ])
            .expect("build prlimit rule"),
        ],
    );

    // A child's `ioctl` for exactly one request: `adopt_fd0` setting the
    // inherited socketpair non-blocking, the only ioctl either child makes. A
    // coprocess blocks on its socket and makes none, so it has no `ioctl` at
    // all.
    //
    // That is what keeps `/dev/sev-guest` out of reach. It is driven purely by
    // ioctl, and through it a child could ask for an attestation report over
    // `report_data` of its choosing — a bearer proof of "I am the measured
    // image" — or for the derived key session state is sealed under.
    // Attestation and key derivation happen in the worker; the child receives
    // its plaintext already opened. Naming the allowed request rather than the
    // SNP ones also survives a kernel struct growing, which changes the `_IOWR`
    // numbers a denylist would have to name.
    //
    // `FIONBIO` is a `c_ulong` on glibc and a `c_int` on musl.
    // A coprocess may narrow itself further once it is ready — a filter of its
    // own on top of this one, which can only refuse more — and do nothing else
    // with either call: `no_new_privs`, which it already has, and a filter
    // installed with no flags. A flag could open a listener another process
    // answers its calls through, or let speculation past what the kernel
    // guards it with.
    if let Filters::Coprocess = of {
        rules.insert(
            libc::SYS_prctl,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        libc::PR_SET_NO_NEW_PRIVS as u64,
                    )
                    .expect("build prctl-option condition"),
                ])
                .expect("build prctl rule"),
            ],
        );
        rules.insert(
            libc::SYS_seccomp,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        u64::from(libc::SECCOMP_SET_MODE_FILTER),
                    )
                    .expect("build seccomp-operation condition"),
                    SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0)
                        .expect("build seccomp-flags condition"),
                ])
                .expect("build seccomp rule"),
            ],
        );
    }

    if let Filters::Child = of {
        #[allow(clippy::unnecessary_cast)]
        let fionbio = libc::FIONBIO as u64;
        rules.insert(
            libc::SYS_ioctl,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, fionbio)
                        .expect("build ioctl-request condition"),
                ])
                .expect("build ioctl rule"),
            ],
        );
    }

    SeccompFilter::new(
        rules,
        // Not listed: KILL THE PROCESS. Loud and fail-closed — an `Errno` would
        // hand the child a failure its own code might paper over, and a control
        // that can be papered over is not one. The supervisor sees the death as
        // a dropped connection and fails the request safely; `SIGSYS` in the
        // exit status is what names the cause.
        SeccompAction::KillProcess,
        SeccompAction::Allow, // listed (and any condition met): allowed
        ARCH,
    )
    .expect("build the allowlist")
    .try_into()
    .expect("compile the allowlist to BPF")
}

/// Everything the two children were measured making, plus what a path the
/// trace did not reach must have. Allowed unconditionally; those with
/// arguments worth inspecting are added separately in [`allowlist`].
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
    // `prlimit64` carries a condition: in `allowlist`.
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
    // No memfd_create or ftruncate. wasmtime builds a module's copy-on-write
    // memory image from the file the module was mapped from, and makes a
    // memfd only for a module deserialized from bytes; the executor child
    // maps its cwasm from the fd it inherited, and the compile child never
    // instantiates. A memfd would also be memory charged to the child that
    // nothing in its address space shows.
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
    // ── Threads: `clone` carries a condition, in `allowlist`; `clone3` is
    //    refused by `no_clone3` ───────────────────────────────────────────
    // ── Files, and only for reading. `openat` carries a condition; the
    //    old `open` is not listed ─────────────────────────────────────────
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
    // is not `openat` (see `allowlist`).
    // NOT creat: it is a write-open by definition.
    // ── Signals: wasmtime's trap handler (see `allowlist`) ─────────────
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn, // reasoned
    libc::SYS_sigaltstack,
    libc::SYS_tgkill,          // reasoned: abort() raises SIGABRT at itself
    libc::SYS_restart_syscall, // reasoned: kernel-injected on interruption
];

/// Entry points aarch64 does not have at all, so naming them unconditionally
/// would not compile there.
///
/// The guest is x86_64 — SEV-SNP — and an aarch64 port would have to revisit
/// this whole list against that libc rather than just this block.
#[cfg(target_arch = "x86_64")]
const ALLOWED_X86_64: &[libc::c_long] = &[
    libc::SYS_access,
    libc::SYS_poll,
    libc::SYS_epoll_wait,
    libc::SYS_readlink,     // reasoned: the backtrace path
    libc::SYS_gettimeofday, // reasoned: see the time group in `ALLOWED`
];

/// Everything a coprocess was measured making, plus what a path the trace did
/// not reach must have.
///
/// A coprocess is a statically linked program that blocks on the socket it was
/// given and computes over the descriptors it was handed. Measured: ONNX
/// Runtime linked into one, traced through its start, a session over a graph
/// and runs of it. Narrower than [`ALLOWED`] by what blocking on one socket
/// does without: no event loop (`epoll`, `eventfd`), no `ioctl` (see
/// [`allowlist`]), and no message calls. That last is what keeps descriptors
/// off its socket: it has no call that sends one, and one sent to it is
/// discarded unread with the bytes `read` takes.
const COPROCESS_ALLOWED: &[libc::c_long] = &[
    // ── Starting up, and stopping ──────────────────────────────────────
    libc::SYS_execve, // installed pre-exec, so this one starts the coprocess
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_arch_prctl,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list, // glibc
    libc::SYS_rseq,            // glibc
    // `prlimit64` carries a condition: in `allowlist`.
    libc::SYS_readlinkat, // a static glibc reads `/proc/self/exe` as it starts
    libc::SYS_sched_getaffinity, // ONNX Runtime's static initializers count the CPUs
    libc::SYS_ppoll,      // the start's check of fds 0–2, where there is no `poll`
    libc::SYS_getrandom,
    libc::SYS_getpid, // reasoned: the abort path
    libc::SYS_gettid,
    // ── Memory ─────────────────────────────────────────────────────────
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_mremap, // reasoned: a large block reallocated
    libc::SYS_brk,
    libc::SYS_madvise, // reasoned: allocator release
    // ── Its socket, blocking, and the descriptors it was handed ────────
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_close,
    libc::SYS_fcntl, // reasoned: a handed descriptor checked open before it is taken
    // ── Files, and only for reading. `openat` carries a condition ──────
    libc::SYS_fstat,
    libc::SYS_newfstatat, // glibc
    libc::SYS_statx,      // glibc
    libc::SYS_lseek,
    libc::SYS_pread64, // reasoned: a handed file read at an offset
    // ── Waiting. Threads: `clone` carries a condition, in `allowlist`;
    //    `clone3` is refused by `no_clone3` ───────────────────────────────
    libc::SYS_futex,
    libc::SYS_sched_yield,     // reasoned: futex/spin fallbacks
    libc::SYS_clock_nanosleep, // reasoned: thread parking
    libc::SYS_nanosleep,       // reasoned: the same, older entry point
    // ── Time, where the clocksource is not the vDSO's: see `ALLOWED` ───
    libc::SYS_clock_gettime, // reasoned
    libc::SYS_clock_getres,  // reasoned
    // ── Signals ────────────────────────────────────────────────────────
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask, // reasoned: a thread's start and abort() mask signals
    libc::SYS_rt_sigreturn,   // reasoned
    libc::SYS_sigaltstack,
    libc::SYS_tgkill,          // reasoned: abort() raises SIGABRT at itself
    libc::SYS_restart_syscall, // reasoned: kernel-injected on interruption
];

/// The coprocess's entry points aarch64 does not have — see [`ALLOWED_X86_64`].
#[cfg(target_arch = "x86_64")]
const COPROCESS_ALLOWED_X86_64: &[libc::c_long] = &[
    libc::SYS_poll,         // the start's check that fds 0–2 are open
    libc::SYS_access,       // reasoned: the loader of a dynamically linked build
    libc::SYS_gettimeofday, // reasoned: see the time group in `COPROCESS_ALLOWED`
];

/// Match an open whose access mode is `O_RDONLY` and that neither creates
/// nor truncates, and only that.
///
/// The child reads cgroup files for `available_parallelism`, `/proc/self` for
/// a backtrace, and the cwasm it was handed; a coprocess reads `/proc/cpuinfo`
/// and `/sys/devices/system/cpu/` for its CPUs, `/proc/self/maps` for its
/// stack, and the files it was handed. Neither writes a file. A writable
/// descriptor is what exfiltration needs: the serial port the host reads is a
/// node with a name.
///
/// The access mode alone is not the whole verb. `O_RDONLY | O_CREAT` makes a
/// file in `/tmp` or `/run`, which outlives the child and stays charged to its
/// memory group; `O_TRUNC` empties a file through a descriptor opened for
/// reading.
///
/// The path is behind a pointer, which a filter may not read; the flags are
/// not, and the verb is what matters. `Dword` because the kernel truncates
/// `flags` to `int` before reading it, so nothing hides in the high half.
/// `O_LARGEFILE` and `O_CLOEXEC`, which a libc may add, are outside the mask.
fn read_only_open(flags_arg: u8) -> Vec<SeccompRule> {
    let read_only = SeccompCondition::new(
        flags_arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq((libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC) as u64),
        libc::O_RDONLY as u64,
    )
    .expect("build open-flags condition");
    vec![SeccompRule::new(vec![read_only]).expect("build read-open rule")]
}
