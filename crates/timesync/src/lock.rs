//! The keeper locking itself, once it has opened everything it will use and
//! before it reads anything from the network.
//!
//! What it parses from there — TLS from the key exchange, time packets — came
//! through the host. A flaw in that parsing should get whoever exploits it the
//! keeper's one power, the clock, and nothing past it: no other capability, no
//! file it did not already hold, no socket but vsock, no process.
//!
//! Only in the measured build. A developer's box runs the keeper over TCP and
//! with its own idea of what it may do.

#[cfg(all(target_os = "linux", feature = "vsock"))]
mod measured {
    use std::collections::BTreeMap;

    use caps::{CapSet, Capability, CapsHashSet};
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    /// Everything the keeper calls once locked, and nothing else; anything
    /// else kills it, and its ending ends the guest. Measured by tracing the
    /// keeper from its lock through key exchanges, time packets and steps.
    const ALLOWED: &[libc::c_long] = &[
        // ── Memory ─────────────────────────────────────────────────────────
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_brk,
        libc::SYS_madvise,
        // ── Its descriptors: vsock streams, the log device, the clocksource
        libc::SYS_read,
        libc::SYS_readv,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_pread64,
        libc::SYS_close,
        libc::SYS_fcntl,
        // `socket`, `setsockopt` and `ioctl` carry conditions, in `allowlist`.
        libc::SYS_connect,
        libc::SYS_getsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
        // ── Waiting ────────────────────────────────────────────────────────
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        // ── Time: reading it, and steering it ─────────────────────────────
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_clock_adjtime,
        libc::SYS_adjtimex,
        // ── The rest of being a process ──────────────────────────────────
        libc::SYS_getrandom,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_tgkill,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];

    /// What the keeper is told does not exist, rather than killed for asking.
    ///
    /// It opens no file once locked. The TLS verifier does look, at the first
    /// key exchange, for the system's certificate store — a guest has none,
    /// and the roots are compiled in — and on being told there is nothing
    /// there it goes on with the roots it was given. So the lookups, and any
    /// open, get ENOENT: nothing can be opened, and nothing dies of looking.
    const UNSEEN: &[libc::c_long] = &[
        libc::SYS_openat,
        libc::SYS_open,
        libc::SYS_statx,
        libc::SYS_newfstatat,
        libc::SYS_stat,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
    ];

    fn arg_is(arg: u8, value: u64) -> Vec<SeccompRule> {
        vec![
            SeccompRule::new(vec![
                SeccompCondition::new(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
                    .expect("build an argument condition"),
            ])
            .expect("build a rule"),
        ]
    }

    /// [`UNSEEN`], answered ENOENT; everything else let through to the
    /// allowlist. A filter of its own because the allowlist has one answer for
    /// everything it refuses, and that answer is a kill. Of two filters the
    /// kernel takes the stricter answer for each call, so these, which the
    /// allowlist lets through, get this one's.
    fn unseen() -> BpfProgram {
        let rules = UNSEEN.iter().map(|sys| (*sys, Vec::new())).collect();
        SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::ENOENT.cast_unsigned()),
            TargetArch::x86_64,
        )
        .and_then(BpfProgram::try_from)
        .expect("the keeper's lookup filter compiles")
    }

    fn allowlist() -> BpfProgram {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = ALLOWED
            .iter()
            .chain(UNSEEN)
            .map(|sys| (*sys, Vec::new()))
            .collect();
        // vsock and nothing else: the key exchange and the time packets both
        // cross it, and a socket of any other family is a way out it has no
        // use for. The guest has no IP stack, so this costs nothing there;
        // it says what the keeper is, not what the kernel lacks.
        rules.insert(libc::SYS_socket, arg_is(0, libc::AF_VSOCK as u64));
        // Its vsock buffer, and no other socket option.
        rules.insert(libc::SYS_setsockopt, arg_is(1, libc::AF_VSOCK as u64));
        // One request: a stream made non-blocking. That keeps every device
        // driven by ioctl out of reach — `/dev/sev-guest` above all, through
        // which a report over data of its choosing would prove "I am this
        // measured image" to anyone.
        rules.insert(libc::SYS_ioctl, arg_is(1, libc::FIONBIO as u64));
        SeccompFilter::new(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .and_then(BpfProgram::try_from)
        .expect("the keeper's filter compiles")
    }

    /// Keep CAP_SYS_TIME and nothing else, then install the filters. Whatever
    /// goes wrong, the keeper does not go on unlocked.
    pub fn lock() -> Result<(), &'static str> {
        let keep: CapsHashSet = [Capability::CAP_SYS_TIME].into_iter().collect();
        for cap in caps::all() {
            if cap != Capability::CAP_SYS_TIME {
                caps::drop(None, CapSet::Bounding, cap)
                    .map_err(|_| "could not drop a capability from its bounding set")?;
            }
        }
        caps::clear(None, CapSet::Inheritable)
            .map_err(|_| "could not clear its inheritable set")?;
        caps::set(None, CapSet::Effective, &keep)
            .map_err(|_| "could not narrow its effective set")?;
        caps::set(None, CapSet::Permitted, &keep)
            .map_err(|_| "could not narrow its permitted set")?;
        // `apply_filter` sets `no_new_privs` first, which loading a filter
        // without CAP_SYS_ADMIN requires — and which it no longer has. The
        // lookup filter goes first: the allowlist has no `seccomp`, so nothing
        // can be installed after it.
        seccompiler::apply_filter(&unseen()).map_err(|_| "could not install its lookup filter")?;
        seccompiler::apply_filter(&allowlist()).map_err(|_| "could not install its syscall filter")
    }
}

#[cfg(all(target_os = "linux", feature = "vsock"))]
pub use measured::lock;

#[cfg(not(all(target_os = "linux", feature = "vsock")))]
pub fn lock() -> Result<(), &'static str> {
    Ok(())
}
