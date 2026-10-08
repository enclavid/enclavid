//! What a supervisor requires of its guest before it runs a single child, and
//! the one measurement of the guest it sizes everything by.
//!
//! Every outcome here goes to the log device. On a guest stderr is `/dev/null`
//! and `install_panic` never forwards a payload, so a boot check that only
//! panicked would tell an operator the guest died and nothing about why.

/// Boot-time requirement that the kernel's Yama `ptrace_scope` keeps a
/// compromised child from reading a sibling child's memory (`ptrace`,
/// `process_vm_readv`, `/proc/<pid>/mem`, all gated by `PTRACE_MODE_ATTACH`).
/// The measured image sets it on its command line; this makes an image that
/// does not stop at boot instead of running without sibling isolation.
///
/// The floor is a compile-time constant, not a setting: the host provisions
/// the guest's settings, and a floor it could lower would check nothing.
///
/// It is 3, "no attach". `scope=1` lets a child `PR_SET_PTRACER_ANY` and invite
/// a cooperating sibling. `scope=2` admits any holder of `CAP_SYS_PTRACE`, which
/// a child spawned without an identity of its own has, PID 1 running as root.
/// (Every child a runner with [`Cgroups`](crate::Cgroups) spawns has an identity
/// of its own and no capability; the floor covers them too.) Only `scope=3`
/// denies everyone, and it cannot be lowered again without a reboot — in a
/// disposable measured guest a property rather than a cost.
///
/// It is the second control on that axis: the child's syscall allowlist has no
/// `ptrace`, `process_vm_readv` or `pidfd_getfd`. The floor still covers a child
/// spawned without the filter, and it is the kernel's rather than this process
/// getting its own filter right. Nothing in this workspace calls `ptrace`, so it
/// costs the guest nothing.
///
/// Enforced only under `guest-hardening`, the feature a measured image builds
/// with: `scope=3` cannot be undone without a reboot, which is not something a
/// developer's machine can be asked for. No-op off Linux.
///
/// The value is safe to disclose: it is `sysctl.kernel.yama.ptrace_scope` off
/// the measured command line, a number the host set.
#[cfg(all(target_os = "linux", feature = "guest-hardening"))]
pub fn require_ptrace_scope() {
    use safe_logger::{error_and_panic, info, reason, safe};

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
            error_and_panic!(
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
        }
        None => {
            error_and_panic!(
                "engine-supervisor: cannot read the yama ptrace_scope — the LSM is not enabled, \
                 so ptrace is unrestricted and cross-sibling child memory reads are possible. \
                 Stopping.",
                reason!("a constant, emitted once at boot before any session exists"),
            );
        }
    }
}

/// No-op: either this is not Linux, or this build did not ask for the floor —
/// see the guest build's `require_ptrace_scope`.
#[cfg(not(all(target_os = "linux", feature = "guest-hardening")))]
pub fn require_ptrace_scope() {}

/// Boot-time requirement that this process can open the `needed` descriptors
/// its own bounds are written against, raising the soft limit to get there.
///
/// How many children may run at once and how many cached artifacts may be held
/// open are counts of descriptors. A worker whose table cannot back them fails
/// `accept`, `socketpair` and `memfd_create` at its own configured peak — every
/// request at once, the blast radius the per-request child exists to bound — so
/// it does not boot.
///
/// Enforced in every build, unlike [`require_ptrace_scope`]: a descriptor limit
/// is the process's own to raise, and a developer's machine is where a short one
/// shows up first — macOS ships a soft limit of 256.
///
/// Only the soft limit moves, and only as far as `needed`: the hard limit is
/// the administrator's ceiling, and macOS refuses a soft limit of "unlimited"
/// even under an unlimited hard one.
///
/// Both numbers are safe to disclose: the limit is the one the host
/// provisioned, and `needed` is this build's constants plus a term derived from
/// the host's own child bound.
pub fn require_fd_budget(needed: u64) {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    use safe_logger::{error_and_panic, info, reason, safe};

    // `None` is no limit at all.
    let limit = getrlimit(Resource::Nofile);
    let soft = limit.current.unwrap_or(u64::MAX);
    let want = limit.maximum.map_or(needed, |hard| needed.min(hard));
    let raised = Rlimit {
        current: Some(want),
        maximum: limit.maximum,
    };
    let available = if want > soft && setrlimit(Resource::Nofile, raised).is_ok() {
        want
    } else {
        soft
    };

    if available < needed {
        error_and_panic!(
            "engine-supervisor: {} file descriptors available, {} needed for this build's \
             cache and child bounds — the worker would fail to accept connections and spawn \
             children at its own configured peak. Raise the host's RLIMIT_NOFILE hard limit. \
             Stopping.",
            safe(&available, reason!("a limit the host itself provisioned")),
            safe(
                &needed,
                reason!(
                    "this build's constants plus a term derived from the child bound \
                     the host itself set"
                )
            ),
            reason!("a constant, emitted once at boot before any request exists"),
        );
    }
    info!(
        "engine-supervisor: {} file descriptors available (>= required {})",
        safe(&available, reason!("a limit the host itself provisioned")),
        safe(&needed, reason!("a constant of the measured build")),
        reason!("a constant, emitted once at boot before any request exists"),
    );
}

/// The memory this machine reports, in bytes: on Linux what `/proc/meminfo` calls
/// `MemTotal` — what the kernel manages once its own reservations are taken, not
/// the size the guest was launched with. A supervisor sizes what it admits
/// against it, so failing to read it stops the boot.
///
/// The machine's, not a control group's: a process run under a memory limit
/// below it is sized as if it had the whole machine.
pub fn physical_memory() -> u64 {
    use safe_logger::{debug, error_and_panic, reason};

    let bytes = machine_memory();
    if bytes == 0 {
        debug!("the machine reported no memory");
        error_and_panic!(
            "engine-supervisor: cannot read this machine's physical memory, so what a \
             supervisor admits cannot be sized against it. Stopping.",
            reason!("a constant, emitted once at boot before any request exists"),
        );
    }
    bytes
}

/// `sysinfo`'s total RAM, which is what `/proc/meminfo` reports as `MemTotal`.
#[cfg(target_os = "linux")]
// `totalram` is a C `unsigned long`: already `u64` here, narrower on a 32-bit
// target.
#[allow(clippy::useless_conversion)]
fn machine_memory() -> u64 {
    let info = rustix::system::sysinfo();
    u64::from(info.totalram).saturating_mul(u64::from(info.mem_unit))
}

/// A developer's machine: no `sysinfo`, so the POSIX page count.
#[cfg(not(target_os = "linux"))]
fn machine_memory() -> u64 {
    // SAFETY: `sysconf` takes a constant name and returns a number; nothing is
    // passed by pointer.
    let (pages, page) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    match (u64::try_from(pages), u64::try_from(page)) {
        (Ok(pages), Ok(page)) => pages.saturating_mul(page),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::physical_memory;

    /// What admissions are sized against reads as a real size here too — at least
    /// a page, and a whole number of them.
    #[test]
    fn this_machine_reports_its_memory() {
        let bytes = physical_memory();
        assert!(
            bytes >= 4096 && bytes.is_multiple_of(4096),
            "read {bytes} bytes"
        );
    }
}
