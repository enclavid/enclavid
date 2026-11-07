// The SHAPE of the filter the coprocess narrows itself with: what it lets past
// and what ends the process, one raw call at a time. That a decode survives it
// is the integration tests'.

use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use libc::c_long;

use super::{filter, narrow_to};

/// How a probe ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The filter killed it.
    Killed,
    /// It faulted: the time-stamp counter is not its to read.
    Faulted,
    /// It made its call and exited.
    Survived,
}

use Outcome::{Faulted, Killed, Survived};

/// What a probe does once narrowed.
#[derive(Clone, Copy)]
enum Probe {
    /// One system call, made raw, with exactly the arguments a row names.
    Call(c_long, [c_long; 6]),
    /// A read of the time-stamp counter.
    Counter,
}

/// A [`Probe::Call`] from its number and up to six arguments.
macro_rules! call {
    ($nr:expr $(, $arg:expr)* $(,)?) => {{
        let given: &[c_long] = &[$($arg as c_long),*];
        let mut args = [0; 6];
        args[..given.len()].copy_from_slice(given);
        Probe::Call($nr, args)
    }};
}

/// Exit codes a probe uses, so a failure names itself.
const SURVIVED: i32 = 42;
const UNSUPPORTED: i32 = 7;

/// Make `probe` in a forked child narrowed as the coprocess narrows itself,
/// its socket `socket`, and say how the child ended — `None` where this
/// environment cannot install a filter at all.
fn narrowed(socket: RawFd, probe: Probe) -> Option<Outcome> {
    // Built here, so the child only reads it.
    let filter = filter(socket).expect("build the filter");
    // SAFETY: the child of this multi-threaded harness makes only
    // async-signal-safe calls — `signal`, `prctl` and `seccomp`, the probe,
    // `_exit` — and never returns into the harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        // A fault ends it as a fault, not through the harness's handler,
        // whose own calls the filter would answer first.
        // SAFETY: see the fork.
        unsafe { libc::signal(libc::SIGSEGV, libc::SIG_DFL) };
        if narrow_to(&filter).is_err() {
            // SAFETY: see the fork.
            unsafe { libc::_exit(UNSUPPORTED) }
        }
        match probe {
            Probe::Call(nr, [a, b, c, d, e, f]) => {
                // SAFETY: see the fork. What the arguments point at was built
                // before it, and the child's copy is its own.
                unsafe { libc::syscall(nr, a, b, c, d, e, f) };
            }
            Probe::Counter => {
                // SAFETY: reads the counter, or faults.
                std::hint::black_box(unsafe { core::arch::x86_64::_rdtsc() });
            }
        }
        // SAFETY: see the fork.
        unsafe { libc::_exit(SURVIVED) }
    }

    let mut status = 0;
    // SAFETY: waits for the child just forked, into a local.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "wait for the probe");
    if libc::WIFSIGNALED(status) {
        return Some(match libc::WTERMSIG(status) {
            libc::SIGSYS => Killed,
            libc::SIGSEGV => Faulted,
            signal => panic!("the probe died of signal {signal}, which is neither"),
        });
    }
    match libc::WEXITSTATUS(status) {
        SURVIVED => Some(Survived),
        UNSUPPORTED => None,
        other => panic!("the probe ended unexpectedly: {other}"),
    }
}

/// Every row, made in a child of its own, ends as listed: read and write on
/// the socket alone, memory as the allocator asks for it, and an exit — and no
/// time-stamp counter.
#[test]
fn each_call_ends_as_listed() {
    // What the calls point at, built before any child exists. The other end
    // stays open, so a write to the socket is taken.
    let (socket, _other) = UnixStream::pair().expect("a socket pair");
    let fd = socket.as_raw_fd();
    let mut byte = 0u8;
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let null = c"/dev/null".as_ptr();
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    let private = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

    let rows = [
        // Its socket, and no other descriptor; nothing opened.
        (
            "read(socket)",
            call!(libc::SYS_read, fd, &raw mut byte, 0),
            Survived,
        ),
        (
            "write(socket)",
            call!(libc::SYS_write, fd, &raw mut byte, 1),
            Survived,
        ),
        (
            "read(0)",
            call!(libc::SYS_read, 0, &raw mut byte, 0),
            Killed,
        ),
        (
            "write(2)",
            call!(libc::SYS_write, 2, &raw mut byte, 1),
            Killed,
        ),
        (
            "openat(O_RDONLY)",
            call!(libc::SYS_openat, libc::AT_FDCWD, null, libc::O_RDONLY),
            Killed,
        ),
        // Memory as the allocator asks for it, and in no other way.
        (
            "mmap(read-write, private anonymous)",
            call!(libc::SYS_mmap, 0, 4096, rw, private, -1, 0),
            Survived,
        ),
        (
            "mmap(executable)",
            call!(
                libc::SYS_mmap,
                0,
                4096,
                rw | libc::PROT_EXEC,
                private,
                -1,
                0
            ),
            Killed,
        ),
        (
            "mmap(read-only)",
            call!(libc::SYS_mmap, 0, 4096, libc::PROT_READ, private, -1, 0),
            Killed,
        ),
        (
            "mmap(shared)",
            call!(
                libc::SYS_mmap,
                0,
                4096,
                rw,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0
            ),
            Killed,
        ),
        (
            "mmap(fixed)",
            call!(
                libc::SYS_mmap,
                0,
                4096,
                rw,
                private | libc::MAP_FIXED,
                -1,
                0
            ),
            Killed,
        ),
        (
            "mmap(the socket)",
            call!(libc::SYS_mmap, 0, 4096, rw, libc::MAP_PRIVATE, fd, 0),
            Killed,
        ),
        (
            "mremap(MAYMOVE)",
            call!(libc::SYS_mremap, 0, 0, 4096, libc::MREMAP_MAYMOVE, 0),
            Survived,
        ),
        (
            "mremap(MAYMOVE | FIXED)",
            call!(
                libc::SYS_mremap,
                0,
                0,
                4096,
                libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
                0
            ),
            Killed,
        ),
        ("munmap", call!(libc::SYS_munmap, 0, 0), Survived),
        ("brk", call!(libc::SYS_brk, 0), Survived),
        (
            "madvise(DONTNEED)",
            call!(libc::SYS_madvise, 0, 0, libc::MADV_DONTNEED),
            Killed,
        ),
        (
            "mprotect(read)",
            call!(libc::SYS_mprotect, 0, 0, libc::PROT_READ),
            Killed,
        ),
        // No process, no clock, no counter given back, no other filter.
        (
            "fork",
            call!(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0),
            Killed,
        ),
        (
            "clock_gettime",
            call!(
                libc::SYS_clock_gettime,
                libc::CLOCK_MONOTONIC,
                &raw mut time
            ),
            Killed,
        ),
        (
            "prctl(PR_SET_TSC, PR_TSC_ENABLE)",
            call!(libc::SYS_prctl, libc::PR_SET_TSC, libc::PR_TSC_ENABLE),
            Killed,
        ),
        (
            "seccomp(SET_MODE_FILTER, TSYNC)",
            call!(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                0
            ),
            Killed,
        ),
        ("the time-stamp counter", Probe::Counter, Faulted),
    ];

    let mut wrong = Vec::new();
    for (what, probe, expected) in rows {
        match narrowed(fd, probe) {
            None => {
                eprintln!("this environment cannot install a seccomp filter — skipping");
                return;
            }
            Some(ended) if ended != expected => {
                wrong.push(format!("{what}: {ended:?}, listed {expected:?}"));
            }
            Some(_) => {}
        }
    }
    assert!(
        wrong.is_empty(),
        "the filter does not end these calls as listed:\n{}",
        wrong.join("\n")
    );
}
