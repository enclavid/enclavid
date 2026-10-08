// The SHAPE of the child's syscall filters: what they kill, refuse and let
// past, one raw system call at a time. That a real child survives them is the
// child packages' integration tests, which drive a full round through the
// image's own build under them. Both halves are needed: filters that permit
// everything pass those, and filters that permit nothing pass these.

use libc::c_long;
use rustix::process::{Pid, WaitOptions, waitpid};

use super::filters;

/// How a probe ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The filters killed it: the call is not on the list.
    Killed,
    /// The call came back "not implemented", and the probe went on.
    Refused,
    /// It made the call and exited: the call is allowed.
    Survived,
}

use Outcome::{Killed, Refused, Survived};

/// One system call, made raw: the number and arguments are exactly the ones a
/// row names, where a libc wrapper may make another call (glibc's `open` is
/// `openat`).
#[derive(Clone, Copy)]
struct Call {
    nr: c_long,
    args: [c_long; 6],
}

/// A [`Call`] from its number and up to six arguments, each as its register
/// holds it.
macro_rules! call {
    ($nr:expr $(, $arg:expr)* $(,)?) => {{
        let given: &[c_long] = &[$($arg as c_long),*];
        let mut args = [0; 6];
        args[..given.len()].copy_from_slice(given);
        Call { nr: $nr, args }
    }};
}

/// Exit codes a probe uses, so a failure names itself.
const SURVIVED: i32 = 42;
const REFUSED: i32 = 38;
const UNSUPPORTED: i32 = 7;

/// Make `call` in a forked child under the real filters, installed the way a
/// spawned child gets them, and say how the child ended — `None` where this
/// environment cannot install a filter at all.
fn under_filter(call: Call) -> Option<Outcome> {
    // Built here, so the child only reads them.
    let filters = filters();
    // SAFETY: the child of this multi-threaded harness makes only
    // async-signal-safe calls — `apply_filter`'s `prctl` and `seccomp`, the call
    // under test, `_exit` — and never returns into the harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let installed = filters
            .iter()
            .try_for_each(|filter| seccompiler::apply_filter(filter));
        let code = match installed {
            Ok(()) => {
                let [a, b, c, d, e, f] = call.args;
                // SAFETY: see the fork. What the arguments point at was built
                // before it, and the child's copy is its own.
                let made = unsafe { libc::syscall(call.nr, a, b, c, d, e, f) };
                let errno = std::io::Error::last_os_error().raw_os_error();
                if made == -1 && errno == Some(libc::ENOSYS) {
                    REFUSED
                } else {
                    SURVIVED
                }
            }
            Err(_) => UNSUPPORTED,
        };
        // SAFETY: see the fork.
        unsafe { libc::_exit(code) }
    }

    let (_, status) = waitpid(Pid::from_raw(pid), WaitOptions::empty())
        .expect("wait for the probe")
        .expect("the probe has ended");
    if let Some(signal) = status.terminating_signal() {
        assert_eq!(
            signal,
            libc::SIGSYS,
            "the probe died of signal {signal}, which is not the filter"
        );
        return Some(Killed);
    }
    match status.exit_status() {
        Some(SURVIVED) => Some(Survived),
        Some(REFUSED) => Some(Refused),
        Some(UNSUPPORTED) => None,
        other => panic!("the probe ended unexpectedly: {other:?}"),
    }
}

/// Every row, made in a child of its own, ends as listed.
#[test]
fn each_call_ends_as_listed() {
    // What the calls point at, built before any child exists.
    let mut pair = [0i32; 2];
    let mut ring = [0u8; 120]; // struct io_uring_params
    let mut handle = [0u8; 128]; // struct file_handle
    let mut mount_id = 0i32;
    let how = [0u64; 3]; // struct open_how { flags, mode, resolve }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let mut termios = [0u8; 64];
    let mut byte = 0u8;
    let on: libc::c_int = 1;
    let null = c"/dev/null".as_ptr();
    let created = c"/tmp/enclavid-seccomp-probe".as_ptr();

    #[allow(unused_mut)]
    let mut rows = vec![
        // No socket of any family: the child talks over the socketpair it was
        // handed and can address nothing — no AF_VSOCK, no network.
        (
            "socket(AF_INET)",
            call!(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0),
            Killed,
        ),
        (
            "socket(AF_VSOCK)",
            call!(libc::SYS_socket, libc::AF_VSOCK, libc::SOCK_STREAM, 0),
            Killed,
        ),
        (
            "socketpair",
            call!(
                libc::SYS_socketpair,
                libc::AF_UNIX,
                libc::SOCK_STREAM,
                0,
                &raw mut pair
            ),
            Killed,
        ),
        // Writes the filter would never see: a ring's entries, and opens that
        // are not `openat` or keep their flags behind a pointer.
        (
            "io_uring_setup",
            call!(libc::SYS_io_uring_setup, 8, &raw mut ring),
            Killed,
        ),
        (
            "name_to_handle_at",
            call!(
                libc::SYS_name_to_handle_at,
                libc::AT_FDCWD,
                null,
                &raw mut handle,
                &raw mut mount_id,
                0
            ),
            Killed,
        ),
        (
            "open_by_handle_at",
            call!(
                libc::SYS_open_by_handle_at,
                -1,
                &raw mut handle,
                libc::O_WRONLY
            ),
            Killed,
        ),
        (
            "openat2",
            call!(libc::SYS_openat2, libc::AT_FDCWD, null, &raw const how, 24),
            Killed,
        ),
        // Files, for reading only: the same path every way, so the flags are
        // the only variable. The read half is what a child needs to start.
        (
            "openat(O_RDONLY)",
            call!(libc::SYS_openat, libc::AT_FDCWD, null, libc::O_RDONLY),
            Survived,
        ),
        (
            "openat(O_WRONLY)",
            call!(libc::SYS_openat, libc::AT_FDCWD, null, libc::O_WRONLY),
            Killed,
        ),
        (
            "openat(O_RDWR)",
            call!(libc::SYS_openat, libc::AT_FDCWD, null, libc::O_RDWR),
            Killed,
        ),
        (
            "openat(O_RDONLY | O_CREAT)",
            call!(
                libc::SYS_openat,
                libc::AT_FDCWD,
                created,
                libc::O_RDONLY | libc::O_CREAT,
                0o600
            ),
            Killed,
        ),
        (
            "openat(O_RDONLY | O_TRUNC)",
            call!(
                libc::SYS_openat,
                libc::AT_FDCWD,
                null,
                libc::O_RDONLY | libc::O_TRUNC
            ),
            Killed,
        ),
        (
            "memfd_create",
            call!(
                libc::SYS_memfd_create,
                c"enclavid-seccomp-probe".as_ptr(),
                0
            ),
            Killed,
        ),
        ("ftruncate", call!(libc::SYS_ftruncate, -1, 0), Killed),
        // The filesystem's shape: somewhere writable to mount, or a device node
        // of its own.
        (
            "mount",
            call!(
                libc::SYS_mount,
                c"none".as_ptr(),
                c"/tmp".as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                0
            ),
            Killed,
        ),
        (
            "mknodat",
            call!(
                libc::SYS_mknodat,
                libc::AT_FDCWD,
                c"/tmp/enclavid-seccomp-probe-node".as_ptr(),
                libc::S_IFCHR | 0o600,
                libc::makedev(1, 3)
            ),
            Killed,
        ),
        // Another process, whatever `ptrace_scope` says.
        (
            "ptrace",
            call!(libc::SYS_ptrace, libc::PTRACE_ATTACH, 1, 0, 0),
            Killed,
        ),
        (
            "process_vm_readv",
            call!(libc::SYS_process_vm_readv, 1, 0, 0, 0, 0, 0),
            Killed,
        ),
        (
            "prlimit64 reading another process's",
            call!(
                libc::SYS_prlimit64,
                1,
                libc::RLIMIT_NOFILE,
                0,
                &raw mut limit
            ),
            Killed,
        ),
        // Anything that outlives the child: a shared segment, a process.
        (
            "shmget",
            call!(
                libc::SYS_shmget,
                libc::IPC_PRIVATE,
                4096,
                libc::IPC_CREAT | 0o600
            ),
            Killed,
        ),
        (
            "clone(SIGCHLD), a fork",
            call!(libc::SYS_clone, libc::SIGCHLD),
            Killed,
        ),
        // Without CLONE_SIGHAND the kernel refuses it, so no thread is made;
        // what is checked is that the filter let it through.
        (
            "clone(CLONE_THREAD)",
            call!(libc::SYS_clone, libc::CLONE_THREAD),
            Survived,
        ),
        // Refused rather than killed, so glibc falls back to `clone`.
        ("clone3", call!(libc::SYS_clone3, 0, 0), Refused),
        // A resource limit: its own, to read.
        (
            "prlimit64 reading its own",
            call!(
                libc::SYS_prlimit64,
                0,
                libc::RLIMIT_NOFILE,
                0,
                &raw mut limit
            ),
            Survived,
        ),
        (
            "prlimit64 setting its own",
            call!(
                libc::SYS_prlimit64,
                0,
                libc::RLIMIT_CORE,
                &raw const zero,
                0
            ),
            Killed,
        ),
        // `ioctl`: only the one request the child makes. fd 0 here is not a
        // socket, so FIONBIO fails — after the filter let it through.
        (
            "ioctl(FIONBIO)",
            call!(libc::SYS_ioctl, 0, libc::FIONBIO, &raw const on),
            Survived,
        ),
        (
            "ioctl(TCGETS)",
            call!(libc::SYS_ioctl, 0, libc::TCGETS, &raw mut termios),
            Killed,
        ),
        // What every child does.
        ("read", call!(libc::SYS_read, 0, &raw mut byte, 0), Survived),
        (
            "mmap, anonymous",
            call!(
                libc::SYS_mmap,
                0,
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0
            ),
            Survived,
        ),
    ];
    // musl's `open`, under the same condition as `openat`.
    #[cfg(target_arch = "x86_64")]
    rows.extend([
        (
            "open(O_RDONLY)",
            call!(libc::SYS_open, null, libc::O_RDONLY),
            Survived,
        ),
        (
            "open(O_WRONLY)",
            call!(libc::SYS_open, null, libc::O_WRONLY),
            Killed,
        ),
        (
            "open(O_RDONLY | O_CREAT)",
            call!(
                libc::SYS_open,
                created,
                libc::O_RDONLY | libc::O_CREAT,
                0o600
            ),
            Killed,
        ),
        (
            "open(O_RDONLY | O_TRUNC)",
            call!(libc::SYS_open, null, libc::O_RDONLY | libc::O_TRUNC),
            Killed,
        ),
    ]);

    let mut wrong = Vec::new();
    for (what, call, expected) in rows {
        match under_filter(call) {
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
