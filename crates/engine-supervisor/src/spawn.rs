//! Starting one process — a child, or the coprocess a child may have beside it:
//! its socket, its descriptors, and what it is given between fork and exec —
//! its group, score, limits and identity when it is placed, and its syscall
//! filters last.

#[cfg(all(test, target_os = "linux"))]
mod tests;

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use remoc::RemoteSend;
use remoc::codec::Ciborium;

use crate::INHERITED_FD;
use crate::cgroup::Placement;
use crate::channel::channel_config;

/// Why a child or a coprocess could not be started, or a child did not hand
/// over its service client.
///
/// Each variant's text carries the error under it, as remoc's own do, so one
/// logged line says the whole of it.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// A descriptor meant for the process sits on 0, 1 or 2, where std puts its
    /// stdio before any of ours is placed.
    #[error("a child's {0} sits on a stdio descriptor")]
    OnStdio(&'static str),
    /// The socketpair to the child could not be made ready.
    #[error("make the child's socketpair: {0}")]
    Socketpair(io::Error),
    /// The process did not exec — or failed between fork and exec, which std
    /// reports the same way.
    #[error("spawn {}: {err}", exe.display())]
    Exec { exe: PathBuf, err: io::Error },
    /// The supervisor's end could not be handed to the runtime.
    #[error("adopt the supervisor's end: {0}")]
    Adopt(io::Error),
    /// remoc could not be stood up over the socketpair.
    #[error("connect to the child: {0}")]
    Connect(remoc::ConnectError<io::Error, io::Error>),
    /// The child's service client did not arrive.
    #[error("receive the child's service client: {0}")]
    Receive(remoc::rch::base::RecvError),
    /// The child closed the connection without sending its service client.
    #[error("the child closed before sending its service client")]
    Closed,
}

/// Spawn `exe` as a fresh child with one end of a socketpair on its fd 0, frame
/// the supervisor's end with remoc (supervisor = client, child = server), and
/// return the child (`kill_on_drop`) and the service client `Cli` it sends on
/// the base channel.
///
/// `inherit` lands in order from [`INHERITED_FD`] up, and those are the only
/// descriptors besides stdio that survive `exec`: on Linux every other one is
/// marked CLOEXEC between fork and exec, whatever flag it was opened with. So a
/// child gets handles to its own composition's cwasm and weights files and to
/// nothing else — no other composition's memfd, no sibling's socket, no
/// connection to the host.
///
/// `filtered` puts the child under its syscall filters (Linux only), as a
/// [`ChildRunner`](crate::ChildRunner) always does; `false` is for a bench or a
/// test. A runner with [`Cgroups`](crate::Cgroups) also places each child — its
/// memory group, score and identity; this entry point places none.
pub async fn spawn_and_connect<Cli>(
    exe: &Path,
    inherit: &[BorrowedFd<'_>],
    filtered: bool,
) -> Result<(tokio::process::Child, Cli), SpawnError>
where
    Cli: RemoteSend,
{
    let (child, sup_end) = spawn_child(exe, inherit, filtered, None)?;
    let client = connect::<Cli>(sup_end).await?;
    Ok((child, client))
}

/// Spawn `exe` as a coprocess: `socket` on its fd 0, and `inherit` from
/// [`INHERITED_FD`] up, as [`spawn_and_connect`] hands a child its own. The
/// supervisor keeps no end of `socket` — whoever holds the other end is who the
/// coprocess talks to — so nothing is connected here, and the coprocess is
/// returned `kill_on_drop`.
///
/// `filtered` puts it under the coprocess's syscall filters (Linux only), as a
/// [`Coprocess`](crate::Coprocess) always does; `false` is for a bench or a
/// test. This entry point places it in no group and under no identity of its
/// own.
pub fn spawn_coprocess(
    exe: &Path,
    socket: OwnedFd,
    inherit: &[BorrowedFd<'_>],
    filtered: bool,
) -> Result<tokio::process::Child, SpawnError> {
    spawn(
        exe,
        socket,
        inherit,
        filtered.then_some(Filters::Coprocess),
        None,
    )
}

/// Which syscall filters a spawned process runs under: a child's, or the
/// narrower ones of the coprocess beside it — see the seccomp module.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Filters {
    Child,
    Coprocess,
}

/// The spawn half of [`spawn_and_connect`], placing the child first when given a
/// [`Placement`]. Returns the child and the supervisor's end of its socketpair.
pub(crate) fn spawn_child(
    exe: &Path,
    inherit: &[BorrowedFd<'_>],
    filtered: bool,
    placement: Option<Placement>,
) -> Result<(tokio::process::Child, std::os::unix::net::UnixStream), SpawnError> {
    let (sup_end, child_end) =
        std::os::unix::net::UnixStream::pair().map_err(SpawnError::Socketpair)?;
    sup_end
        .set_nonblocking(true)
        .map_err(SpawnError::Socketpair)?;
    let child = spawn(
        exe,
        OwnedFd::from(child_end),
        inherit,
        filtered.then_some(Filters::Child),
        placement,
    )?;
    Ok((child, sup_end))
}

/// [`spawn_coprocess`] as a runner starts one: always under the coprocess's
/// filters, and placed first when given a [`Placement`].
pub(crate) fn spawn_placed_coprocess(
    exe: &Path,
    socket: OwnedFd,
    inherit: &[BorrowedFd<'_>],
    placement: Option<Placement>,
) -> Result<tokio::process::Child, SpawnError> {
    spawn(exe, socket, inherit, Some(Filters::Coprocess), placement)
}

/// Spawn `exe` with `stdin` on its fd 0 and `inherit` from [`INHERITED_FD`] up,
/// placed first when given a [`Placement`] and under `filters` last.
fn spawn(
    exe: &Path,
    stdin: OwnedFd,
    inherit: &[BorrowedFd<'_>],
    filters: Option<Filters>,
    placement: Option<Placement>,
) -> Result<tokio::process::Child, SpawnError> {
    // std puts the process's stdio on 0, 1 and 2 before any of ours runs, so a
    // descriptor of ours numbered there would already be something else.
    let at_stdio = |fd: RawFd| fd <= libc::STDERR_FILENO;
    if placement
        .as_ref()
        .and_then(|p| p.procs.as_ref())
        .is_some_and(|fd| at_stdio(fd.as_raw_fd()))
    {
        return Err(SpawnError::OnStdio("process list"));
    }
    let inherited: Vec<RawFd> = inherit.iter().map(|fd| fd.as_raw_fd()).collect();
    if inherited.iter().any(|&fd| at_stdio(fd)) {
        return Err(SpawnError::OnStdio("inherited descriptor"));
    }
    // The first number past those the inherited descriptors are placed on, and
    // room, made here before the fork, for each one lifted above it.
    let past = INHERITED_FD + RawFd::try_from(inherited.len()).unwrap_or(RawFd::MAX - INHERITED_FD);
    let mut lifted: Vec<RawFd> = vec![0; inherited.len()];

    let mut cmd = tokio::process::Command::new(exe);
    // An empty environment, plus what is named here. The process takes every
    // input over its socket, so nothing a worker's environment holds — a key put
    // there by mistake, say — reaches it through `/proc/self/environ`.
    cmd.env_clear();
    if let Ok(v) = std::env::var("RUST_BACKTRACE") {
        cmd.env("RUST_BACKTRACE", v);
    }
    // Its socket on fd 0. `Stdio::from` closes this process's copy at spawn, so
    // the process's death ends the stream at once.
    cmd.stdin(std::process::Stdio::from(stdin));
    // Null stdout and stderr: the process speaks only over fd 0, and the
    // worker's own stdio leads to the host. The `debug` build alone gives it the
    // worker's stderr — its image already puts every role's `debug!` on the port
    // — and the worker's threshold with it, from the environment cleared above;
    // without one, every dependency's dump of every byte it moves goes there too.
    cmd.stdout(std::process::Stdio::null());
    #[cfg(not(feature = "debug"))]
    cmd.stderr(std::process::Stdio::null());
    #[cfg(feature = "debug")]
    {
        cmd.stderr(std::process::Stdio::inherit());
        if let Ok(level) = std::env::var(safe_logger::LEVEL_KEY) {
            cmd.env(safe_logger::LEVEL_KEY, level);
        }
    }
    // An early return or a dropped request kills the process.
    cmd.kill_on_drop(true);

    #[cfg(target_os = "linux")]
    let filters = filters.map(crate::seccomp::filters);
    #[cfg(not(target_os = "linux"))]
    let _ = (filters, placement); // no filter or placement off Linux

    // Runs between fork and exec, in a copy of this process where only
    // async-signal-safe work is sound: every call in it is a single system call
    // that allocates nothing, takes no lock and does not panic, over what was
    // built above before the fork. Errors are raw errnos or kinds, which do not
    // allocate either.
    let before_exec = move || -> std::io::Result<()> {
        // ---- its memory group, first (Linux) ----
        //
        // Charges do not move with a process that changes group, so the exec,
        // the runtime and the work must all be counted in its group from the
        // start. And before the inherited descriptor, which may be put on this
        // one's number. `0` names the writer. A process that cannot be placed
        // never execs.
        #[cfg(target_os = "linux")]
        if let Some(procs) = placement.as_ref().and_then(|p| p.procs.as_ref())
            && rustix::io::write(procs, b"0")? != 1
        {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        // ---- the inherited descriptors (all platforms) ----
        //
        // Each onto its number, in order, from `INHERITED_FD` up. Before the
        // filters, which refuse `dup2` as they do nearly everything a process
        // has no use for. Each is lifted first, as a CLOEXEC copy at or above
        // `past`, so that placing one never lands on another still to be
        // placed; then `dup2` puts each where it goes, without CLOEXEC. The
        // lifted copies close at the exec.
        for (src, copy) in inherited.iter().zip(lifted.iter_mut()) {
            // SAFETY: copies a descriptor this process holds open — the caller
            // keeps it alive across the spawn — onto the lowest free number at
            // or above `past`.
            let fd = unsafe { libc::fcntl(*src, libc::F_DUPFD_CLOEXEC, past) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            *copy = fd;
        }
        for (to, copy) in (INHERITED_FD..).zip(lifted.iter()) {
            // SAFETY: copies a descriptor this process holds open onto a number
            // below every lifted copy, whose holder, if any, is a copy of one
            // of the supervisor's — the one placed here is lifted already.
            if unsafe { libc::dup2(*copy, to) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        #[cfg(target_os = "linux")]
        {
            // ---- every other descriptor: closed at the exec ----
            //
            // CLOEXEC on everything else is what keeps a process to the
            // descriptors named above, and a flag set by a call of its own
            // after the descriptor was made leaves a window: the vsock
            // listener's accept marks its connection that way, and a fork from
            // another thread inside the window copies the connection without
            // the flag. So every descriptor past the inherited one is marked
            // here, whatever it carries. Marked, not closed: std's own pipe,
            // which carries a failure here back to the spawn, is among them and
            // must stay open until the exec.
            //
            // SAFETY: `close_range` takes two descriptor numbers and a flag, no
            // pointer; with CLOSE_RANGE_CLOEXEC it closes nothing, only sets
            // the flag.
            let marked = unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    past,
                    libc::c_uint::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                )
            };
            if marked < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // ---- its score, limits and identity, while still root ----
            if let Some(p) = &placement {
                use rustix::fs::{Mode, OFlags};
                use rustix::process::{Resource, Rlimit, setrlimit};
                use rustix::thread::{
                    Gid, Uid, set_thread_groups, set_thread_res_gid, set_thread_res_uid,
                };

                // While it still holds CAP_SYS_RESOURCE, raised for the worker
                // by its service file, so the value is also this process's
                // floor — a write by a holder of it sets the minimum the
                // process may later lower it to. And before the identity
                // changes: `/proc/self` stays root's until the exec.
                let score = rustix::fs::open(
                    c"/proc/self/oom_score_adj",
                    OFlags::WRONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                if rustix::io::write(&score, &p.oom_score_adj)? != p.oom_score_adj.len() {
                    return Err(std::io::ErrorKind::WriteZero.into());
                }
                drop(score);
                // Hard and soft alike: what the identity below cannot raise
                // again. No core: a dump is the round's memory in a file.
                setrlimit(
                    Resource::Nproc,
                    Rlimit {
                        current: Some(p.tasks),
                        maximum: Some(p.tasks),
                    },
                )?;
                setrlimit(
                    Resource::Core,
                    Rlimit {
                        current: Some(0),
                        maximum: Some(0),
                    },
                )?;
                // Per thread: libc's wrappers broadcast to every thread through
                // machinery that takes locks, and a forked child has one thread.
                // Groups, then group, then user: the first two need the root the
                // last gives up.
                let (uid, gid) = (Uid::from_raw(p.uid), Gid::from_raw(p.uid));
                set_thread_groups(&[])?;
                set_thread_res_gid(gid, gid, gid)?;
                set_thread_res_uid(uid, uid, uid)?;
            }
            // ---- the syscall filters, last: nothing after them but `execve` ----
            //
            // `apply_filter` sets `no_new_privs` first, which loading a filter
            // without privilege needs and which blocks a setuid gain on any
            // later exec.
            for filter in filters.into_iter().flatten() {
                seccompiler::apply_filter(filter).map_err(|e| match e {
                    seccompiler::Error::Prctl(e) | seccompiler::Error::Seccomp(e) => e,
                    _ => std::io::ErrorKind::Other.into(),
                })?;
            }
        }
        Ok(())
    };
    // SAFETY: `before_exec` keeps to what the time between fork and exec allows —
    // see the comment above it, and the SAFETY of each block inside.
    unsafe { cmd.as_std_mut().pre_exec(before_exec) };

    let process = cmd.spawn().map_err(|err| SpawnError::Exec {
        exe: exe.to_path_buf(),
        err,
    })?;
    safe_logger::debug!("spawned: {}", exe.display());
    Ok(process)
}

/// The handshake half of [`spawn_and_connect`]: frame the supervisor's end with
/// remoc and receive the child's service client on the base channel.
pub(crate) async fn connect<Cli>(sup_end: std::os::unix::net::UnixStream) -> Result<Cli, SpawnError>
where
    Cli: RemoteSend,
{
    let sup_end = tokio::net::UnixStream::from_std(sup_end).map_err(SpawnError::Adopt)?;
    let (read, write) = sup_end.into_split();
    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(channel_config(), read, write)
            .await
            .map_err(SpawnError::Connect)?;
    safe_logger::debug!("child connected");
    tokio::spawn(conn);
    rx.recv()
        .await
        .map_err(SpawnError::Receive)?
        .ok_or(SpawnError::Closed)
}

/// What the child maps from the supervisor's memory: the length of the
/// descriptors it inherits, together. Zero for one that cannot be measured,
/// which only leaves that child's score less reduced.
pub(crate) fn inherited_len(inherit: &[BorrowedFd<'_>]) -> u64 {
    inherit
        .iter()
        .filter_map(|fd| rustix::fs::fstat(fd).ok())
        .filter_map(|stat| u64::try_from(stat.st_size).ok())
        .fold(0, u64::saturating_add)
}
