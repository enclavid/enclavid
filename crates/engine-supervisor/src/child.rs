//! The CHILD half: adopt the socket the supervisor put on fd 0, serve one
//! request, exit.
//!
//! Unfeatured, so a child package can depend on this crate with
//! `default-features = false` and reach exactly this much of it.

use std::os::fd::{AsFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use remoc::RemoteSend;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;

use crate::channel::channel_config;

/// The child fd number an inherited descriptor lands on: the one after stdio —
/// fd 0 the socketpair, 1 and 2 stdout and stderr. A fixed number rather than
/// the supervisor's own, which would tell a child how many descriptors the
/// supervisor holds.
pub const INHERITED_FD: RawFd = libc::STDERR_FILENO + 1;

/// Take the descriptor the supervisor handed this child at [`INHERITED_FD`],
/// once.
///
/// Called before anything in the child opens a file: a slot left empty would be
/// the next file's, and taking it would make a second owner of that file. A
/// second call is refused, so there is never a second owner of this one either.
pub fn take_inherited_fd() -> std::io::Result<OwnedFd> {
    static TAKEN: AtomicBool = AtomicBool::new(false);
    if TAKEN.swap(true, Ordering::AcqRel) {
        return Err(std::io::Error::other(
            "the inherited descriptor was taken already",
        ));
    }
    // SAFETY: `fcntl(F_GETFD)` on a bare number reads that slot's flags or fails
    // with EBADF; it creates, closes and dereferences nothing.
    if unsafe { libc::fcntl(INHERITED_FD, libc::F_GETFD) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the slot is open, as just checked, and nothing else in this
    // process owns it. The supervisor placed it before exec, and `TAKEN` makes
    // this the only `OwnedFd` ever made of it, so it is closed once, by the
    // owner returned here.
    Ok(unsafe { OwnedFd::from_raw_fd(INHERITED_FD) })
}

/// Why a child stopped serving its supervisor other than by being done.
///
/// Each variant's text carries the error under it, as remoc's own do, so the
/// one line a child logs says the whole of it.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// fd 0 could not be taken as the supervisor's socket.
    #[error("adopt fd 0: {0}")]
    Adopt(std::io::Error),
    /// remoc could not be stood up over that socket.
    #[error("connect to the supervisor: {0}")]
    Connect(remoc::ConnectError<std::io::Error, std::io::Error>),
    /// The service client could not be handed to the supervisor.
    #[error("send the service client: {0}")]
    SendClient(remoc::rch::base::SendError<()>),
    /// Serving ended on an error rather than on the supervisor letting go.
    #[error("serve: {0}")]
    Serve(remoc::rtc::ServeError),
}

/// Adopt fd 0 — the socketpair end the supervisor placed there via
/// `Command::stdin` — as a tokio [`UnixStream`](tokio::net::UnixStream). The
/// child's entry point calls this, then [`serve_child`] (or its own remoc serve).
///
/// Through a copy of fd 0 rather than fd 0 itself: taking ownership of a bare
/// descriptor number is the one thing std will not do safely, and a copy costs
/// one `fcntl`. Both name the same socket, and fd 0 stays open beside it until
/// the process exits — which this one does as soon as it has served, so the
/// supervisor sees the end at the same moment either way.
pub fn adopt_fd0() -> std::io::Result<tokio::net::UnixStream> {
    let socket = std::io::stdin().as_fd().try_clone_to_owned()?;
    let std_stream = std::os::unix::net::UnixStream::from(socket);
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
) -> Result<(), ServeError>
where
    Srv: ServerShared<Target, Ciborium>,
    Srv::Client: RemoteSend + Clone,
{
    let stream = adopt_fd0().map_err(ServeError::Adopt)?;
    let (read, write) = stream.into_split();
    let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, Srv::Client, Srv::Client, Ciborium>(
        channel_config(),
        read,
        write,
    )
    .await
    .map_err(ServeError::Connect)?;
    tokio::spawn(conn);

    let (server, client) = Srv::new(service, request_buffer);
    tx.send(client)
        .await
        .map_err(|e| ServeError::SendClient(e.without_item()))?;
    server.serve(true).await.map_err(ServeError::Serve)
}
