//! The CHILD half: adopt the socket the supervisor put on fd 0, serve one
//! request, exit.
//!
//! Unfeatured, so a child package can depend on this crate with
//! `default-features = false` and reach exactly this much of it.

use std::os::fd::FromRawFd;
use std::sync::Arc;

use remoc::RemoteSend;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;

use crate::connection_cfg;

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
