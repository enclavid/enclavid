//! The public connection's first metre, from the host's transport to a socket
//! the proxy library can listen on.
//!
//! ## Why it exists
//!
//! This guest has no NIC, so the host carries public connections in over vsock.
//! The proxy library listens on two things and neither is that: its
//! `ServerAddress` is a closed choice of TCP or a unix socket, with no trait to
//! implement for a third. Its CONNECTING side is open — `L4Connect` is how the
//! attested leg to api is built, see `crate::leg` — but its listening side is
//! not.
//!
//! So this accepts the fleet transport and hands each connection to the library
//! over a unix socket in this guest. Everything downstream — the TLS
//! handshake, HTTP, the proxy — is then the library's own, with no wrapper of
//! ours between the kernel and it.
//!
//! ## What it costs, and what it buys
//!
//! One more hop inside this guest: a task per connection copying bytes both
//! ways, and two more descriptors per public connection. Two rather than one
//! because both ends of the hop are in THIS process — the one this file
//! connects with and the one the proxy accepts — so a public connection costs
//! three descriptors here where it used to cost one. It is a copy between two
//! sockets of one process, so it costs what that costs, but it is not free.
//!
//! What it buys is that the accept loop, the TLS termination and the server's
//! own supervision stop being this role's code. The alternative was to keep all
//! three, which is what was here before.
//!
//! ## One path, not one per build
//!
//! A developer build could be handed straight to the library, which does listen
//! on TCP. It is bridged anyway, so that the arrangement a developer exercises
//! is the one the attested build runs. The place a difference would hide is
//! exactly here.
//!
//! ## The socket is not a door for anything else, and not on a disk
//!
//! It lives in this guest and nothing else runs here — the image is one
//! process, and the measurement says so. A second party able to connect to it
//! would be a second party already inside the guest, which is a different
//! problem entirely. It is unlinked before binding so a restart does not find
//! its own leftovers.
//!
//! The path it takes is under `/run`, which this guest mounts as a tmpfs
//! because a CVM has no disk — see `image/init/inittab/gateway`. So the socket
//! is a name in encrypted RAM that ends with the machine, not a file anything
//! outside could ever read.

use safe_logger::debug;

/// How much of one direction is moved per copy.
///
/// The same size the leg to api uses, and for the same reason: large enough
/// that a body is not chopped into syscalls, small enough that an idle
/// connection is not holding much.
const CHUNK: usize = 64 * 1024;

/// Carry public connections to `to`, for ever, at most `at_once` of them.
///
/// Await this on the role's own task: a role whose bridge stopped would hold a
/// listener nothing drains and answer nobody, while still looking alive.
///
/// The permit is what bounds this role, and this is where it belongs now: a
/// public connection costs THREE descriptors here — the one the host carried
/// in, the one this file connects with, and the one the proxy accepts — plus a
/// connection at api and whatever api has sent that the caller has not taken.
/// Without a ceiling one caller opening
/// connections takes all of them until an accept fails, and a failing accept
/// stops every other caller too.
///
/// Taken BEFORE the connection is carried, so the wait happens here and
/// unaccepted connections queue in the listener's backlog rather than inside
/// this process.
pub async fn carry(
    listener: fleet_transport::Listener,
    to: std::path::PathBuf,
    at_once: usize,
) -> ! {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(at_once));
    fleet_transport::accept_forever(listener, move |public, peer| {
        let to = to.clone();
        let slots = slots.clone();
        async move {
            let Ok(slot) = slots.acquire_owned().await else {
                return;
            };
            tokio::spawn(async move {
                let inside = match tokio::net::UnixStream::connect(&to).await {
                    Ok(inside) => inside,
                    Err(e) => {
                        // The listener is this process's own, so this is the
                        // proxy not being up rather than anything a caller did.
                        debug!("the public connection from {peer} found no listener: {e}");
                        return;
                    }
                };
                splice(public, inside, &peer).await;
                drop(slot);
            });
        }
    })
    .await
}

/// Move bytes both ways until either end is done.
async fn splice(
    mut public: fleet_transport::Stream,
    mut inside: tokio::net::UnixStream,
    peer: &str,
) {
    if let Err(e) =
        tokio::io::copy_bidirectional_with_sizes(&mut public, &mut inside, CHUNK, CHUNK).await
    {
        // Every ordinary ending looks like this — a caller that went away, a
        // reset, a half-close the other side did not expect.
        debug!("the public connection from {peer} ended: {e}");
    }
}

/// Bind the socket the proxy will listen on, removing whatever a previous run
/// of this process left behind.
///
/// Returns the path, because that is what the library is configured with.
pub fn prepare(path: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(path);
    // Not an error to remove: the usual case is that there is nothing there.
    let _ = std::fs::remove_file(&path);
    path
}

/// TCP arm only, because the fleet listener is TCP here. What the attested
/// build changes is which listener accepts; everything after it is this file.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A listener on the unix side that answers every connection by echoing
    /// what it reads back, so a test can prove both directions at once.
    async fn echoing(at: &std::path::Path) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(at).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut seen = [0u8; 5];
                    if stream.read_exact(&mut seen).await.is_ok() {
                        let _ = stream.write_all(&seen).await;
                        let _ = stream.flush().await;
                    }
                    // Held open so the caller's half does not close under it.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                });
            }
        })
    }

    /// A path this test alone uses, gone before it binds.
    fn somewhere(name: &str) -> std::path::PathBuf {
        let at = std::env::temp_dir().join(format!("bridge-{}-{name}.sock", std::process::id()));
        prepare(at.to_str().unwrap())
    }

    /// One connection carried, and bytes moving both ways over it.
    #[tokio::test]
    async fn a_connection_is_carried_and_bytes_move_both_ways() {
        let at = somewhere("both-ways");
        let _inside = echoing(&at).await;

        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(carry(listener, at, 8));

        let mut caller = tokio::net::TcpStream::connect(&addr).await.unwrap();
        caller.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        caller.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello", "what went in came back through the bridge");
    }

    /// The ceiling holds: with room for one, a second caller waits rather than
    /// costing a second pair of descriptors.
    ///
    /// What it waits at is the permit, before anything is connected — so an
    /// unaccepted caller sits in the listener's backlog rather than inside this
    /// process.
    #[tokio::test]
    async fn a_second_caller_waits_when_there_is_room_for_one() {
        let at = somewhere("ceiling");
        let _inside = echoing(&at).await;

        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(carry(listener, at, 1));

        // The first takes the only permit and holds it: it is answered, and
        // its connection stays open.
        let mut first = tokio::net::TcpStream::connect(&addr).await.unwrap();
        first.write_all(b"first").await.unwrap();
        let mut back = [0u8; 5];
        first.read_exact(&mut back).await.unwrap();

        // The second connects — the kernel accepts into the backlog — but
        // nothing carries it, so nothing answers.
        let mut second = tokio::net::TcpStream::connect(&addr).await.unwrap();
        second.write_all(b"secnd").await.unwrap();
        let mut nothing = [0u8; 5];
        let waited =
            tokio::time::timeout(Duration::from_millis(300), second.read_exact(&mut nothing)).await;
        assert!(waited.is_err(), "the second caller waits for a permit");
    }

    /// A restart does not trip over its own leftovers.
    #[tokio::test]
    async fn a_leftover_socket_is_cleared_before_binding() {
        let at = std::env::temp_dir().join(format!("bridge-{}-leftover.sock", std::process::id()));
        let _ = std::fs::remove_file(&at);
        std::fs::write(&at, b"what a previous run left").unwrap();
        assert!(at.exists());

        let cleared = prepare(at.to_str().unwrap());
        assert!(!cleared.exists(), "the path is free for the next bind");
        // And binding it now works, which is the whole point of clearing it.
        let listener = tokio::net::UnixListener::bind(&cleared).unwrap();
        drop(listener);
        let _ = std::fs::remove_file(&cleared);
    }
}
