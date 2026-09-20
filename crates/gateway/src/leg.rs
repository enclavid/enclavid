//! How a connection to api is made, and how it reaches the proxy that will use
//! it.
//!
//! ## The handshake is this role's, and cannot be anyone else's
//!
//! A general TLS stack decides whether to trust a peer from a certificate
//! chain. Ours decides from a quote: the peer must prove it runs the build the
//! CALLER named, a value that differs from request to request and is known to
//! nobody but this role. So the proxy is given a connection that is already
//! established and already proved, and is told to speak plain HTTP over it —
//! it performs no handshake of its own and holds no key.
//!
//! [`connect`] is where the proof happens, and it is the only place it can:
//! routing picks by what the host DECLARED, the handshake is what the peer
//! PROVED, and unless the two are the same value the connection does not exist.
//!
//! ## Why a socket pair stands between the two
//!
//! An attested connection is an object in this process's memory — a TLS session
//! over vsock — and the proxy identifies a connection by its file descriptor.
//! Handed such an object directly it sees no descriptor at all, and two things
//! break at once: it never reuses a connection, so every request pays a fresh
//! attested handshake; and every parked connection collides on one key inside
//! its pool, where the bound then stops bounding and a live connection can be
//! dropped to make room for another.
//!
//! So what it is handed is one half of a socket pair — an ordinary kernel
//! socket with an ordinary descriptor — while the other half is joined to the
//! attested session by a pump. Everything the proxy knows how to do then works
//! unchanged, and the session it is really talking through stays ours.
//!
//! The cost is one copy through the kernel in each direction. Measured on a
//! bench: no effect on latency at all, and on bulk transfer a few percent —
//! PROVIDED the pair's buffers are set. Left at the kernel's default they halve
//! throughput, which is why [`BUFFER`] exists and why a socket that refuses it
//! fails the connection rather than serving at half speed.
//!
//! ## What was proved is written down, so it can be checked again
//!
//! A leg is proved once, when it is opened, and then used by many requests —
//! that is what a pool is for. Which leg a later request gets is decided by a
//! key the proxy hashes, so the binding between "this caller named build M" and
//! "this connection proved M" rests on that key being built correctly every
//! time, for ever.
//!
//! [`Ledger`] is what makes it checkable instead. The measurement proved at the
//! handshake is written down against the descriptor the proxy will hold, and
//! `crate::proxy` looks it up again after a connection has been chosen and
//! before the request is sent. A key that ever picked the wrong leg then fails
//! the request rather than serving it.
//!
//! ## The address the proxy is given is not an address
//!
//! Its pool checks that a parked connection still points where the peer says,
//! by asking the kernel for the socket's far end and comparing. A socket pair's
//! far end is nameless and can equal no address, so the peer is declared at the
//! unspecified address, which is the one case that check waives. What keeps one
//! caller's connections away from another's is therefore not the address: it is
//! the key `crate::proxy` builds, and that is where the reasoning about it
//! lives.

use std::os::fd::AsRawFd;
use std::sync::Arc;

use pingora_core::connectors::L4Connect;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_core::protocols::l4::stream::Stream;
use pingora_core::{ConnectError, Error, Result};
use tokio::net::UnixStream;

use crate::upstream::{Tls, connect};

/// How much each half of the pair may hold before its writer waits.
///
/// Set rather than inherited: the kernel's default is small enough that the
/// pump becomes the throughput limit — on the bench it halved a bulk transfer,
/// and this value brought it back to within a few percent of no pump at all.
const BUFFER: libc::c_int = 256 * 1024;

/// How much is moved per pass in each direction. The pair's buffer is what
/// bounds memory; this only decides how many passes it takes to fill it.
const PUMP_CHUNK: usize = 64 * 1024;

/// What every open leg proved, by the descriptor the proxy holds it under.
///
/// Read after a connection has been chosen and before anything is sent — see
/// the module docs. Descriptor numbers are reused by the kernel once closed, so
/// each entry carries the count of the leg that made it: a stale entry can only
/// be removed by the leg it belongs to, and a new leg on the same number
/// overwrites rather than inherits.
#[derive(Default)]
pub struct Ledger {
    open: std::sync::Mutex<std::collections::HashMap<std::os::fd::RawFd, (u64, String)>>,
    legs: std::sync::atomic::AtomicU64,
}

impl Ledger {
    fn record(&self, fd: std::os::fd::RawFd, measurement: &str) -> u64 {
        let leg = self.legs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut open = self.open.lock().expect("the ledger is never held on panic");
        open.insert(fd, (leg, measurement.to_owned()));
        leg
    }

    fn forget(&self, fd: std::os::fd::RawFd, leg: u64) {
        let mut open = self.open.lock().expect("the ledger is never held on panic");
        if open.get(&fd).is_some_and(|(held, _)| *held == leg) {
            open.remove(&fd);
        }
    }

    /// What the connection under `fd` proved when it was opened, if this role
    /// opened it.
    pub fn proved(&self, fd: std::os::fd::RawFd) -> Option<String> {
        let open = self.open.lock().expect("the ledger is never held on panic");
        open.get(&fd).map(|(_, measurement)| measurement.clone())
    }
}

/// One api instance, dialable and provable.
///
/// Built per request by `crate::proxy` and handed to the proxy as the way to
/// open a connection. It carries the measurement the CALLER named, not one this
/// role chose, which is what makes the check in [`connect`] mean anything.
pub struct Leg {
    addr: String,
    measurement: String,
    part: Arc<crate::upstream::Part>,
    tls: Tls,
    ledger: Arc<Ledger>,
}

/// Written out rather than derived, because the proxy prints this. What a leg
/// is made of — which machine, which build — is the fleet's shape, and a
/// derived one would put it wherever a caller of `{:?}` happens to send it.
impl std::fmt::Debug for Leg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a leg to api")
    }
}

impl Leg {
    pub fn new(
        addr: String,
        measurement: String,
        part: Arc<crate::upstream::Part>,
        tls: Tls,
        ledger: Arc<Ledger>,
    ) -> Leg {
        Leg {
            addr,
            measurement,
            part,
            tls,
            ledger,
        }
    }
}

#[async_trait::async_trait]
impl L4Connect for Leg {
    /// The address argument is the one declared on the peer, which for this
    /// transport is a placeholder — see the module docs. Where to dial comes
    /// from this value, which the routing table put here.
    async fn connect(&self, _declared: &SocketAddr) -> Result<Stream> {
        let attested = connect(&self.addr, &self.measurement, &self.part, &self.tls)
            .await
            .map_err(|e| Error::because(ConnectError, "the leg to api could not be opened", e))?;

        let (near, far) = UnixStream::pair()
            .map_err(|e| Error::because(ConnectError, "a socket pair could not be made", e))?;
        for half in [&near, &far] {
            buffered(half).map_err(|e| {
                Error::because(ConnectError, "a socket pair refused its buffer size", e)
            })?;
        }

        // Written down before the leg is handed over, so a request cannot be
        // sent on it before what it proved can be checked.
        let held = near.as_raw_fd();
        let leg = self.ledger.record(held, &self.measurement);

        // Ends when either side does, which is what closes the other: the
        // attested session is dropped here, and the proxy sees its half close.
        // The entry goes with it — and only this leg's entry, never a newer
        // leg that the kernel gave the same number to.
        let ledger = self.ledger.clone();
        tokio::spawn(async move {
            let mut attested = attested;
            let mut far = far;
            let _ = tokio::io::copy_bidirectional_with_sizes(
                &mut far,
                &mut attested,
                PUMP_CHUNK,
                PUMP_CHUNK,
            )
            .await;
            ledger.forget(held, leg);
        });

        Ok(Stream::from(near))
    }
}

/// Give one half of the pair room, in both directions.
fn buffered(half: &UnixStream) -> std::io::Result<()> {
    for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: the descriptor is owned by a live `UnixStream`, and the value
        // is a `c_int` of the length declared beside it.
        let set = unsafe {
            libc::setsockopt(
                half.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                std::ptr::from_ref(&BUFFER).cast(),
                std::mem::size_of_val(&BUFFER) as libc::socklen_t,
            )
        };
        if set != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The pair carries bytes both ways, and the buffers it was given are the
    /// ones it has. A pair left at the default is the configuration the bench
    /// measured at half throughput, so this is a property worth pinning.
    #[tokio::test]
    async fn a_pair_is_given_room_and_carries_both_ways() {
        let (near, far) = UnixStream::pair().unwrap();
        buffered(&near).unwrap();
        buffered(&far).unwrap();

        let mut size = 0 as libc::c_int;
        let mut len = std::mem::size_of_val(&size) as libc::socklen_t;
        // SAFETY: a live descriptor, and an out-parameter of the declared size.
        let read = unsafe {
            libc::getsockopt(
                near.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_mut(&mut size).cast(),
                &mut len,
            )
        };
        assert_eq!(read, 0);
        assert!(
            size >= BUFFER,
            "asked for {BUFFER} of send buffer and got {size}"
        );

        let (mut near, mut far) = (near, far);
        near.write_all(b"there").await.unwrap();
        let mut said = [0u8; 5];
        far.read_exact(&mut said).await.unwrap();
        assert_eq!(&said, b"there");

        far.write_all(b"back!").await.unwrap();
        near.read_exact(&mut said).await.unwrap();
        assert_eq!(&said, b"back!");
    }

    /// What the proxy is handed is an ordinary socket with an ordinary
    /// descriptor. This is the whole reason the pair is here: an attested
    /// session has none, and without one the proxy neither reuses a connection
    /// nor keeps its pool within its bound.
    #[tokio::test]
    async fn the_half_the_proxy_gets_has_a_descriptor() {
        let (near, _far) = UnixStream::pair().unwrap();
        let fd = near.as_raw_fd();
        assert!(fd >= 0);

        let stream = Stream::from(near);
        use pingora_core::protocols::UniqueID;
        assert_eq!(stream.id(), fd, "the proxy identifies a leg by this");
    }
}
