//! The fleet transport: the byte stream every role listens and dials on — the
//! legs between roles that run RA-TLS over it, and the ports the host reaches a
//! guest on (a role's public door, its configuration port, its health port).
//!
//! Two arms, chosen at compile time by the `vsock` feature, because which one a
//! binary needs is a fact about where it runs rather than a runtime choice. A
//! measured guest kernel is built without `CONFIG_INET` — it has no IP stack and
//! no NIC — so an attested build reaches its peers over `AF_VSOCK`; a
//! developer's box has no vsock peers, so it uses TCP.
//!
//! **A fleet leg is necessarily two hops.** vsock addresses guest↔host and
//! nothing else, so a guest cannot dial another guest: it dials the host on a
//! port, and something on the host splices that connection onward. This crate
//! carries one hop and knows nothing about the splice.
//!
//! Nothing above this cares which arm is compiled: both hand back a stream that
//! satisfies what RA-TLS and remoc want of it.

pub mod health;
#[cfg(feature = "tower-adapter")]
pub mod service;

#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!(
    "feature `vsock` requires Linux — AF_VSOCK exists only in the Linux kernel. Build \
     without it for non-Linux dev environments."
);

/// Why a fleet leg failed, in terms that carry nothing out of a message.
///
/// Every field is a closed enum, a [`Measurement`], or nothing at all — there is
/// no `String` here, and that is the whole design. A `String` inside an error is
/// the same unbounded content as a `String` in a log line: it can hold what a
/// foreign `Display` chose to say, and no one re-reads those on a dependency
/// bump. Without one, [`safe_logger::SafeToLog`] below is true of the TYPE, so a
/// log site needs no judgement and no reason of its own.
///
/// `Measurement` is the one field carrying a value a peer chose, and it is a
/// newtype for that reason: it can hold 96 hex characters and nothing else, so
/// admitting it costs none of the property above.
///
/// What is given up is the underlying message. It is not lost — the conversion
/// site sends it to `debug!`, which never leaves the TEE — but production sees
/// this type's own account of what happened and an `ErrorKind`, not the text.
/// That is the trade: which of the seven went wrong is worth having in front of
/// an operator, and a sentence from rustls or remoc is worth having only in
/// front of a developer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegFailure {
    /// Nothing answered, or the connection died before TLS. The kind is
    /// `std::io::ErrorKind`, a fieldless enum whose `Debug` is its own name.
    Connect(std::io::ErrorKind),
    /// This end could not produce its own attested identity, so no handshake was
    /// attempted. Separate from [`LegFailure::Attest`] because the actions are
    /// opposite: nobody was contacted and nobody refused anything, so the fault
    /// is here — a chip that will not mint, a platform TCB that moved out from
    /// under a held endorsement. Folding it into `Attest` sent an operator to
    /// restart a healthy peer.
    Mint,
    /// The RA-TLS handshake did not complete for a reason this end could not
    /// name — an ordinary TLS failure, or a peer refusing US.
    ///
    /// It used to cover [`LegFailure::Pin`] as well. That put the fleet's most
    /// likely failure and its least interesting one behind one word, and the
    /// operator actions are opposite: rebuild and re-pin, versus look at the
    /// network.
    Attest,
    /// The peer attested, to a measurement this end does not pin.
    ///
    /// Carries what it presented, because the whole difficulty was that nothing
    /// did: the check happens inside rustls, comes back as a `rustls::Error`,
    /// and the text was going to a `debug!` that a measured build does not
    /// compile. A [`Measurement`] rather than a `String` so this enum stays
    /// something a log line can print without asking where the bytes came from.
    Pin(Measurement),
    /// remoc could not bring the multiplexed connection up over the stream.
    Rpc,
    /// The connection came up but the service clients did not cross it.
    Clients,
    /// The peer closed before sending its service clients.
    Closed,
    /// An established connection stopped being served.
    Serve,
}

/// A launch measurement, as it may appear in a log line.
///
/// The point of the newtype is what it refuses. [`LegFailure`] is otherwise made
/// of fieldless variants and one `std::io::ErrorKind`, so rendering it can never
/// print something a peer chose; a `String` variant would end that, and the
/// first thing to reach for it would be the message from a failed handshake.
/// Ninety-six lowercase hex characters is the whole vocabulary.
///
/// The value is not trusted, and does not need to be. It comes from a
/// chip-signed report, and it names an image the HOST chose to launch — so a
/// log the host reads is being told something it already decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement(String);

impl Measurement {
    /// `None` for anything that is not 96 lowercase hex characters, which leaves
    /// the caller with [`LegFailure::Attest`] — a less precise answer rather
    /// than an unbounded one.
    pub fn parse(s: &str) -> Option<Self> {
        let ok = s.len() == 96
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        ok.then(|| Measurement(s.to_string()))
    }
}

impl std::fmt::Display for Measurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Says what happened, not which stage it happened at.
///
/// It used to name the stage — `attest`, `rpc` — and the one line that renders
/// this then had to supply the meaning itself. That line said "not reachable
/// yet" for every variant, which is the one thing certainly untrue of the half
/// of them where the peer answered and the two sides failed to agree. Naming
/// the stage and leaving the meaning to the caller is what let those drift
/// apart; the meaning belongs on the type that knows it.
///
/// The stages are not degrees of one thing. "Nothing answered" and "answered
/// and was refused" call for opposite actions, and that only sharpens as the
/// fleet pins measurements: `Attest` stops being a transport hiccup and becomes
/// how a peer-that-is-the-wrong-image reports itself.
impl std::fmt::Display for LegFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegFailure::Connect(kind) => write!(f, "nothing answered at that address ({kind:?})"),
            LegFailure::Mint => f.write_str(
                "could not attest ITSELF, so nothing was dialled — this end cannot prove \
                 what it is",
            ),
            LegFailure::Attest => f.write_str(
                "answered, but the attested handshake did not complete — one side refused \
                 the other",
            ),
            LegFailure::Pin(m) => write!(
                f,
                "attested to {m}, which this end does not pin — the peer is running an \
                 image this one was not built against"
            ),
            LegFailure::Rpc => {
                f.write_str("attested, but the multiplexed connection did not come up")
            }
            LegFailure::Clients => f.write_str("connected, but the service clients did not cross"),
            LegFailure::Closed => {
                f.write_str("connected, then closed before sending its service clients")
            }
            LegFailure::Serve => f.write_str("had been connected, and stopped being served"),
        }
    }
}

impl std::error::Error for LegFailure {}

// The vouch, made once, next to the `Display` a reviewer has to read anyway:
// every arm above writes a literal, the name of a fieldless variant, or a
// `Measurement` — which is 96 hex characters by construction and names an image
// the host itself launched. What none of them can write is a message, because
// there is no type in this enum that could hold one.
impl safe_logger::SafeToLog for LegFailure {}

/// The connected stream, whichever transport carries it.
#[cfg(not(feature = "vsock"))]
pub type Stream = tokio::net::TcpStream;
#[cfg(feature = "vsock")]
pub type Stream = tokio_vsock::VsockStream;

/// Dial a fleet peer.
///
/// The address is per-transport and opaque to callers:
///   * default (TCP): `host:port`
///   * `vsock`: `vsock://CID:PORT` — CID 2 is the host, which is the only
///     address a guest can reach.
#[cfg(not(feature = "vsock"))]
pub async fn dial(addr: &str) -> std::io::Result<Stream> {
    tokio::net::TcpStream::connect(addr).await
}

#[cfg(feature = "vsock")]
pub async fn dial(addr: &str) -> std::io::Result<Stream> {
    let (cid, port) = parse_vsock(addr)?;
    tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port)).await
}

/// Refuse an address [`dial`] could not use, without dialing it.
///
/// For a caller that is handed addresses long before it dials them, so a
/// malformed one is refused where it was declared rather than failing every
/// request that later reaches it.
///
/// The TCP arm is stricter than [`dial`]: an IP and a port, no host name,
/// because accepting a name would make this check a DNS lookup.
#[cfg(not(feature = "vsock"))]
pub fn check_dial_addr(addr: &str) -> std::io::Result<()> {
    addr.parse::<std::net::SocketAddr>()
        .map(|_| ())
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("expected IP:PORT, got `{addr}`"),
            )
        })
}

#[cfg(feature = "vsock")]
pub fn check_dial_addr(addr: &str) -> std::io::Result<()> {
    parse_vsock(addr).map(|_| ())
}

/// A bound fleet listener.
pub struct Listener {
    #[cfg(not(feature = "vsock"))]
    inner: tokio::net::TcpListener,
    #[cfg(feature = "vsock")]
    inner: tokio_vsock::VsockListener,
}

/// Bind a fleet listener.
///
/// The address is per-transport, mirroring [`dial`]:
///   * default (TCP): `host:port`
///   * `vsock`: a bare `u32` port, bound to any CID — a guest does not know its
///     own CID and does not need to.
#[cfg(not(feature = "vsock"))]
pub async fn bind(addr: &str) -> std::io::Result<Listener> {
    Ok(Listener {
        inner: tokio::net::TcpListener::bind(addr).await?,
    })
}

#[cfg(feature = "vsock")]
pub async fn bind(addr: &str) -> std::io::Result<Listener> {
    let port: u32 = addr.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("vsock listen address must be a bare port, got `{addr}`"),
        )
    })?;
    let vsock_addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port);
    Ok(Listener {
        inner: tokio_vsock::VsockListener::bind(vsock_addr)?,
    })
}

impl Listener {
    /// The connections arriving here, for ever. The only way to take one.
    pub fn incoming(self) -> Incoming {
        Incoming {
            listener: self,
            waiting: None,
        }
    }

    /// One raw accept, error and all. Private: what to do with the error is
    /// [`Incoming`]'s to decide, once, and a public accept would invite every
    /// caller to decide it again.
    ///
    /// Polled rather than awaited because both transports offer it over `&self`,
    /// which is what lets [`Incoming`] hold the listener without a borrow
    /// outliving a single poll.
    fn poll_accept(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<(Stream, String)>> {
        self.inner
            .poll_accept(cx)
            .map_ok(|(stream, peer)| (stream, format!("{peer:?}")))
    }

    /// The address this listener actually bound, as a string a [`dial`] would
    /// accept on the same arm. Only tests call it, to learn which port the OS
    /// chose for port 0; a role never asks, because a role was told its address
    /// by the measured command line.
    pub fn local_addr(&self) -> std::io::Result<String> {
        #[cfg(not(feature = "vsock"))]
        {
            Ok(self.inner.local_addr()?.to_string())
        }
        #[cfg(feature = "vsock")]
        {
            let addr = self.inner.local_addr()?;
            Ok(format!("vsock://{}:{}", addr.cid(), addr.port()))
        }
    }
}

/// How long to wait before accepting again, after an accept that failed for a
/// reason which will not clear on its own.
///
/// A second, which is what axum uses for its own listeners and hyper before it.
/// The exact value barely matters — anything nonzero turns a spin into a poll —
/// but the argument for a long one is what these errors ARE: a process out of
/// descriptors starts accepting again when something else releases one, and
/// asking ten times a second does not make that happen sooner.
const ACCEPT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// One connection, and where it came from.
///
/// The peer is for logging only — it carries no authority, since who the peer
/// IS is settled by whatever handshake runs over the stream, not by its
/// address.
pub struct Accepted {
    pub stream: Stream,
    pub peer: String,
}

/// The connections arriving at one listener.
///
/// This is the one accept loop in the crate; everything that takes connections
/// is a few lines over it — [`accept_forever`] here, `service::serve` for a
/// role driving a `tower` service. What each hand-written loop used to get
/// wrong was never the loop but the error arm, and the error arm is inside this
/// type and nowhere else.
///
/// **It never fails and never ends.** A listener has no end, and what to do
/// with a failed accept is already decided inside this type, so
/// [`Incoming::next`] returns a connection and there is nothing for a caller to
/// handle or to get wrong: a peer that went away is skipped, and a listener
/// that cannot accept at all is waited out and reported.
pub struct Incoming {
    listener: Listener,
    /// Set only while a listener that could not accept AT ALL is being waited
    /// out. Allocated on that path and no other.
    waiting: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl Incoming {
    /// The next connection.
    ///
    /// Safe to drop part-way: nothing is taken off the listener until a
    /// connection is returned, and a wait in progress is kept for the next
    /// call rather than restarted.
    pub async fn next(&mut self) -> Accepted {
        std::future::poll_fn(|cx| self.poll_accepted(cx)).await
    }

    fn poll_accepted(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Accepted> {
        use std::future::Future as _;
        use std::task::Poll;
        loop {
            if let Some(waiting) = self.waiting.as_mut() {
                std::task::ready!(waiting.as_mut().poll(cx));
                self.waiting = None;
            }
            match self.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, peer))) => return Poll::Ready(Accepted { stream, peer }),
                Poll::Ready(Err(e)) => match after_failed_accept(&e) {
                    AfterAccept::Again => continue,
                    AfterAccept::Wait => {
                        self.waiting = Some(Box::pin(tokio::time::sleep(ACCEPT_RETRY_DELAY)));
                    }
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// What to do next after an accept failed.
enum AfterAccept {
    /// Accept again at once.
    Again,
    /// Wait [`ACCEPT_RETRY_DELAY`] first.
    Wait,
}

/// Report an accept failure and say what to do about it. The whole policy.
///
/// # Two kinds of error, wanting opposite treatment
///
/// A connection-level one means the peer went away between its connect and the
/// accept. The queued entry went with it, so the next accept finds the queue
/// shorter and parks normally — try again at once. Nothing is reported outward
/// either: every listener here has the host at the far end, so a connection
/// that died on the way is something the host can already see from its side.
///
/// Anything else is this process running short — descriptors, memory. Usually
/// the kernel could not complete the accept at all, the connection is still
/// queued, the listener stays readable, and a bare retry would fail the same
/// way at once: a spin, and on a role whose `debug!` is compiled out a silent
/// one. Sometimes the kernel did hand the connection over and registering it
/// failed afterwards, in which case that one connection is closed and the next
/// accept would succeed — but waiting is the right answer either way, because
/// the shortage is what caused it. It is also the only accept failure the host
/// cannot observe from its end, which is why this one goes outward where the
/// connection errors do not.
///
/// The line names no role. Each runs in its own guest with its own log device,
/// so which one is speaking is already settled by where the line arrived.
fn after_failed_accept(e: &std::io::Error) -> AfterAccept {
    if is_connection_error(e) {
        safe_logger::debug!("accept: one connection went away: {e}");
        return AfterAccept::Again;
    }
    safe_logger::warn!(
        "accept failed ({:?}); this guest is taking no connections until it clears. \
         Retrying.",
        safe_logger::safe(
            &e.kind(),
            safe_logger::reason!(
                "`std::io::ErrorKind` is a fieldless enum whose `Debug` is its own name"
            )
        ),
        safe_logger::reason!(
            "constant text plus a kind; a guest that cannot accept at all is a state the \
             host has no other way to learn"
        )
    );
    safe_logger::debug!("  cause: {e}");
    AfterAccept::Wait
}

/// Accept for ever, handing each connection to `on_conn`.
///
/// `on_conn` is awaited, which means it holds up the next accept: a handler
/// doing real work must spawn and return. The health port deliberately does
/// not, and its comment says why — staying serial is what keeps a burst of
/// probes from becoming a burst of tasks.
pub async fn accept_forever<F, Fut>(listener: Listener, mut on_conn: F) -> !
where
    F: FnMut(Stream, String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut incoming = listener.incoming();
    loop {
        let Accepted { stream, peer } = incoming.next().await;
        on_conn(stream, peer).await;
    }
}

/// Errors that say one peer went away, not that this listener is in trouble.
/// The same set axum treats this way.
fn is_connection_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

/// `vsock://CID:PORT`.
#[cfg(feature = "vsock")]
fn parse_vsock(addr: &str) -> std::io::Result<(u32, u32)> {
    let invalid = |what: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{what} in `{addr}`; expected vsock://CID:PORT"),
        )
    };
    let rest = addr
        .strip_prefix("vsock://")
        .ok_or_else(|| invalid("missing vsock:// prefix"))?;
    let (cid, port) = rest
        .split_once(':')
        .ok_or_else(|| invalid("missing port"))?;
    Ok((
        cid.parse().map_err(|_| invalid("invalid CID"))?,
        port.parse().map_err(|_| invalid("invalid port"))?,
    ))
}

#[cfg(test)]
mod accept_tests {
    use super::{AfterAccept, after_failed_accept};
    use std::io::{Error, ErrorKind};

    /// What an accept failure leads to — retried at once, or waited on — is
    /// the whole policy, so it is pinned here rather than left to whoever edits
    /// the classification next. The second half is the one that matters: an
    /// `EMFILE`-class error read as a departed peer would spin.
    #[test]
    fn only_a_departed_peer_is_retried_at_once() {
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
        ] {
            let decided = after_failed_accept(&Error::from(kind));
            assert!(matches!(decided, AfterAccept::Again), "{kind:?}");
        }
        // `EMFILE` and `ENFILE` have no stable `ErrorKind` on every toolchain,
        // so they are built from the raw errno the kernel actually returns.
        for raw in [24 /* EMFILE */, 23 /* ENFILE */] {
            let e = Error::from_raw_os_error(raw);
            let decided = after_failed_accept(&e);
            assert!(
                matches!(decided, AfterAccept::Wait),
                "raw {raw} ({:?})",
                e.kind()
            );
        }
        for kind in [ErrorKind::OutOfMemory, ErrorKind::Other] {
            let decided = after_failed_accept(&Error::from(kind));
            assert!(matches!(decided, AfterAccept::Wait), "{kind:?}");
        }
    }
}

#[cfg(all(test, not(feature = "vsock")))]
mod tcp_tests {
    use super::check_dial_addr;

    #[test]
    fn a_socket_address_is_dialable() {
        for good in ["127.0.0.1:8443", "[::1]:80"] {
            assert!(check_dial_addr(good).is_ok(), "refused `{good}`");
        }
    }

    /// A name is refused too, although `dial` would resolve one: checking it
    /// would mean resolving it.
    #[test]
    fn anything_else_is_refused() {
        for bad in [
            "8443",
            ":8443",
            "127.0.0.1:",
            "127.0.0.1:99999",
            "localhost:8443",
            "vsock://2:8001",
        ] {
            assert!(check_dial_addr(bad).is_err(), "accepted `{bad}`");
        }
    }
}

#[cfg(all(test, feature = "vsock"))]
mod tests {
    use super::parse_vsock;

    #[test]
    fn parses_a_host_address() {
        // CID 2 is the host — the only peer a guest can name.
        assert_eq!(parse_vsock("vsock://2:8001").unwrap(), (2, 8001));
    }

    #[test]
    fn rejects_what_is_not_a_vsock_address() {
        for bad in ["127.0.0.1:8001", "vsock://2", "vsock://host:8001", "8001"] {
            assert!(parse_vsock(bad).is_err(), "accepted `{bad}`");
        }
    }
}
