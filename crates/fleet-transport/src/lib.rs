//! The intra-fleet transport: the byte stream api's dials and its peers'
//! listeners run RA-TLS over.
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

#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!(
    "feature `vsock` requires Linux — AF_VSOCK exists only in the Linux kernel. Build \
     without it for non-Linux dev environments."
);

/// Why a fleet leg failed, in terms that carry nothing out of a message.
///
/// Every field is a closed enum or nothing at all — there is no `String` here,
/// and that is the whole design. A `String` inside an error is the same
/// unbounded content as a `String` in a log line: it can hold what a foreign
/// `Display` chose to say, and no one re-reads those on a dependency bump.
/// Without one, [`safe_logger::SafeToLog`] below is true of the TYPE, so a log
/// site needs no judgement and no reason of its own.
///
/// What is given up is the underlying message. It is not lost — the conversion
/// site sends it to `debug!`, which never leaves the TEE — but production sees
/// the stage and the kind, not the text. That is the trade: a stage and an
/// `ErrorKind` are worth having in front of an operator, and a sentence from
/// rustls or remoc is worth having only in front of a developer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegFailure {
    /// Nothing answered, or the connection died before TLS. The kind is
    /// `std::io::ErrorKind`, a fieldless enum whose `Debug` is its own name.
    Connect(std::io::ErrorKind),
    /// The RA-TLS handshake did not complete — either peer refusing the other's
    /// attestation, or an ordinary TLS failure.
    Attest,
    /// remoc could not bring the multiplexed connection up over the stream.
    Rpc,
    /// The connection came up but the service clients did not cross it.
    Clients,
    /// The peer closed before sending its service clients.
    Closed,
    /// An established connection stopped being served.
    Serve,
}

impl std::fmt::Display for LegFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegFailure::Connect(kind) => write!(f, "connect: {kind:?}"),
            LegFailure::Attest => f.write_str("attest"),
            LegFailure::Rpc => f.write_str("rpc"),
            LegFailure::Clients => f.write_str("clients"),
            LegFailure::Closed => f.write_str("closed before sending clients"),
            LegFailure::Serve => f.write_str("serve"),
        }
    }
}

impl std::error::Error for LegFailure {}

// The vouch, made once, next to the `Display` a reviewer has to read anyway:
// every arm above writes a literal or the name of a fieldless variant, so there
// is nothing here that a message could have put in.
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
    /// Accept one connection. The second element is the peer, for logging only —
    /// it carries no authority, since who the peer IS is settled by the RA-TLS
    /// handshake that runs over the stream, not by its address.
    pub async fn accept(&mut self) -> std::io::Result<(Stream, String)> {
        let (stream, peer) = self.inner.accept().await?;
        Ok((stream, format!("{peer:?}")))
    }

    /// The address this listener actually bound, as a string a [`dial`] would
    /// accept on the same arm. Its one caller is a test that binds port 0 and
    /// needs to know what the OS chose; a role never asks, because a role was
    /// told its address by the measured command line.
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
