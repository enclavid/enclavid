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

#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!(
    "feature `vsock` requires Linux — AF_VSOCK exists only in the Linux kernel. Build \
     without it for non-Linux dev environments."
);

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
