//! The blind splice.
//!
//! One listener, one destination, a copy each way in between. The relay
//! never parses what it carries — that is its security property, and it is a
//! property of the code's *capabilities*, not of its restraint.
//!
//! ## Three transports on each side
//!
//! ```text
//! listen                       destination
//!   unix:<path>                  hybrid:<path>:<port>   unix socket + CONNECT preamble
//!   tcp:<addr>                   vsock:<cid>:<port>     real AF_VSOCK
//!   vsock:<port>                 tcp:<addr>
//! ```
//!
//! Any listener may feed any destination; the splice is transport-agnostic.
//!
//! ## Why `hybrid` exists, and why it is the only thing here that is forced
//!
//! cloud-hypervisor's host-side vsock is **not** `AF_VSOCK`. Its backend is
//! "a mediator between guest-side AF_VSOCK sockets and host-side AF_UNIX
//! sockets" (`virtio-devices/src/vsock/unix/mod.rs`, inherited from Firecracker),
//! and reaching a listener *inside* a guest takes a preamble:
//!
//! ```text
//! host -> guest:  connect(/run/enclavid/api.vsock), send "CONNECT 443\n",
//!                 read back "OK <assigned_port>\n", then splice
//! guest -> host:  the host merely listens on "<socket>_<port>" — no preamble
//! ```
//!
//! That preamble is the one capability no general-purpose proxy offers: a survey
//! of 64 candidate tools found six independent *library* implementations of the
//! handshake (Firecracker SDK, firecracker-containerd, Kata runtime-rs, …) and
//! zero runnable proxies — everyone inlines it, because it is ~25 lines.
//!
//! Every other combination here is ordinary plumbing that off-the-shelf tools can
//! also do. They are implemented anyway so one binary covers a whole deployment
//! whichever hypervisor is underneath, and so every link gets the same graceful
//! drain, the same explicit socket permissions and the same stale-socket
//! handling — none of which a per-connection `fork` gives you.
//!
//! ## Both traffic directions are the same shape
//!
//! It is tempting to model "inbound from the front door" and "outbound from a
//! guest" as two modes. They are one: the relay accepts, then dials. Only the
//! endpoints differ.
//!
//! ```text
//! front door -> unix:/run/enclavid/in.sock        -> hybrid:/run/enclavid/api.vsock:443
//! api CVM    -> unix:/run/enclavid/api.vsock_1027 -> hybrid:/run/enclavid/exec-1.vsock:1024
//! api CVM    -> unix:/run/enclavid/api.vsock_1024 -> tcp:127.0.0.1:8000
//! ```
//!
//! Row 2 reads oddly until you follow the plumbing: the api guest dials
//! `CID 2, port 1027`; cloud-hypervisor turns that into a connection to
//! `<socket>_1027` on the host; the relay is what is listening there.
//!
//! ## No routing table, on purpose
//!
//! One process carries one link. Fan-out across N executors is expressed by
//! running N instances pointed at N guest sockets, so no process holds a map of
//! the deployment — and a compromised relay learns one endpoint, not the
//! topology. How those instances get started is deliberately outside this crate.
//!
//! ## One header, written and never read
//!
//! A guest behind a splice cannot see who dialled: every connection reaches it
//! from the host. An instance that accepts callers itself can be asked to say,
//! with a PROXY protocol v2 header written ahead of the caller's bytes — the
//! gateway shares its places out by that source.
//!
//! The relay WRITES that header and never reads one. Behind a front that writes
//! its own, the option stays off and the front's header is carried like any
//! other byte. Writing one only "if none is there" would need the relay to read
//! what it carries, and would pass on a header a caller wrote itself — naming
//! any address it liked — whenever nothing stood in front of the relay.
//!
//! Two things are then the front's to get right, because the relay cannot:
//!
//!  * the listener must be reachable by that front alone — a caller that
//!    reaches it directly writes a header of its own;
//!  * the front must write its header when it connects, not with the caller's
//!    first bytes. Until a header arrives the guest cannot tell one source from
//!    another, so a caller that connects and says nothing would hold the
//!    guest's places outside any source's share for as long as it stays silent.
//!    This relay writes its own header as soon as it has dialled.
//!
//! Only a TCP listener can write one: a unix or vsock peer has no address such
//! a header carries.
//!
//! ## A closed destination ends the splice
//!
//! Once the destination closes, the caller gets a few seconds to finish
//! (`AFTER_DESTINATION_CLOSES`) and is then let go. The other way round there is no bound: a caller
//! that closes its side is waiting for an answer, and the destination decides
//! how long that takes.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

/// Upper bound on the hypervisor's acknowledgement line (`OK <port>\n`). Real
/// replies are under 16 bytes; the cap keeps a wedged or hostile endpoint from
/// growing the buffer while we hunt for a newline that never arrives.
const MAX_ACK_LINE: usize = 64;

/// Any accepted or dialled connection. Boxed so the 3×3 transport matrix does not
/// have to be spelled out: one vtable hop per connection is invisible next to the
/// copying that follows.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
pub type Stream = Box<dyn Duplex>;

#[cfg(not(target_os = "linux"))]
fn no_vsock<T>() -> io::Result<T> {
    // AF_VSOCK is Linux-only. Parsing still accepts the scheme everywhere so the
    // config shape stays portable and the failure names the real reason.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "AF_VSOCK is only available on Linux; use `hybrid:` under cloud-hypervisor",
    ))
}

/// Where a relay instance listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// `unix:<path>` — a unix socket. Under cloud-hypervisor this is also how a
    /// guest's *outbound* connections arrive: the VMM connects to
    /// `<vm-socket>_<port>`, and the relay is what listens there.
    Unix(PathBuf),
    /// `tcp:<addr>` — an ordinary TCP listener, for a front-end that speaks TCP.
    Tcp(String),
    /// `vsock:<port>` — a real `AF_VSOCK` listener on any CID. Only meaningful on
    /// a VMM that exposes kernel vsock to the host (QEMU `vhost-vsock-pci`), never
    /// under cloud-hypervisor.
    Vsock(u32),
}

/// Where a relay instance sends what it accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// `hybrid:<path>:<port>` — a listener inside a CVM under cloud-hypervisor:
    /// connect to the VM's host-side unix socket, then send `CONNECT <port>`.
    Hybrid { socket: PathBuf, port: u32 },
    /// `vsock:<cid>:<port>` — a listener inside a CVM over real `AF_VSOCK`. No
    /// preamble: the kernel carries the address.
    Vsock { cid: u32, port: u32 },
    /// `tcp:<addr>` — a plain listener on the host, today only `host-hatch`.
    Tcp(String),
}

impl Endpoint {
    /// Parse a `scheme:value` listen spec.
    pub fn parse(spec: &str) -> Result<Self, String> {
        match spec.split_once(':') {
            Some(("unix", path)) if !path.is_empty() => Ok(Self::Unix(PathBuf::from(path))),
            Some(("tcp", addr)) if !addr.is_empty() => Ok(Self::Tcp(addr.to_string())),
            Some(("vsock", port)) => port
                .parse()
                .map(Self::Vsock)
                .map_err(|_| format!("`{port}` is not a vsock port")),
            _ => Err(format!(
                "expected unix:<path>, tcp:<addr> or vsock:<port>, got `{spec}`"
            )),
        }
    }

    /// Bind the listener. `mode` applies only to a unix socket, where filesystem
    /// permissions ARE the isolation boundary: a socket another uid cannot open is
    /// a CVM that uid cannot reach. That makes the mode a security control rather
    /// than cosmetics — too load-bearing to leave to the ambient umask.
    ///
    /// Two residual weaknesses, both deliberately accepted:
    ///
    ///  * the socket is live under the ambient umask for the moment between
    ///    `bind` and `set_permissions`;
    ///  * `set_permissions` re-resolves the path, so a uid that can create names
    ///    in the directory could swap in a symlink and redirect the chmod.
    ///
    /// Narrowing the umask around `bind` closes both, and was tried — but umask is
    /// process-global, so a library call that moves it races every other file
    /// created anywhere in the process. Trading a local hazard for a global one is
    /// the wrong direction. Both residuals also presuppose write access to the
    /// socket's directory, and an attacker with that can simply bind the path
    /// first and intercept the link outright — so the directory's own permissions
    /// are the real control, and this mode is the second layer.
    pub async fn bind(&self, mode: u32) -> io::Result<Listener> {
        match self {
            Self::Unix(path) => {
                reclaim_stale_socket(path).await?;
                let listener = UnixListener::bind(path)?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
                Ok(Listener::Unix(listener))
            }
            Self::Tcp(addr) => Ok(Listener::Tcp(TcpListener::bind(addr).await?)),
            #[cfg(target_os = "linux")]
            Self::Vsock(port) => {
                let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, *port);
                Ok(Listener::Vsock(tokio_vsock::VsockListener::bind(addr)?))
            }
            #[cfg(not(target_os = "linux"))]
            Self::Vsock(_) => no_vsock(),
        }
    }
}

impl Destination {
    /// Parse a `scheme:value` destination spec.
    pub fn parse(spec: &str) -> Result<Self, String> {
        match spec.split_once(':') {
            // Resolved at parse time, not at first connection: an unresolvable
            // address would otherwise pass startup and then fail once per client
            // forever, which reads as a network fault rather than a typo.
            Some(("tcp", addr)) if !addr.is_empty() => {
                use std::net::ToSocketAddrs;
                addr.to_socket_addrs()
                    .map_err(|e| format!("`{addr}` does not resolve: {e}"))?
                    .next()
                    .ok_or_else(|| format!("`{addr}` resolved to no address"))?;
                Ok(Self::Tcp(addr.to_string()))
            }
            // Split the port off the RIGHT so a path may contain colons.
            Some(("hybrid", rest)) => {
                let (path, port) = rest
                    .rsplit_once(':')
                    .ok_or_else(|| format!("expected hybrid:<path>:<port>, got `{spec}`"))?;
                if path.is_empty() {
                    return Err(format!("empty socket path in `{spec}`"));
                }
                Ok(Self::Hybrid {
                    socket: PathBuf::from(path),
                    port: port
                        .parse()
                        .map_err(|_| format!("`{port}` is not a vsock port"))?,
                })
            }
            Some(("vsock", rest)) => {
                let (cid, port) = rest
                    .split_once(':')
                    .ok_or_else(|| format!("expected vsock:<cid>:<port>, got `{spec}`"))?;
                let cid: u32 = cid.parse().map_err(|_| format!("`{cid}` is not a CID"))?;
                let port: u32 = port
                    .parse()
                    .map_err(|_| format!("`{port}` is not a vsock port"))?;
                // u32::MAX is the kernel's VMADDR_CID_ANY / VMADDR_PORT_ANY
                // sentinel, not an address — dialling it would silently mean
                // something other than what was written.
                if cid == u32::MAX || port == u32::MAX {
                    return Err(format!("`{spec}` uses the ANY sentinel as an address"));
                }
                Ok(Self::Vsock { cid, port })
            }
            _ => Err(format!(
                "expected hybrid:<path>:<port>, vsock:<cid>:<port> or tcp:<addr>, got `{spec}`"
            )),
        }
    }

    /// Open a connection to this destination.
    pub async fn connect(&self) -> io::Result<Stream> {
        match self {
            Self::Hybrid { socket, port } => Ok(Box::new(connect_hybrid(socket, *port).await?)),
            Self::Tcp(addr) => Ok(Box::new(TcpStream::connect(addr).await?)),
            #[cfg(target_os = "linux")]
            Self::Vsock { cid, port } => {
                let addr = tokio_vsock::VsockAddr::new(*cid, *port);
                Ok(Box::new(tokio_vsock::VsockStream::connect(addr).await?))
            }
            #[cfg(not(target_os = "linux"))]
            Self::Vsock { .. } => no_vsock(),
        }
    }
}

/// A bound listener, whatever transport it came from.
pub enum Listener {
    Unix(UnixListener),
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockListener),
}

// Named by transport only: the inner handles carry no information worth logging,
// and a manual impl avoids depending on the vsock crate deriving `Debug`.
impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unix(_) => "Listener::Unix",
            Self::Tcp(_) => "Listener::Tcp",
            #[cfg(target_os = "linux")]
            Self::Vsock(_) => "Listener::Vsock",
        })
    }
}

impl Listener {
    /// One connection, with its two ends when it has addresses a PROXY header
    /// can carry — which only TCP does.
    pub async fn accept(&self) -> io::Result<(Stream, Option<Ends>)> {
        match self {
            Self::Unix(l) => Ok((Box::new(l.accept().await?.0), None)),
            Self::Tcp(l) => {
                let (stream, source) = l.accept().await?;
                let destination = stream.local_addr()?;
                Ok((
                    Box::new(stream),
                    Some(Ends {
                        source,
                        destination,
                    }),
                ))
            }
            #[cfg(target_os = "linux")]
            Self::Vsock(l) => Ok((Box::new(l.accept().await?.0), None)),
        }
    }
}

/// Who dialled a TCP listener, and the address it dialled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ends {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// A PROXY protocol v2 header naming `ends`: version 2, the PROXY command, TCP.
///
/// An IPv4 caller of a dual-stack listener arrives as a mapped IPv6 address,
/// and is written as the IPv4 address it is — the one a reader sharing places
/// out by source should see. Two ends of different families, which the
/// protocol cannot write as such, are both written as IPv6.
pub fn proxy_header(ends: Ends) -> Vec<u8> {
    use ppp::v2::{Builder, Command, Protocol, Version};

    let canonical = |end: SocketAddr| SocketAddr::new(end.ip().to_canonical(), end.port());
    let pair = match (canonical(ends.source), canonical(ends.destination)) {
        pair @ (SocketAddr::V4(_), SocketAddr::V4(_)) => pair,
        (source, destination) => (as_v6(source), as_v6(destination)),
    };
    Builder::with_addresses(Version::Two | Command::Proxy, Protocol::Stream, pair)
        .build()
        .expect("an address block without records always fits a header")
}

fn as_v6(end: SocketAddr) -> SocketAddr {
    match end.ip() {
        IpAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), end.port()),
        IpAddr::V6(_) => end,
    }
}

/// Clear a unix socket left behind by a crash, with two guards before unlinking:
///
///  * the path must actually be a socket — otherwise a typo'd listen spec would
///    have this process delete an unrelated file on startup;
///  * nobody may be serving it — a successful connect means a live relay owns the
///    path, and stealing it would silently blackhole its traffic.
///
/// This reclaim is also the *only* cleanup that matters. Unlinking on shutdown
/// looks tidier but cannot be relied on (SIGKILL, panic, power loss all skip it)
/// and races a fast restart, where the exiting process would delete the socket its
/// own replacement had already bound.
async fn reclaim_stale_socket(path: &Path) -> io::Result<()> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !meta.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a socket", path.display()),
        ));
    }
    match UnixStream::connect(path).await {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("{} is already served by a live listener", path.display()),
        )),
        // ONLY a refused connect proves nobody is home. Every other errno means we
        // failed to reach a socket that may well be serving: EACCES because it
        // belongs to another uid, EAGAIN because a busy listener's accept queue is
        // momentarily full, EMFILE because we are out of descriptors. Treating
        // those as "stale" would unlink a live socket and silently blackhole the
        // instance still running on it — the exact outcome the check above exists
        // to prevent. Surface them instead.
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => std::fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!(
                "cannot determine whether {} is live ({e}); refusing to unlink it",
                path.display()
            ),
        )),
    }
}

/// How long the hypervisor gets to acknowledge a `CONNECT`. A healthy muxer
/// answers in microseconds; the bound exists so a destination that accepts and
/// then goes silent cannot park a task and two descriptors indefinitely.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Open a connection to a listener inside a CVM over the hybrid vsock protocol.
pub async fn connect_hybrid(socket: &Path, port: u32) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket).await?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        stream
            .write_all(format!("CONNECT {port}\n").as_bytes())
            .await?;
        read_ack(&mut stream).await
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "hypervisor did not acknowledge CONNECT in time",
        )
    })??;
    Ok(stream)
}

/// Consume the `OK <assigned_port>\n` acknowledgement, **one byte at a time**.
///
/// Deliberately not `BufReader::lines()`. A buffered reader fills in blocks, so
/// it can pull bytes that belong to the spliced stream into its buffer and then
/// discard them when it is dropped. An HTTP *client* survives that — it speaks
/// first, so nothing follows the ack — but a relay does not: whichever side
/// speaks first is not ours to decide. The published Rust implementation of this
/// handshake (`hyper-client-sockets`) has exactly that shape, which is why this is
/// written out rather than depended on.
///
/// One byte at a time costs a handful of syscalls once per connection, against an
/// unbounded correctness hazard. Not a tradeoff worth optimising.
async fn read_ack<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut line = Vec::with_capacity(MAX_ACK_LINE);
    let mut byte = [0u8; 1];

    loop {
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "hypervisor closed the connection before acknowledging CONNECT",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() == MAX_ACK_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hypervisor acknowledgement exceeded the line bound",
            ));
        }
        line.push(byte[0]);
    }

    // "OK <port>" on success; anything else means no listener on that guest port.
    if line.starts_with(b"OK") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "hypervisor refused CONNECT: {}",
                String::from_utf8_lossy(&line)
            ),
        ))
    }
}

/// Would this pair make the relay dial itself?
///
/// Pointing a link at its own listen address turns one client connection into an
/// unbounded chain of self-connections: the relay accepts, dials itself, accepts
/// that, dials again, until descriptors run out. Cheap to catch at startup, and
/// otherwise only noticed as a mysterious fd exhaustion.
///
/// Exact-address comparison only — it catches the configuration people actually
/// write, not every alias (a symlink or a second bind address still gets through).
pub fn is_self_referential(listen: &Endpoint, to: &Destination) -> bool {
    match (listen, to) {
        (Endpoint::Unix(a), Destination::Hybrid { socket: b, .. }) => a == b,
        (Endpoint::Tcp(a), Destination::Tcp(b)) => a == b,
        _ => false,
    }
}

/// How long a caller may go on sending once the destination has closed.
///
/// A destination that has closed is done: nothing sent to it afterwards is
/// answered. Waiting for the caller to close as well would let one that never
/// does hold a task and two descriptors here for ever — and a relay that
/// accepts callers directly would run out of descriptors for everyone.
#[cfg(not(test))]
const AFTER_DESTINATION_CLOSES: Duration = Duration::from_secs(5);
#[cfg(test)]
const AFTER_DESTINATION_CLOSES: Duration = Duration::from_millis(200);

/// Dial `dest`, write `header` there first if there is one, and splice
/// `inbound` to it until the destination is done — see
/// `AFTER_DESTINATION_CLOSES` for when that is.
pub async fn serve_connection(
    inbound: Stream,
    dest: &Destination,
    header: Option<Vec<u8>>,
) -> io::Result<()> {
    let mut outbound = dest.connect().await?;
    if let Some(header) = header {
        outbound.write_all(&header).await?;
    }
    let (mut from_caller, mut to_caller) = tokio::io::split(inbound);
    let (mut from_destination, mut to_destination) = tokio::io::split(outbound);
    let up = async {
        tokio::io::copy(&mut from_caller, &mut to_destination).await?;
        to_destination.shutdown().await
    };
    let down = async {
        tokio::io::copy(&mut from_destination, &mut to_caller).await?;
        to_caller.shutdown().await
    };
    tokio::pin!(up, down);
    tokio::select! {
        ended = &mut up => {
            ended?;
            down.await
        }
        ended = &mut down => {
            ended?;
            tokio::time::timeout(AFTER_DESTINATION_CLOSES, up)
                .await
                .unwrap_or(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_specs_parse() {
        assert_eq!(
            Endpoint::parse("unix:/run/enclavid/in.sock").unwrap(),
            Endpoint::Unix(PathBuf::from("/run/enclavid/in.sock"))
        );
        assert_eq!(
            Endpoint::parse("tcp:127.0.0.1:8443").unwrap(),
            Endpoint::Tcp("127.0.0.1:8443".into())
        );
        assert_eq!(
            Endpoint::parse("vsock:1027").unwrap(),
            Endpoint::Vsock(1027)
        );

        for bad in ["", "unix:", "nope:/x", "/run/x.sock", "vsock:abc"] {
            assert!(Endpoint::parse(bad).is_err(), "`{bad}` should not parse");
        }
    }

    #[test]
    fn destination_specs_parse() {
        assert_eq!(
            Destination::parse("hybrid:/run/enclavid/api.vsock:443").unwrap(),
            Destination::Hybrid {
                socket: PathBuf::from("/run/enclavid/api.vsock"),
                port: 443
            }
        );
        assert_eq!(
            Destination::parse("vsock:3:443").unwrap(),
            Destination::Vsock { cid: 3, port: 443 }
        );
        assert_eq!(
            Destination::parse("tcp:127.0.0.1:8000").unwrap(),
            Destination::Tcp("127.0.0.1:8000".into())
        );

        for bad in [
            "hybrid:/run/x.sock",
            "hybrid::443",
            "vsock:3",
            "nope:x",
            "",
            // The ANY sentinel is not an address.
            "vsock:4294967295:443",
            "vsock:3:4294967295",
            // A destination that cannot resolve must fail at startup, not once
            // per connection forever.
            "tcp:not a host:1",
        ] {
            assert!(Destination::parse(bad).is_err(), "`{bad}` should not parse");
        }
    }

    /// The port is split off the right, so a colon in the path survives.
    #[test]
    fn hybrid_path_may_contain_a_colon() {
        assert_eq!(
            Destination::parse("hybrid:/run/od:d/api.vsock:443").unwrap(),
            Destination::Hybrid {
                socket: PathBuf::from("/run/od:d/api.vsock"),
                port: 443
            }
        );
    }

    /// Stand in for cloud-hypervisor's host-side vsock socket: read a `CONNECT`
    /// line, answer `ack`, then echo whatever follows back to the caller.
    async fn fake_hypervisor(path: PathBuf, ack: &'static str) -> tokio::task::JoinHandle<Vec<u8>> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                sock.read_exact(&mut byte).await.unwrap();
                if byte[0] == b'\n' {
                    break;
                }
                request.push(byte[0]);
            }
            sock.write_all(ack.as_bytes()).await.unwrap();
            // Everything after the ack belongs to the spliced stream.
            let mut rest = Vec::new();
            let _ = sock.read_to_end(&mut rest).await;
            request.extend_from_slice(b"|");
            request.extend_from_slice(&rest);
            request
        })
    }

    #[tokio::test]
    async fn sends_connect_preamble_and_accepts_ok() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ch.vsock");
        let server = fake_hypervisor(sock.clone(), "OK 1077\n").await;

        let mut client = connect_hybrid(&sock, 443).await.unwrap();
        client.write_all(b"payload").await.unwrap();
        client.shutdown().await.unwrap();

        assert_eq!(server.await.unwrap(), b"CONNECT 443|payload");
    }

    /// The regression this crate exists to avoid: a buffered reader would pull
    /// `payload` into its own buffer alongside the ack and drop it. Byte-at-a-time
    /// leaves the stream positioned exactly after the newline.
    #[tokio::test]
    async fn does_not_swallow_bytes_that_follow_the_ack() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ch.vsock");
        // Ack and first payload bytes arrive in ONE write — the interleaving a
        // block-buffered reader mishandles.
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            loop {
                s.read_exact(&mut byte).await.unwrap();
                if byte[0] == b'\n' {
                    break;
                }
            }
            s.write_all(b"OK 1077\nHELLO-FROM-GUEST").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut client = connect_hybrid(&sock, 443).await.unwrap();
        let mut seen = Vec::new();
        client.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"HELLO-FROM-GUEST", "ack consumed part of the stream");
    }

    #[tokio::test]
    async fn refusal_is_an_error_not_a_splice() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ch.vsock");
        let _server = fake_hypervisor(sock.clone(), "ERROR bad port\n").await;

        let err = connect_hybrid(&sock, 9).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn unterminated_ack_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ch.vsock");
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            loop {
                s.read_exact(&mut byte).await.unwrap();
                if byte[0] == b'\n' {
                    break;
                }
            }
            // No newline, ever.
            s.write_all(&vec![b'K'; MAX_ACK_LINE * 4]).await.unwrap();
            let mut park = Vec::new();
            let _ = s.read_to_end(&mut park).await;
        });

        let err = connect_hybrid(&sock, 443).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn stale_socket_is_reclaimed_but_live_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.sock");
        let ep = Endpoint::Unix(path.clone());

        // Dropping a listener does NOT unlink its path, so this leaves exactly
        // what a SIGKILLed relay leaves: a socket file with nobody behind it.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists(), "precondition: a stale socket is left behind");

        let live = ep.bind(0o600).await.unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // A second bind must refuse rather than steal the path from `live`.
        let err = ep.bind(0o600).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        drop(live);
    }

    /// A typo'd listen spec must not make this process delete an unrelated file.
    #[tokio::test]
    async fn non_socket_path_is_refused_not_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("important.conf");
        std::fs::write(&path, b"do not delete me").unwrap();

        let err = Endpoint::Unix(path.clone()).bind(0o600).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"do not delete me");
    }

    #[test]
    fn a_link_pointed_at_itself_is_rejected() {
        let sock = PathBuf::from("/run/enclavid/api.vsock");
        assert!(is_self_referential(
            &Endpoint::Unix(sock.clone()),
            &Destination::Hybrid {
                socket: sock.clone(),
                port: 443
            }
        ));
        assert!(is_self_referential(
            &Endpoint::Tcp("127.0.0.1:9000".into()),
            &Destination::Tcp("127.0.0.1:9000".into())
        ));
        // The real configurations must still pass: the hybrid destination is the
        // VM's socket, never the path the relay accepts on.
        assert!(!is_self_referential(
            &Endpoint::Unix(PathBuf::from("/run/enclavid/api.vsock_1027")),
            &Destination::Hybrid {
                socket: sock,
                port: 1024
            }
        ));
    }

    /// A destination that accepts and then says nothing must not park the task.
    #[tokio::test(start_paused = true)]
    async fn silent_destination_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ch.vsock");
        let listener = UnixListener::bind(&sock).unwrap();
        let _held = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            // Accept, never answer, never close.
            std::future::pending::<()>().await;
            drop(s);
        });

        // Time is paused (`start_paused`), so the runtime auto-advances to the
        // handshake deadline the moment nothing else can make progress — the test
        // proves the bound exists without actually waiting for it.
        let err = connect_hybrid(&sock, 443).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// The preamble-free path: unix in, TCP out — plain forwarding, no handshake.
    #[tokio::test]
    async fn splices_without_a_preamble() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            s.write_all(&buf).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("in.sock");
        let listener = Endpoint::Unix(path.clone()).bind(0o600).await.unwrap();
        let dest = Destination::Tcp(echo_addr);
        tokio::spawn(async move {
            let (inbound, ends) = listener.accept().await.unwrap();
            assert_eq!(ends, None, "a unix peer has no address to name");
            serve_connection(inbound, &dest, None).await.unwrap();
        });

        let mut client = UnixStream::connect(&path).await.unwrap();
        client.write_all(b"round-trip").await.unwrap();
        client.shutdown().await.unwrap();
        let mut back = Vec::new();
        client.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"round-trip");
    }

    /// Each family is named as it is, an IPv4 caller of a dual-stack listener
    /// as the IPv4 address it is, and two ends of different families both as
    /// IPv6 — never as no address at all.
    #[test]
    fn both_ends_are_named_in_one_family() {
        use ppp::v2::{Addresses, Command, Header, Protocol};

        for (source, destination, expected) in [
            (
                "192.0.2.7:40000",
                "198.51.100.1:443",
                ("192.0.2.7:40000", "198.51.100.1:443"),
            ),
            (
                "[2001:db8::7]:40000",
                "[2001:db8::1]:443",
                ("[2001:db8::7]:40000", "[2001:db8::1]:443"),
            ),
            (
                "[::ffff:192.0.2.7]:40000",
                "[::ffff:198.51.100.1]:443",
                ("192.0.2.7:40000", "198.51.100.1:443"),
            ),
            (
                "192.0.2.7:40000",
                "[2001:db8::1]:443",
                ("[::ffff:192.0.2.7]:40000", "[2001:db8::1]:443"),
            ),
        ] {
            let ends = Ends {
                source: source.parse().unwrap(),
                destination: destination.parse().unwrap(),
            };
            let written = proxy_header(ends);
            let read = Header::try_from(written.as_slice()).unwrap();
            assert_eq!(read.command, Command::Proxy);
            assert_eq!(read.protocol, Protocol::Stream);
            assert_eq!(read.len(), written.len(), "nothing trails the header");
            let expected: Addresses = (
                expected.0.parse::<SocketAddr>().unwrap(),
                expected.1.parse::<SocketAddr>().unwrap(),
            )
                .into();
            assert_eq!(read.addresses, expected, "{source}");
        }
    }

    /// A caller that stays open and silent is let go once the destination has
    /// closed, instead of holding the splice for as long as it likes.
    #[tokio::test]
    async fn a_silent_caller_is_let_go_once_the_destination_closes() {
        let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest = Destination::Tcp(sink.local_addr().unwrap().to_string());
        tokio::spawn(async move {
            let (closing, _) = sink.accept().await.unwrap();
            drop(closing);
        });

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _silent = TcpStream::connect(front.local_addr().unwrap())
            .await
            .unwrap();
        let (inbound, _) = front.accept().await.unwrap();
        let splice =
            tokio::spawn(async move { serve_connection(Box::new(inbound), &dest, None).await });

        tokio::time::timeout(AFTER_DESTINATION_CLOSES * 10, splice)
            .await
            .expect("the splice ends although the caller never closed")
            .unwrap()
            .unwrap();
    }

    /// The other way round there is no such bound: a caller that has closed its
    /// side is waiting for an answer, and gets it however long it takes.
    #[tokio::test]
    async fn a_caller_that_closes_first_still_gets_its_answer() {
        let slow = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest = Destination::Tcp(slow.local_addr().unwrap().to_string());
        tokio::spawn(async move {
            let (mut s, _) = slow.accept().await.unwrap();
            let mut asked = Vec::new();
            s.read_to_end(&mut asked).await.unwrap();
            tokio::time::sleep(AFTER_DESTINATION_CLOSES * 3).await;
            s.write_all(&asked).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(front.local_addr().unwrap())
            .await
            .unwrap();
        let (inbound, _) = front.accept().await.unwrap();
        tokio::spawn(async move { serve_connection(Box::new(inbound), &dest, None).await });

        client.write_all(b"a question").await.unwrap();
        client.shutdown().await.unwrap();
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.unwrap();
        assert_eq!(answer, b"a question");
    }

    /// End to end: a TCP caller is named to the destination ahead of its own
    /// bytes, which follow untouched.
    #[tokio::test]
    async fn a_tcp_caller_is_named_ahead_of_its_bytes() {
        let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = sink.local_addr().unwrap().to_string();
        let received = tokio::spawn(async move {
            let (mut s, _) = sink.accept().await.unwrap();
            let mut all = Vec::new();
            s.read_to_end(&mut all).await.unwrap();
            all
        });

        let listener = Endpoint::Tcp("127.0.0.1:0".into())
            .bind(0o600)
            .await
            .unwrap();
        let Listener::Tcp(ref tcp) = listener else {
            unreachable!("a tcp endpoint binds a tcp listener")
        };
        let relay_addr = tcp.local_addr().unwrap();
        let dest = Destination::Tcp(sink_addr);
        tokio::spawn(async move {
            let (inbound, ends) = listener.accept().await.unwrap();
            serve_connection(inbound, &dest, ends.map(proxy_header))
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let caller = client.local_addr().unwrap();
        client.write_all(b"the caller's bytes").await.unwrap();
        client.shutdown().await.unwrap();

        let all = received.await.unwrap();
        let header = ppp::v2::Header::try_from(all.as_slice()).unwrap();
        assert_eq!(
            header.addresses,
            ppp::v2::Addresses::from((caller, relay_addr))
        );
        assert_eq!(&all[header.len()..], b"the caller's bytes");
    }
}
