//! One server: its key exchange, then its time packets for as long as they
//! last, and then the same again.
//!
//! Both go through the host, on the two vsock ports the server list gives it,
//! and the host is trusted with neither. The key exchange is TLS that ends
//! here, checked against the compiled-in roots; it agrees the keys every time
//! packet is then authenticated with. What the host can do is not deliver.
//!
//! The time packets cross a vsock STREAM, since vsock carries no datagrams,
//! each prefixed with its length as two big-endian bytes. The relay on the far
//! side reads the same framing and sends each packet as one UDP datagram.

use std::sync::Arc;
use std::time::Duration;

use ntp_proto::{
    KeyExchangeClient, KeyExchangeResult, NtpClock, NtpInstant, NtpSourceAction, NtpTimestamp,
    NtsClientConfig, ProtocolVersion, tls_utils::Certificate,
};
use rustls::pki_types::CertificateDer;
use safe_logger::{debug, reason, safe, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;

use crate::clock::SystemClock;
use crate::servers::Server;
use crate::system::{Created, Request, Source, SourceActions, SourceId, SystemUpdate};

/// How long a key exchange may take, from the dial to the last record. A
/// server across an ocean answers in well under a second.
const KEY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The wait after a server stops, doubled each time it stops again soon, up to
/// the second. A server that kept answering for [`SETTLED`] starts over at the
/// first.
const FIRST_RETRY: Duration = Duration::from_secs(10);
const LAST_RETRY: Duration = Duration::from_secs(600);
const SETTLED: Duration = Duration::from_secs(3600);

/// The port every NTS server here sends time packets from, and so the one its
/// key exchange has to name: the relay for them is fixed when it starts.
const TIME_PORT: u16 = 123;

/// How long one time packet may take to hand to the host. ntp-proto takes an
/// answer only within 5 s of its request, so a packet the host has held longer
/// is lost either way; and the host decides how much a guest may send, so
/// without a bound it could hold a source here, between polls, for good.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a server stopped serving this guest's clock, in words of this crate's
/// own — never a message a library or a server wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// Nothing answered on the host's port for it.
    Connect(std::io::ErrorKind),
    /// The key exchange did not finish in time.
    TimedOut,
    /// Something answered and the key exchange failed: the TLS handshake — a
    /// certificate that does not chain to the roots among the causes — or the
    /// records after it.
    KeyExchange,
    /// The key exchange named a different server for time packets than the
    /// one it was, which the relay for them does not reach.
    NamedElsewhere,
    /// The source missed corrections the system made to the clock, which it
    /// keeps its own estimate in step with: its estimate no longer is.
    Behind,
    /// The server stopped answering time packets.
    Unreachable,
    /// The server asked not to be asked again.
    Refused,
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stop::Connect(kind) => {
                write!(f, "nothing answered on the host's port for it ({kind:?})")
            }
            Stop::TimedOut => f.write_str("the key exchange did not finish in time"),
            Stop::KeyExchange => f.write_str("the key exchange failed"),
            Stop::NamedElsewhere => {
                f.write_str("the key exchange named another server for time packets")
            }
            Stop::Behind => f.write_str("it missed corrections to the clock"),
            Stop::Unreachable => f.write_str("it stopped answering time packets"),
            Stop::Refused => f.write_str("it asked not to be asked again"),
        }
    }
}

// Every arm above writes a literal or the name of an `ErrorKind`, a fieldless
// enum: nothing a server or a library chose can reach the line.
impl safe_logger::SafeToLog for Stop {}

/// Keep one server's time coming, for ever.
pub async fn keep(
    server: Server,
    roots: Arc<[CertificateDer<'static>]>,
    system: mpsc::Sender<Request>,
) {
    let certificates: Arc<[Certificate]> = roots;
    let client = KeyExchangeClient::new(&NtsClientConfig {
        certificates,
        // NTPv4, the version RFC 8915 defines NTS for. ntp-proto would also
        // offer its draft NTPv5, which no server on the list needs.
        protocol_version: ProtocolVersion::V4,
    })
    .expect("the compiled-in roots make a TLS client");

    let mut retry = FIRST_RETRY;
    loop {
        let started = Instant::now();
        let stop = match exchange(&server, &client).await {
            Ok(ke) => serve(&server, ke, &system).await,
            Err(stop) => stop,
        };
        warn!(
            "timesync: {}: {}",
            safe(
                &server.name,
                reason!("a server name compiled into the image")
            ),
            stop,
            reason!("at most once per retry wait, which doubles while a server keeps failing"),
        );
        if started.elapsed() >= SETTLED {
            retry = FIRST_RETRY;
        }
        tokio::time::sleep(retry).await;
        retry = (retry * 2).min(LAST_RETRY);
    }
}

async fn exchange(server: &Server, client: &KeyExchangeClient) -> Result<KeyExchangeResult, Stop> {
    let stream = fleet_transport::dial(&host_address(server.port))
        .await
        .map_err(|e| Stop::Connect(e.kind()))?;
    let ke = tokio::time::timeout(
        KEY_EXCHANGE_TIMEOUT,
        client.exchange_keys(stream, server.name.to_string(), []),
    )
    .await
    .map_err(|_| Stop::TimedOut)?
    .map_err(|e| {
        debug!("timesync: {}: {e}", server.name);
        Stop::KeyExchange
    })?;
    if ke.remote != server.name || ke.port != TIME_PORT {
        debug!(
            "timesync: {}: named {}:{} for time packets",
            server.name, ke.remote, ke.port
        );
        return Err(Stop::NamedElsewhere);
    }
    Ok(ke)
}

/// Run the source a key exchange made until it stops, and tell the system.
async fn serve(server: &Server, ke: KeyExchangeResult, system: &mpsc::Sender<Request>) -> Stop {
    let (reply, created) = oneshot::channel();
    system
        .send(Request::Create { ke, reply })
        .await
        .expect("the system outlives every source");
    let Created {
        id,
        source,
        actions,
        updates,
    } = created
        .await
        .expect("the system answers every request to create");
    let stop = poll(server, id, source, actions, updates, system).await;
    system
        .send(Request::Remove(id))
        .await
        .expect("the system outlives every source");
    stop
}

async fn poll(
    server: &Server,
    id: SourceId,
    mut source: Source,
    mut actions: SourceActions,
    mut updates: broadcast::Receiver<SystemUpdate>,
    system: &mpsc::Sender<Request>,
) -> Stop {
    // A fresh one for every packet sent; see the `Send` arm.
    let mut carrier: Option<Carrier> = None;
    let mut sent: Option<NtpTimestamp> = None;
    let timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(timer);
    let mut armed = false;

    loop {
        for action in actions {
            match action {
                NtpSourceAction::Send(packet) => {
                    // Each packet on a stream of its own, and so from a socket
                    // and port of its own on the host, as chrony sends by
                    // default. Some servers stop answering one flow for a
                    // while, and a source that kept its flow would wait it
                    // out; a late answer to the packet before was one the
                    // source would discard anyway.
                    let opened = match Carrier::open(server.time_port()).await {
                        Ok(opened) => opened,
                        Err(e) => return Stop::Connect(e.kind()),
                    };
                    let writer = &mut carrier.insert(opened).writer;
                    sent = Some(now());
                    // A packet the host would not take is a packet lost, as
                    // one it took and never delivered is: the source counts
                    // the poll unanswered, and enough of those end it.
                    let written =
                        tokio::time::timeout(WRITE_TIMEOUT, write_frame(writer, &packet)).await;
                    if !matches!(written, Ok(Ok(()))) {
                        carrier = None;
                    }
                }
                NtpSourceAction::UpdateSystem(update) => system
                    .send(Request::Update(id, Box::new(update)))
                    .await
                    .expect("the system outlives every source"),
                NtpSourceAction::SetTimer(after) => {
                    timer.as_mut().reset(Instant::now() + after);
                    armed = true;
                }
                NtpSourceAction::Reset => return Stop::Unreachable,
                NtpSourceAction::Demobilize => return Stop::Refused,
            }
        }
        actions = tokio::select! {
            () = &mut timer, if armed => {
                armed = false;
                source.handle_timer()
            }
            update = updates.recv() => match update {
                Ok(update) => source.handle_system_update(update),
                // Each message is a correction — a step, a change of rate —
                // the source applies to its own estimate, not a state; one
                // missed leaves the estimate off by it for good. A fresh
                // source, after a fresh key exchange, starts level.
                Err(broadcast::error::RecvError::Lagged(_)) => return Stop::Behind,
                Err(broadcast::error::RecvError::Closed) => {
                    unreachable!("the system outlives every source")
                }
            },
            packet = next_packet(&mut carrier) => match (packet, sent) {
                (Some((packet, received)), Some(sent)) => {
                    source.handle_incoming(&packet, NtpInstant::now(), sent, received)
                }
                // A packet before any was sent answers nothing.
                (Some(_), None) => SourceActions::default(),
                // The host closed the stream: no answer to this packet, which
                // is all a stream of its own can stand for. The next poll
                // opens another.
                (None, _) => {
                    carrier = None;
                    SourceActions::default()
                }
            },
        };
    }
}

/// The stream time packets cross: written here, read by a task of its own.
///
/// The reading is a task rather than a branch of [`poll`]'s `select!` because
/// a frame read half-way when another branch wins would be dropped half-read,
/// and every frame after it misread. The task also stamps each packet's arrival
/// the moment it is whole, rather than when the loop gets round to it.
struct Carrier {
    writer: WriteHalf<fleet_transport::Stream>,
    packets: mpsc::Receiver<(Vec<u8>, NtpTimestamp)>,
    reader: tokio::task::JoinHandle<()>,
}

impl Carrier {
    async fn open(port: u32) -> std::io::Result<Self> {
        let stream = fleet_transport::dial(&host_address(port)).await?;
        let (mut reader_half, writer) = tokio::io::split(stream);
        let (arrived, packets) = mpsc::channel(4);
        let reader = tokio::spawn(async move {
            while let Ok(packet) = read_frame(&mut reader_half).await {
                if arrived.send((packet, now())).await.is_err() {
                    break;
                }
            }
        });
        Ok(Carrier {
            writer,
            packets,
            reader,
        })
    }
}

impl Drop for Carrier {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// The next packet in, with when it arrived. Waits for ever with no carrier
/// open, so the branch is simply never taken before the first send. `None`
/// once the carrier has closed.
async fn next_packet(carrier: &mut Option<Carrier>) -> Option<(Vec<u8>, NtpTimestamp)> {
    match carrier {
        Some(carrier) => carrier.packets.recv().await,
        None => std::future::pending().await,
    }
}

fn now() -> NtpTimestamp {
    SystemClock
        .now()
        .expect("CLOCK_REALTIME is readable by any process")
}

/// Where on the host a port is: vsock CID 2 in the measured build, loopback on
/// a developer's box.
#[cfg(feature = "vsock")]
fn host_address(port: u32) -> String {
    format!("vsock://2:{port}")
}

#[cfg(not(feature = "vsock"))]
fn host_address(port: u32) -> String {
    format!("127.0.0.1:{port}")
}

/// One packet, as its length in two big-endian bytes and then itself.
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> std::io::Result<()> {
    let length = u16::try_from(packet.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut frame = Vec::with_capacity(2 + packet.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(packet);
    writer.write_all(&frame).await
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let length = reader.read_u16().await?;
    let mut packet = vec![0; usize::from(length)];
    reader.read_exact(&mut packet).await?;
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_cross_a_stream_whole_and_in_order() {
        let (mut near, mut far) = tokio::io::duplex(64);
        let packets: [&[u8]; 3] = [b"one", b"", &[7u8; 48]];
        let writing = async {
            for packet in packets {
                write_frame(&mut near, packet).await.unwrap();
            }
        };
        let reading = async {
            let mut read = Vec::new();
            for _ in packets {
                read.push(read_frame(&mut far).await.unwrap());
            }
            read
        };
        let ((), read) = tokio::join!(writing, reading);
        assert_eq!(read, packets.map(|p| p.to_vec()));
    }

    #[tokio::test]
    async fn a_packet_too_long_for_its_length_is_refused() {
        let (mut near, _far) = tokio::io::duplex(64);
        let packet = vec![0u8; usize::from(u16::MAX) + 1];
        assert!(write_frame(&mut near, &packet).await.is_err());
    }
}
