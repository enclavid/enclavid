//! Who a public connection came from, and how many places one source may hold.
//!
//! ## The address is the host's word
//!
//! This guest has no NIC, so every public connection arrives from the host and
//! the transport's own peer is the host each time. Who dialled is known only to
//! the first hop that saw the caller's TCP, and that hop says so in a PROXY
//! protocol v2 header written ahead of the caller's bytes.
//!
//! The host can write any address there. That costs only availability, which
//! the host holds anyway; what the header buys is that one caller cannot take
//! every place for itself.
//!
//! A share counts a connection from its header on. Until the header arrives one
//! source cannot be told from another, so the first hop has to write it as soon
//! as it connects, not with the caller's first bytes. A hop that waits for the
//! caller to speak lets one that connects and says nothing hold a place outside
//! any share, until `handshake_timeout` lets it go.
//!
//! ## Required, never detected
//!
//! Every connection starts with exactly one header, and one that does not is
//! let go before the handshake. Accepting a header "if one is there" would let
//! any caller that reaches the listener with no header-writing hop in front
//! claim any address. A caller's own header sent behind the real one reaches
//! rustls in place of a ClientHello and fails there.
//!
//! Except in a build whose attestation is a software stand-in
//! (`dev-attestation`). There a connection may start without a header, and
//! holds the one share every unstated source holds. Such a build proves nothing
//! about what runs it, so refusing a caller that connects straight to it would
//! protect nothing — and a developer reaches it without a header-writing hop in
//! front. The attested build cannot have that feature at all.
//!
//! Version 2 only, parsed by `ppp`. This role frames the header — the fixed
//! sixteen bytes, then the length they announce, capped — and `ppp` checks what
//! the bytes say. `ppp` also speaks the text version; nothing here calls it.
//!
//! ## What is kept, and for how long
//!
//! A keyed hash of the source, under a key made at boot and never stored, for
//! as long as that source has a connection open. A share needs only "same
//! source or not", which the hash answers. This role then keeps no address, and
//! nothing it keeps about a caller outlives its last connection.
//!
//! The address is never logged and never forwarded. api holds session ids, and
//! an address beside one would assemble inside the enclave the link between who
//! and which session that everything else keeps apart.
//!
//! An IPv6 source is its /64: that is the smallest block a subscriber is given,
//! so every address inside it is the caller's to choose. A subscriber given a
//! larger block holds more sources, as a caller with many addresses does.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex};

use ppp::v2::{Addresses, Command, Header, PROTOCOL_PREFIX, ParseError};
use ring::hmac;
use ring::rand::SystemRandom;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// The fixed part of every version 2 header: the signature, then version and
/// command, family and transport, and the length of what follows.
const FIXED: usize = 16;

/// The most this role reads past the fixed part. An IPv6 address block is 36
/// bytes; the rest is room for the records a front may append, which this role
/// skips unread.
const MAX_TAIL: usize = 1024;

/// Where a connection came from, as its header says.
///
/// No `Debug` and no `Display`: an address is not for printing.
pub enum Origin {
    /// An IPv4 source, or an IPv6 one that maps an IPv4 address.
    V4([u8; 4]),
    /// The /64 of an IPv6 source.
    V6([u8; 8]),
    /// No source stated: a LOCAL header, which a front sends about itself, or an
    /// address family with no address to share places out by. All of these hold
    /// one share between them.
    Unstated,
}

/// A connection that did not start with a header this role accepts.
///
/// Says nothing about what was sent instead.
#[derive(Debug)]
pub struct Malformed;

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a PROXY protocol v2 header")
    }
}

/// What the handshake runs over once the header is off: the stream itself.
#[cfg(not(feature = "dev-attestation"))]
pub type Opened<S> = S;

/// What the handshake runs over once the header is off: the stream, with the
/// bytes read while looking for a header that was not there put back in front.
#[cfg(feature = "dev-attestation")]
pub type Opened<S> = tokio::io::Join<
    tokio::io::Chain<std::io::Cursor<Vec<u8>>, tokio::io::ReadHalf<S>>,
    tokio::io::WriteHalf<S>,
>;

/// Read the header off the front of `stream`, and not one byte more: what
/// follows is the caller's TLS.
pub async fn read<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
) -> Result<(Origin, Opened<S>), Malformed> {
    let mut start = vec![0u8; PROTOCOL_PREFIX.len()];
    stream.read_exact(&mut start).await.map_err(|_| Malformed)?;
    if start != PROTOCOL_PREFIX {
        return headless(stream, start);
    }

    start.resize(FIXED, 0);
    stream
        .read_exact(&mut start[PROTOCOL_PREFIX.len()..])
        .await
        .map_err(|_| Malformed)?;
    // `ppp` checks the fixed part before this role reads a byte more on its
    // word, and says how many more it announces.
    let length = match Header::try_from(start.as_slice()) {
        Ok(_) => 0,
        Err(ParseError::Partial(_, length)) if length <= MAX_TAIL => length,
        Err(_) => return Err(Malformed),
    };
    let mut header = start;
    header.resize(FIXED + length, 0);
    stream
        .read_exact(&mut header[FIXED..])
        .await
        .map_err(|_| Malformed)?;
    let header = Header::try_from(header.as_slice()).map_err(|_| Malformed)?;

    let origin = match (header.command, header.addresses) {
        (Command::Local, _) => Origin::Unstated,
        (_, Addresses::IPv4(addresses)) => Origin::V4(addresses.source_address.octets()),
        (_, Addresses::IPv6(addresses)) => match addresses.source_address.to_ipv4_mapped() {
            Some(v4) => Origin::V4(v4.octets()),
            None => Origin::V6(
                addresses.source_address.octets()[..8]
                    .try_into()
                    .expect("an IPv6 address is sixteen bytes"),
            ),
        },
        _ => Origin::Unstated,
    };
    Ok((origin, opened(stream, Vec::new())))
}

/// A connection that did not start with a header.
#[cfg(not(feature = "dev-attestation"))]
fn headless<S>(_: S, _: Vec<u8>) -> Result<(Origin, Opened<S>), Malformed> {
    Err(Malformed)
}

/// A connection that did not start with a header: served in this build, with
/// what was read put back for the handshake.
#[cfg(feature = "dev-attestation")]
fn headless<S: AsyncRead + AsyncWrite>(
    stream: S,
    read: Vec<u8>,
) -> Result<(Origin, Opened<S>), Malformed> {
    Ok((Origin::Unstated, opened(stream, read)))
}

#[cfg(not(feature = "dev-attestation"))]
fn opened<S>(stream: S, _: Vec<u8>) -> Opened<S> {
    stream
}

#[cfg(feature = "dev-attestation")]
fn opened<S: AsyncRead + AsyncWrite>(stream: S, read: Vec<u8>) -> Opened<S> {
    let (from, to) = tokio::io::split(stream);
    tokio::io::join(std::io::Cursor::new(read).chain(from), to)
}

/// How many connections each source holds, by keyed hash.
pub struct Sources {
    key: hmac::Key,
    open: Mutex<HashMap<[u8; 16], usize>>,
}

impl Sources {
    /// No source holding anything yet. The key is made here and lives only in
    /// this value.
    pub fn new() -> Arc<Sources> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .expect("a guest that terminates TLS has a random source");
        Arc::new(Sources {
            key,
            open: Mutex::new(HashMap::new()),
        })
    }

    /// A place for one more connection from `origin`, or none if it already
    /// holds `each`. Given back when the returned value is dropped.
    ///
    /// `each` is the current table's, so a push lowering it lets no source
    /// open more while leaving the connections it holds alone.
    ///
    /// The map holds one entry per source with a connection open, so it is as
    /// large as the connections this role serves at most, and no larger.
    pub fn admit(self: &Arc<Self>, origin: Origin, each: usize) -> Option<Admitted> {
        let key = self.hashed(origin);
        let mut open = self.open.lock().expect("never held on panic");
        if open.get(&key).is_some_and(|held| *held >= each) {
            return None;
        }
        *open.entry(key).or_insert(0) += 1;
        Some(Admitted {
            sources: self.clone(),
            key,
        })
    }

    fn hashed(&self, origin: Origin) -> [u8; 16] {
        let (family, address): (u8, &[u8]) = match &origin {
            Origin::V4(address) => (4, address),
            Origin::V6(prefix) => (6, prefix),
            Origin::Unstated => (0, &[]),
        };
        let mut context = hmac::Context::with_key(&self.key);
        context.update(&[family]);
        context.update(address);
        context.sign().as_ref()[..16]
            .try_into()
            .expect("an HMAC-SHA256 tag is thirty-two bytes")
    }

    #[cfg(test)]
    fn sources_open(&self) -> usize {
        self.open.lock().unwrap().len()
    }
}

/// One connection's place in its source's share, given back on drop.
pub struct Admitted {
    sources: Arc<Sources>,
    key: [u8; 16],
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut open = self.sources.open.lock().expect("never held on panic");
        if let Entry::Occupied(mut held) = open.entry(self.key) {
            *held.get_mut() -= 1;
            if *held.get() == 0 {
                held.remove();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    use ppp::v2::{Builder, Protocol, Version};
    use tokio::io::AsyncWriteExt;

    /// A header as a front writes one.
    fn written(source: &str, destination: &str) -> Vec<u8> {
        let source: SocketAddr = source.parse().unwrap();
        let destination: SocketAddr = destination.parse().unwrap();
        Builder::with_addresses(
            Version::Two | Command::Proxy,
            Protocol::Stream,
            (source, destination),
        )
        .build()
        .unwrap()
    }

    /// A connection on which `bytes` arrive, then nothing more.
    async fn arriving(bytes: &[u8]) -> tokio::io::DuplexStream {
        let (near, mut far) = tokio::io::duplex(4096);
        far.write_all(bytes).await.unwrap();
        drop(far);
        near
    }

    async fn origin_of(bytes: &[u8]) -> Result<Origin, Malformed> {
        read(arriving(bytes).await).await.map(|(origin, _)| origin)
    }

    /// What the handshake would be handed to read, after the header.
    async fn left_for_the_handshake(bytes: &[u8]) -> Vec<u8> {
        let (_, mut opened) = read(arriving(bytes).await).await.ok().unwrap();
        let mut rest = Vec::new();
        opened.read_to_end(&mut rest).await.unwrap();
        rest
    }

    fn same_source(sources: &Arc<Sources>, a: Origin, b: Origin) -> bool {
        sources.hashed(a) == sources.hashed(b)
    }

    #[tokio::test]
    async fn each_address_family_is_read() {
        assert!(matches!(
            origin_of(&written("192.0.2.7:40000", "198.51.100.1:443")).await,
            Ok(Origin::V4([192, 0, 2, 7]))
        ));
        assert!(matches!(
            origin_of(&written(
                "[2001:db8:1:2:3:4:5:6]:40000",
                "[2001:db8::1]:443"
            ))
            .await,
            Ok(Origin::V6([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]))
        ));
        // A dual-stack front writes an IPv4 caller as a mapped IPv6 address. It
        // is the same caller, and it holds the same share.
        assert!(matches!(
            origin_of(&written("[::ffff:192.0.2.7]:40000", "[::1]:443")).await,
            Ok(Origin::V4([192, 0, 2, 7]))
        ));

        let local = Builder::with_addresses(
            Version::Two | Command::Local,
            Protocol::Stream,
            Addresses::Unspecified,
        )
        .build()
        .unwrap();
        assert!(matches!(origin_of(&local).await, Ok(Origin::Unstated)));

        let unspecified = Builder::with_addresses(
            Version::Two | Command::Proxy,
            Protocol::Unspecified,
            Addresses::Unspecified,
        )
        .build()
        .unwrap();
        assert!(matches!(
            origin_of(&unspecified).await,
            Ok(Origin::Unstated)
        ));
    }

    /// Exactly the header is taken off the stream: what follows is the caller's
    /// ClientHello, and a byte read too many would break it.
    #[tokio::test]
    async fn not_one_byte_past_the_header_is_read() {
        let mut sent = written("192.0.2.7:40000", "198.51.100.1:443");
        sent.extend_from_slice(b"the caller's bytes");
        assert_eq!(left_for_the_handshake(&sent).await, b"the caller's bytes");
    }

    /// Records a front appends after the addresses are skipped, not refused —
    /// and skipped whole, so none of them is left for rustls to read.
    #[tokio::test]
    async fn appended_records_are_skipped() {
        let source: SocketAddr = "192.0.2.7:40000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let mut sent = Builder::with_addresses(
            Version::Two | Command::Proxy,
            Protocol::Stream,
            (source, destination),
        )
        .write_tlv(
            ppp::v2::Type::UniqueId,
            b"an id a front gave the connection",
        )
        .unwrap()
        .build()
        .unwrap();
        sent.extend_from_slice(b"the caller's bytes");

        assert!(matches!(
            origin_of(&sent).await,
            Ok(Origin::V4([192, 0, 2, 7]))
        ));
        assert_eq!(left_for_the_handshake(&sent).await, b"the caller's bytes");
    }

    /// Bytes that begin as a header and are not one are refused, in every
    /// build: a header is either absent or right.
    #[tokio::test]
    async fn a_header_that_is_not_right_is_refused() {
        let good = written("192.0.2.7:40000", "198.51.100.1:443");

        let mut version_one = good.clone();
        version_one[12] = 0x11;

        let mut unknown_command = good.clone();
        unknown_command[12] = 0x22;

        // An IPv4 family whose address block is cut short.
        let mut short = good[..16].to_vec();
        short[15] = 4;
        short.extend_from_slice(&[192, 0, 2, 7]);

        let mut too_long = good[..16].to_vec();
        too_long[14..16].copy_from_slice(&((MAX_TAIL + 1) as u16).to_be_bytes());
        too_long.resize(16 + MAX_TAIL + 1, 0);

        let mut unknown_family = good.clone();
        unknown_family[13] = 0x41;

        let mut unknown_transport = good.clone();
        unknown_transport[13] = 0x13;

        for (what, bytes) in [
            ("version 1 in the binary layout", version_one),
            ("an unknown command", unknown_command),
            ("an unknown address family", unknown_family),
            ("an unknown transport", unknown_transport),
            ("an address block cut short", short),
            ("a length past the ceiling", too_long),
            ("a header that ends early", good[..20].to_vec()),
            ("a signature that ends early", good[..8].to_vec()),
        ] {
            assert!(origin_of(&bytes).await.is_err(), "accepted {what}");
        }
    }

    /// Starts that are not a header at all.
    fn headless() -> [(&'static str, Vec<u8>); 3] {
        let mut wrong_signature = written("192.0.2.7:40000", "198.51.100.1:443");
        wrong_signature[0] = b'X';
        [
            (
                "the text version",
                b"PROXY TCP4 192.0.2.7 198.51.100.1 40000 443\r\n".to_vec(),
            ),
            (
                "a ClientHello",
                vec![
                    0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0, 0, 0, 0, 0,
                ],
            ),
            ("a wrong signature", wrong_signature),
        ]
    }

    /// In the attested build a connection without a header is refused.
    #[cfg(not(feature = "dev-attestation"))]
    #[tokio::test]
    async fn a_connection_without_a_header_is_refused() {
        for (what, bytes) in headless() {
            assert!(origin_of(&bytes).await.is_err(), "accepted {what}");
        }
    }

    /// In a `dev-attestation` build it is served as an unstated source, and
    /// every byte read looking for a header is handed to the handshake.
    #[cfg(feature = "dev-attestation")]
    #[tokio::test]
    async fn a_connection_without_a_header_is_served_with_its_bytes_intact() {
        for (what, bytes) in headless() {
            assert!(
                matches!(origin_of(&bytes).await, Ok(Origin::Unstated)),
                "refused {what}"
            );
            assert_eq!(left_for_the_handshake(&bytes).await, bytes, "{what}");
        }
    }

    #[test]
    fn one_source_holds_no_more_than_its_share() {
        let sources = Sources::new();
        let first = sources.admit(Origin::V4([192, 0, 2, 7]), 2).unwrap();
        let _second = sources.admit(Origin::V4([192, 0, 2, 7]), 2).unwrap();
        assert!(sources.admit(Origin::V4([192, 0, 2, 7]), 2).is_none());

        // Another source is untouched by the first one's share.
        assert!(sources.admit(Origin::V4([192, 0, 2, 8]), 2).is_some());

        // And a place given back can be taken again.
        drop(first);
        assert!(sources.admit(Origin::V4([192, 0, 2, 7]), 2).is_some());
    }

    /// The share is the current table's: lowered, it lets a source that holds
    /// more open nothing new, and cuts nothing it holds.
    #[test]
    fn a_lowered_share_stops_new_connections_and_keeps_the_open_ones() {
        let sources = Sources::new();
        let held: Vec<_> = (0..3)
            .map(|_| sources.admit(Origin::V4([192, 0, 2, 7]), 3).unwrap())
            .collect();
        assert!(sources.admit(Origin::V4([192, 0, 2, 7]), 1).is_none());
        drop(held);
        assert!(sources.admit(Origin::V4([192, 0, 2, 7]), 1).is_some());
    }

    /// Nothing about a source outlives its last connection.
    #[test]
    fn a_source_with_nothing_open_is_forgotten() {
        let sources = Sources::new();
        let held = sources.admit(Origin::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]), 2);
        assert_eq!(sources.sources_open(), 1);
        drop(held);
        assert_eq!(sources.sources_open(), 0);
    }

    /// The families are told apart: four bytes of an IPv6 prefix are not the
    /// IPv4 address they happen to spell.
    #[test]
    fn sources_are_told_apart_by_family() {
        let sources = Sources::new();
        assert!(!same_source(
            &sources,
            Origin::V4([0x20, 0x01, 0x0d, 0xb8]),
            Origin::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]),
        ));
        assert!(!same_source(
            &sources,
            Origin::V4([0, 0, 0, 0]),
            Origin::Unstated
        ));
        assert!(same_source(&sources, Origin::Unstated, Origin::Unstated));
    }

    /// Two gateways, or one across a restart, do not hash a source alike: the
    /// key is made at boot and nothing can be matched across it.
    #[test]
    fn the_key_is_made_at_boot() {
        let (one, other) = (Sources::new(), Sources::new());
        assert_ne!(
            one.hashed(Origin::V4([192, 0, 2, 7])),
            other.hashed(Origin::V4([192, 0, 2, 7]))
        );
    }
}
