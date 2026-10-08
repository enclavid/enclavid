//! `fleet-stream` — one blob, one stream, across a fleet leg.
//!
//! remoc caps one item at `rch::DEFAULT_MAX_ITEM_SIZE`, and an item past the cap
//! fails the channel it was sent on for good. So a value that can outgrow it does
//! not ride inside a call. It crosses beside the call on a `bin` channel: a raw
//! chmux port, with no codec and no cap — and also no notion of where a value
//! ends, or whether all of it arrived. This crate supplies the end.
//!
//! The contract, on both sides:
//!
//!   * The call carries a [`BlobHeader`]: the blob's exact length, bounded where it
//!     is decoded, and its SHA-256.
//!   * The blob is ONE chmux message, ended only once every byte was handed over.
//!     Across several messages a sender that died between two of them would read
//!     as one that finished.
//!   * The receiver accepts a stream that started, ended, carried exactly the
//!     declared length and hashes to the declared digest, and nothing else. A chunk
//!     that would run past the length is refused before it reaches the sink, and a
//!     stream that makes no progress for the caller's idle deadline is refused too.
//!
//! The digest is not authenticity. The sender chose it along with the bytes, so it
//! binds what this side kept to what the sender meant to send and says nothing
//! about whether either should be believed. That stays the receiving role's
//! question, asked the way it asks it of any other argument.
//!
//! An end is read where it arrives and never forwarded. remoc can hand a `bin` end
//! on to a third party, and doing so buffers up to a receiver's `max_data_size` and
//! drops a partial message without a word. A hop that passes bytes on reads them
//! with [`recv_exact`] and writes them again with [`send`].
//!
//! It also holds the connection every such stream runs over: the one remoc config
//! both leg contracts build from, and what a role sets of it ([`LegSettings`]).

mod leg;

pub use leg::{LegSettings, connection_cfg};

use std::time::Duration;

use bytes::Bytes;
use remoc::chmux::RecvChunkError;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, timeout_at};

pub use remoc::rch::bin;

/// A stream's length, at most `MAX`.
///
/// Refused on decode past the bound, so a header claiming more fails the call that
/// carries it before a byte of the stream is read, and nothing is ever reserved
/// from a length a peer chose beyond what the receiving role decided to accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
struct StreamLen<const MAX: u64>(u64);

impl<const MAX: u64> StreamLen<MAX> {
    /// `n`, or `None` past the bound.
    const fn new(n: u64) -> Option<Self> {
        if n > MAX { None } else { Some(Self(n)) }
    }

    /// The length, already held to the bound.
    const fn get(self) -> u64 {
        self.0
    }
}

impl<'de, const MAX: u64> Deserialize<'de> for StreamLen<MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(d)?)
            .ok_or_else(|| serde::de::Error::custom("a stream length past its bound"))
    }
}

/// What a call says about the blob streaming beside it: how long it is, exactly,
/// and what it hashes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobHeader<const MAX: u64> {
    len: StreamLen<MAX>,
    sha256: [u8; 32],
}

impl<const MAX: u64> BlobHeader<MAX> {
    /// The header naming `bytes`, or `None` past the bound. The only constructor,
    /// so a header this side sends always describes bytes it holds.
    pub fn of(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            len: StreamLen::new(bytes.len() as u64)?,
            sha256: Sha256::digest(bytes).into(),
        })
    }

    /// The declared length. Not `len`: this is a claim about a stream, not a
    /// collection that could be empty.
    pub fn length(&self) -> u64 {
        self.len.get()
    }
}

/// Why a stream was refused.
///
/// Fixed text and no counts. Every number a stream could report — how far it got,
/// how much it overran — is the sender's choice, and these errors reach a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// The channel was never established.
    Connect,
    /// The sender closed without starting a message.
    NoMessage,
    /// The sender abandoned its message part-way.
    Cancelled,
    /// The connection under the channel ended, or the far end closed it.
    Closed,
    /// Nothing new arrived within the idle deadline.
    Idle,
    /// The message ended before its declared length.
    Short,
    /// The message ran past its declared length.
    Long,
    /// The bytes do not hash to the declared digest.
    Digest,
    /// The sink refused a write.
    Sink,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StreamError::Connect => "the stream was never established",
            StreamError::NoMessage => "the stream closed without a message",
            StreamError::Cancelled => "the stream was abandoned part-way",
            StreamError::Closed => "the stream's connection closed",
            StreamError::Idle => "the stream stalled",
            StreamError::Short => "the stream ended short of its declared length",
            StreamError::Long => "the stream ran past its declared length",
            StreamError::Digest => "the stream does not match its declared digest",
            StreamError::Sink => "the stream's bytes could not be kept",
        })
    }
}
impl std::error::Error for StreamError {}

/// Send `bytes` as ONE message, and complete only once every byte was handed over.
///
/// chmux marks the last chunk of a message as it sends it, so a message is ended by
/// sending all of it and by nothing else. A future dropped part-way leaves a
/// message without its last chunk, which [`recv_exact`] refuses.
pub async fn send(tx: bin::Sender, bytes: impl Into<Bytes>) -> Result<(), StreamError> {
    let mut tx = tx.into_inner().await.map_err(|_| StreamError::Connect)?;
    tx.send(bytes.into()).await.map_err(|_| StreamError::Closed)
}

/// Receive exactly the blob `header` names into `sink`.
///
/// `idle` is how long the stream may go without a new byte. It is measured from the
/// last chunk that carried data, not from the last chunk: chmux delivers an empty
/// chunk as readily as a full one, and a deadline that each of them reset would let
/// a live peer that sends nothing hold this call forever.
///
/// `sink` is written synchronously between awaits, so it should be RAM-backed — a
/// memfd or a `Vec`. On any error what is in it is not the blob and must not be
/// read as one.
pub async fn recv_exact<const MAX: u64, W: std::io::Write + ?Sized>(
    rx: bin::Receiver,
    header: &BlobHeader<MAX>,
    idle: Duration,
    sink: &mut W,
) -> Result<(), StreamError> {
    let mut deadline = Instant::now() + idle;
    let mut rx = timeout_at(deadline, rx.into_inner())
        .await
        .map_err(|_| StreamError::Idle)?
        .map_err(|_| StreamError::Connect)?;

    let want = header.length();
    let mut got = 0u64;
    let mut started = false;
    let mut digest = Sha256::new();
    loop {
        // The deadline wraps the whole `recv_chunk`, not one read inside it: chmux
        // skips data that arrives without a message's first chunk and keeps
        // waiting, so a bound on anything narrower would not bound this.
        match timeout_at(deadline, rx.recv_chunk()).await {
            Err(_) => return Err(StreamError::Idle),
            Ok(Ok(Some(chunk))) => {
                started = true;
                if chunk.is_empty() {
                    continue;
                }
                // Before the sink, so not one byte past the declared length is kept.
                if chunk.len() as u64 > want - got {
                    return Err(StreamError::Long);
                }
                digest.update(&chunk);
                sink.write_all(&chunk).map_err(|_| StreamError::Sink)?;
                got += chunk.len() as u64;
                deadline = Instant::now() + idle;
            }
            // `None` before any chunk is a sender that closed without a message, not
            // an empty blob: an empty blob arrives as one empty chunk, then `None`.
            Ok(Ok(None)) if !started => return Err(StreamError::NoMessage),
            Ok(Ok(None)) => break,
            Ok(Err(RecvChunkError::Cancelled)) => return Err(StreamError::Cancelled),
            Ok(Err(RecvChunkError::ChMux)) => return Err(StreamError::Closed),
        }
    }
    if got != want {
        return Err(StreamError::Short);
    }
    if digest.finalize().as_slice() != header.sha256 {
        return Err(StreamError::Digest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use remoc::codec::Ciborium;
    use remoc::rch::base;

    type BaseTx = base::Sender<bin::Receiver, Ciborium>;
    type BaseRx = base::Receiver<bin::Receiver, Ciborium>;

    const BOUND: u64 = 1 << 20;
    const IDLE: Duration = Duration::from_secs(5);

    /// One end of a real connection whose base channel carries `bin` receivers. Its
    /// driver is spawned as soon as it is up: the other end's handshake still needs
    /// it running.
    async fn end(io: tokio::io::DuplexStream) -> (BaseTx, BaseRx) {
        let (r, w) = tokio::io::split(io);
        let (conn, tx, rx) = remoc::Connect::io::<_, _, bin::Receiver, bin::Receiver, Ciborium>(
            remoc::Cfg::default(),
            r,
            w,
        )
        .await
        .expect("the end comes up");
        tokio::spawn(conn);
        (tx, rx)
    }

    /// Both ends of one connection — the shape a call carrying a `bin` end takes,
    /// without a service around it.
    async fn connection() -> (BaseTx, BaseRx) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let ((tx, _), (_, rx)) = tokio::join!(end(a), end(b));
        (tx, rx)
    }

    /// A fresh `bin` channel whose receiver has crossed the connection.
    async fn pair(tx: &mut BaseTx, rx: &mut BaseRx) -> (bin::Sender, bin::Receiver) {
        let (bin_tx, bin_rx) = bin::channel();
        tx.send(bin_rx).await.expect("the receiver crosses");
        let bin_rx = rx
            .recv()
            .await
            .expect("the receiver decodes")
            .expect("the connection is up");
        (bin_tx, bin_rx)
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn exact_length_and_digest_is_accepted() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let blob = pattern(300_000);
        let header = BlobHeader::<BOUND>::of(&blob).unwrap();
        let mut sink = Vec::new();
        let (sent, got) = tokio::join!(
            send(bin_tx, blob.clone()),
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        sent.unwrap();
        got.unwrap();
        assert_eq!(sink, blob);
    }

    #[tokio::test]
    async fn an_empty_blob_finishes_like_any_other() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let header = BlobHeader::<BOUND>::of(&[]).unwrap();
        let mut sink = Vec::new();
        let (sent, got) = tokio::join!(
            send(bin_tx, Vec::new()),
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        sent.unwrap();
        got.unwrap();
        assert!(sink.is_empty());
    }

    #[tokio::test]
    async fn a_stream_that_ends_short_is_refused() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let blob = pattern(100_000);
        let header = BlobHeader::<BOUND>::of(&blob).unwrap();
        let mut sink = Vec::new();
        let (sent, got) = tokio::join!(
            send(bin_tx, blob[..blob.len() - 1].to_vec()),
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        sent.unwrap();
        assert_eq!(got, Err(StreamError::Short));
    }

    #[tokio::test]
    async fn a_byte_past_the_declared_length_never_reaches_the_sink() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let blob = pattern(100_000);
        let header = BlobHeader::<BOUND>::of(&blob).unwrap();
        let mut longer = blob.clone();
        longer.push(0);
        let mut sink = Vec::new();
        let (_, got) = tokio::join!(
            send(bin_tx, longer),
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        assert_eq!(got, Err(StreamError::Long));
        assert!(sink.len() as u64 <= header.length());
    }

    #[tokio::test]
    async fn a_wrong_digest_is_refused() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let blob = pattern(100_000);
        let header = BlobHeader::<BOUND>::of(&blob).unwrap();
        let mut other = blob.clone();
        other[50_000] ^= 0xFF;
        let mut sink = Vec::new();
        let (sent, got) = tokio::join!(
            send(bin_tx, other),
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        sent.unwrap();
        assert_eq!(got, Err(StreamError::Digest));
    }

    /// The sender goes away mid-message. chmux ends the port, and the receiver must
    /// read that as an abandoned message — never as one that finished.
    #[tokio::test]
    async fn a_sender_that_drops_mid_message_is_cancelled_not_finished() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let blob = pattern(100_000);
        let header = BlobHeader::<BOUND>::of(&blob).unwrap();
        let mut sink = Vec::new();
        let (_, got) = tokio::join!(
            async move {
                let mut raw = bin_tx.into_inner().await.unwrap();
                let part = raw
                    .send_chunks()
                    .send(blob[..1000].to_vec().into())
                    .await
                    .unwrap();
                drop(part);
                drop(raw);
            },
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        assert_eq!(got, Err(StreamError::Cancelled));
    }

    #[tokio::test]
    async fn a_sender_that_never_starts_is_not_an_empty_blob() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let header = BlobHeader::<BOUND>::of(&[]).unwrap();
        let mut sink = Vec::new();
        let (_, got) = tokio::join!(
            async move {
                drop(bin_tx.into_inner().await.unwrap());
            },
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        assert_eq!(got, Err(StreamError::NoMessage));
    }

    /// A live sender that started a message and stopped producing.
    #[tokio::test]
    async fn a_stalled_sender_is_refused_after_the_idle_deadline() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let blob = pattern(100_000);
        let header = BlobHeader::<BOUND>::of(&blob).unwrap();
        let mut raw = bin_tx.into_inner().await.unwrap();
        let held = raw
            .send_chunks()
            .send(blob[..1000].to_vec().into())
            .await
            .unwrap();
        let mut sink = Vec::new();
        let got = recv_exact(bin_rx, &header, Duration::from_millis(200), &mut sink).await;
        drop(held);
        assert_eq!(got, Err(StreamError::Idle));
    }

    /// Empty chunks are chunks to chmux, and a deadline each of them reset would
    /// never fire. They are not progress, so they move nothing.
    #[tokio::test]
    async fn empty_chunks_do_not_hold_the_idle_deadline_open() {
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let header = BlobHeader::<BOUND>::of(&pattern(1000)).unwrap();
        let idle = Duration::from_millis(300);
        // The sender keeps sending for far longer than the receiver may wait, so an
        // `Idle` that only came once it stopped would show up as the elapsed time.
        const SENDS: u32 = 40;
        let mut raw = bin_tx.into_inner().await.unwrap();
        let mut sink = Vec::new();
        let start = Instant::now();
        let (got, ()) = tokio::join!(
            async {
                let got = recv_exact(bin_rx, &header, idle, &mut sink).await;
                (got, start.elapsed())
            },
            async {
                let mut chunks = Some(raw.send_chunks());
                for _ in 0..SENDS {
                    let Some(c) = chunks.take() else { break };
                    match c.send(Bytes::new()).await {
                        Ok(c) => chunks = Some(c),
                        Err(_) => break,
                    }
                    tokio::time::sleep(idle / 2).await;
                }
            }
        );
        let (got, elapsed) = got;
        assert_eq!(got, Err(StreamError::Idle));
        assert!(
            elapsed < idle * SENDS / 4,
            "refused only after {elapsed:?}, as the sender stopped"
        );
    }

    #[test]
    fn a_length_past_the_bound_is_refused_on_decode() {
        #[derive(Serialize)]
        struct Loose {
            len: u64,
            sha256: [u8; 32],
        }
        let encode = |len| {
            let mut b = Vec::new();
            ciborium::into_writer(
                &Loose {
                    len,
                    sha256: [0; 32],
                },
                &mut b,
            )
            .unwrap();
            b
        };
        assert!(ciborium::from_reader::<BlobHeader<8>, _>(&encode(8)[..]).is_ok());
        assert!(ciborium::from_reader::<BlobHeader<8>, _>(&encode(9)[..]).is_err());
    }

    #[test]
    fn the_header_for_bytes_past_the_bound_is_none() {
        assert!(BlobHeader::<8>::of(&[0u8; 8]).is_some());
        assert!(BlobHeader::<8>::of(&[0u8; 9]).is_none());
    }

    /// A refused stream fails on its own port, and the connection under it carries
    /// the next one.
    #[tokio::test]
    async fn the_connection_carries_the_next_stream_after_a_failed_one() {
        let (mut tx, mut rx) = connection().await;
        let blob = pattern(100_000);
        let header = BlobHeader::<BOUND>::of(&blob).unwrap();

        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let mut longer = blob.clone();
        longer.push(0);
        let mut sink = Vec::new();
        let (_, got) = tokio::join!(
            send(bin_tx, longer),
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        assert_eq!(got, Err(StreamError::Long));

        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let mut sink = Vec::new();
        let (sent, got) = tokio::join!(
            send(bin_tx, blob.clone()),
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        sent.unwrap();
        got.unwrap();
        assert_eq!(sink, blob);
    }

    /// The reason the crate exists: a blob one byte past remoc's item limit, which
    /// no call could carry, streams whole.
    #[tokio::test]
    async fn a_blob_past_one_remoc_item_streams_whole() {
        const BIG: u64 = 32 << 20;
        let (mut tx, mut rx) = connection().await;
        let (bin_tx, bin_rx) = pair(&mut tx, &mut rx).await;
        let blob = pattern(remoc::rch::DEFAULT_MAX_ITEM_SIZE + 1);
        let header = BlobHeader::<BIG>::of(&blob).unwrap();
        let mut sink = Vec::new();
        let (sent, got) = tokio::join!(
            send(bin_tx, blob.clone()),
            recv_exact(bin_rx, &header, IDLE, &mut sink)
        );
        sent.unwrap();
        got.unwrap();
        assert!(sink == blob);
    }
}
