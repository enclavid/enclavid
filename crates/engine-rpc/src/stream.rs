//! The bundle a `run_with_bundle` carries — streamed beside the call, not inside it.
//!
//! A round request travels as ONE remoc item, and an item past remoc's limit fails
//! the channel it was sent on for good. The request already carries the round's
//! clip and state frame, so a bundle inside it decided whether a round fit at all —
//! and on a cache miss during a media round, it did not. Beside the call, the
//! request is the round alone and stays one bounded item whatever the bundle weighs.
//!
//! Two blobs, two ends, one header: the cwasm and the [`BundleMeta`] it is
//! registered with, each a `fleet_stream` blob under its own bound. The metadata is
//! a blob rather than a header field because at its bound
//! ([`MAX_BUNDLE_META_BYTES`], 7 MiB) it cannot fit beside a full clip in one
//! request.

use std::future::Future;
use std::time::Duration;

use fleet_stream::{BlobHeader, StreamError, bin};
use serde::{Deserialize, Serialize};

use crate::bundle::{BundleMeta, CompiledBundle, MAX_BUNDLE_META_BYTES, MAX_CWASM_BYTES};
use crate::execute::ExecError;

/// How long a bundle stream may go without a new byte, unless the receiver says
/// otherwise.
///
/// The patience a leg gives silence by default
/// ([`LegSettings::timeout`](crate::LegSettings::timeout)). The sender writes
/// from memory and has no reason to pause, so a stream that stalls this long has
/// a peer that stopped.
pub const DEFAULT_BUNDLE_STREAM_IDLE: Duration = Duration::from_secs(20);

/// How long a whole bundle may take to arrive, unless the receiver says
/// otherwise.
///
/// The idle deadline bounds a stall, not a trickle: a byte every few seconds keeps
/// it from firing, and would hold the receiver's cache fill for as long as the
/// peer liked. 120 s carries a bundle at [`MAX_CWASM_BYTES`] at about 13 MiB/s,
/// far below what a leg that carries rounds runs at. A receiver on a slower leg
/// gives more, or never takes a bundle that large.
pub const DEFAULT_BUNDLE_STREAM_DEADLINE: Duration = Duration::from_secs(120);

/// The most a [`BundleHeader`] encodes to. It measures 178 bytes with both lengths
/// at their bounds and every digest byte at its widest encoding; a test below holds
/// it to this.
pub(crate) const BUNDLE_HEADER_MAX_ENCODED: usize = 256;

/// The two blobs a bundle streams as, each named by length and digest.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleHeader {
    pub(crate) cwasm: BlobHeader<MAX_CWASM_BYTES>,
    pub(crate) meta: BlobHeader<MAX_BUNDLE_META_BYTES>,
}

/// The bundle a `run_with_bundle` call carries: a bounded header in the request,
/// and one `bin` end per blob beside it.
///
/// The fields are private to this crate, so outside it a stream is built only by
/// the door, from a whole [`CompiledBundle`], and read only through
/// [`receive`](Self::receive), which holds every byte to the header.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleStream {
    pub(crate) header: BundleHeader,
    pub(crate) cwasm: bin::Receiver,
    pub(crate) meta: bin::Receiver,
}

/// Why a bundle stream was refused. Fixed text, no counts, as [`StreamError`]'s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// The cwasm's stream failed.
    Cwasm(StreamError),
    /// The metadata's stream failed.
    Meta(StreamError),
    /// The metadata arrived whole and did not decode.
    MetaDecode,
    /// The two did not arrive within the receiver's deadline.
    Deadline,
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Cwasm(e) => write!(f, "cwasm: {e}"),
            BundleError::Meta(e) => write!(f, "metadata: {e}"),
            BundleError::MetaDecode => f.write_str("the bundle's metadata did not decode"),
            BundleError::Deadline => f.write_str("the bundle did not arrive in time"),
        }
    }
}
impl std::error::Error for BundleError {}

impl BundleStream {
    /// The lengths the cwasm and the metadata are declared at, each already held
    /// to its bound. The sender's word until [`receive`](Self::receive) holds the
    /// bytes to it; a receiver reserves room by it before reading any.
    pub fn declared(&self) -> (u64, u64) {
        (self.header.cwasm.length(), self.header.meta.length())
    }

    /// Split a bundle into the stream a call carries and the writer that feeds it.
    ///
    /// The writer sends both blobs at once, so the receiver may read them in either
    /// order without one waiting on the other. It must run while the call is
    /// awaited: the receiver reads inside the call, so a writer started after it
    /// returns has nobody left to write to.
    ///
    /// Both digests are taken here, inline — about 35 ms for a 66 MB cwasm on
    /// SHA-NI — on the round that already waits for the bundle to cross.
    pub(crate) fn split(
        bundle: CompiledBundle,
    ) -> Result<(Self, impl Future<Output = ()> + Send + 'static), ExecError> {
        let meta = bundle.encoded_meta().ok_or(ExecError::Unknown)?;
        let CompiledBundle { cwasm, .. } = bundle;
        // `None` is a bundle past what the hop accepts, which a round cannot fix.
        let header = BundleHeader {
            cwasm: BlobHeader::of(&cwasm).ok_or(ExecError::Unknown)?,
            meta: BlobHeader::of(&meta).ok_or(ExecError::Unknown)?,
        };
        let (cwasm_tx, cwasm_rx) = bin::channel();
        let (meta_tx, meta_rx) = bin::channel();
        let writer = async move {
            let _ = tokio::join!(
                fleet_stream::send(cwasm_tx, cwasm),
                fleet_stream::send(meta_tx, meta),
            );
        };
        Ok((
            Self {
                header,
                cwasm: cwasm_rx,
                meta: meta_rx,
            },
            writer,
        ))
    }

    /// Receive both blobs, each to its exact length and digest, within
    /// `deadline` for the whole ([`DEFAULT_BUNDLE_STREAM_DEADLINE`] unless the
    /// receiver has reason for another) and with no more than `idle` between
    /// bytes ([`DEFAULT_BUNDLE_STREAM_IDLE`] likewise), and decode the metadata
    /// only once both have passed. The cwasm goes to `sink` as it arrives;
    /// returns the cwasm's length, the metadata, and the metadata's length on
    /// the wire — both lengths the header's, which every byte was held to.
    ///
    /// Read concurrently, because the writer sends them concurrently and chmux
    /// flow-controls each port on its own: reading one to the end before starting
    /// the other would leave the other's sender waiting on credit for no reason.
    ///
    /// On an error what is in `sink` is not the cwasm and must not be read as one.
    pub async fn receive<W: std::io::Write + Send>(
        self,
        sink: &mut W,
        deadline: Duration,
        idle: Duration,
    ) -> Result<(u64, BundleMeta, u64), BundleError> {
        let Self {
            header,
            cwasm,
            meta,
        } = self;
        let mut meta_bytes = Vec::new();
        tokio::time::timeout(deadline, async {
            tokio::try_join!(
                async {
                    fleet_stream::recv_exact(cwasm, &header.cwasm, idle, sink)
                        .await
                        .map_err(BundleError::Cwasm)
                },
                async {
                    fleet_stream::recv_exact(meta, &header.meta, idle, &mut meta_bytes)
                        .await
                        .map_err(BundleError::Meta)
                },
            )
        })
        .await
        .map_err(|_| BundleError::Deadline)??;
        let meta = ciborium::from_reader(&meta_bytes[..]).map_err(|_| BundleError::MetaDecode)?;
        Ok((header.cwasm.length(), meta, header.meta.length()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execute::{Prop, RUN_REQUEST_HEADROOM, RunRequest};
    use crate::keys::CompositionKey;
    use crate::padded::{Framed, Padded};
    use hatch_client::{Clip, Event, MAX_CLIP_BYTES, MAX_CLIP_FRAMES, MediaResult, SessionState};

    /// The header with no bounds, so a test can put on the wire what the real type
    /// will not produce.
    #[derive(Serialize)]
    struct LooseBlob {
        len: u64,
        sha256: [u8; 32],
    }
    #[derive(Serialize)]
    struct LooseHeader {
        cwasm: LooseBlob,
        meta: LooseBlob,
    }

    /// Both lengths at their bounds, and every digest byte past 0x17 so it takes
    /// two bytes in CBOR — the widest header that still decodes.
    fn widest_header() -> LooseHeader {
        LooseHeader {
            cwasm: LooseBlob {
                len: MAX_CWASM_BYTES,
                sha256: [0xFF; 32],
            },
            meta: LooseBlob {
                len: MAX_BUNDLE_META_BYTES,
                sha256: [0xFF; 32],
            },
        }
    }

    #[test]
    fn the_bundle_header_at_its_bounds_encodes_within_its_budget() {
        let mut b = Vec::new();
        ciborium::into_writer(&widest_header(), &mut b).unwrap();
        ciborium::from_reader::<BundleHeader, _>(&b[..]).expect("lengths at their bounds decode");
        assert!(
            b.len() <= BUNDLE_HEADER_MAX_ENCODED,
            "the widest header encodes to {} bytes",
            b.len()
        );
    }

    /// The const assertion beside `RunRequest`, held against a real encoding: a
    /// request with every field at its bound, plus the header naming its bundle.
    #[test]
    fn a_round_request_at_its_bounds_fits_its_budget() {
        let req = RunRequest {
            composition_key: CompositionKey::from_digest([0xFF; 32]),
            props: (0..engine_types::limits::MAX_PROPS)
                .map(|i| (format!("{i:016}"), Prop::Float(f64::MAX)))
                .collect(),
            session_state: Padded::seal(&SessionState::default()).expect("fits the frame"),
            event: Event::Media(MediaResult {
                slot: u32::MAX,
                clip: Clip {
                    frames: vec![vec![0xFF; MAX_CLIP_BYTES / MAX_CLIP_FRAMES]; MAX_CLIP_FRAMES],
                },
            }),
        };
        let mut b = Vec::new();
        ciborium::into_writer(&(&req, &widest_header()), &mut b).unwrap();
        let budget = MAX_CLIP_BYTES
            + <SessionState as Framed>::FRAME
            + BUNDLE_HEADER_MAX_ENCODED
            + RUN_REQUEST_HEADROOM;
        assert!(
            b.len() <= budget,
            "a round at its bounds encodes to {} bytes, over its {budget}-byte budget",
            b.len()
        );
    }

    /// The door's own pair: what `split` sends, `receive` takes back whole.
    #[tokio::test]
    async fn a_split_bundle_is_received_whole() {
        let bundle = crate::bundle::sample_bundle();
        let cwasm = bundle.cwasm.clone();
        let meta_encoded = bundle.encoded_meta().unwrap();
        let (stream, writer) = BundleStream::split(bundle).unwrap();

        // Across a real connection, because a `bin` end only connects by crossing
        // one. Each end's driver is spawned as soon as that end is up: the other
        // end's handshake still needs it running.
        type Ends = BundleStream;
        async fn end(
            io: tokio::io::DuplexStream,
        ) -> (
            remoc::rch::base::Sender<Ends, remoc::codec::Ciborium>,
            remoc::rch::base::Receiver<Ends, remoc::codec::Ciborium>,
        ) {
            let (r, w) = tokio::io::split(io);
            let (conn, tx, rx) = remoc::Connect::io::<_, _, Ends, Ends, remoc::codec::Ciborium>(
                crate::connection_cfg(&crate::LegSettings::default()),
                r,
                w,
            )
            .await
            .unwrap();
            tokio::spawn(conn);
            (tx, rx)
        }
        let (a, b) = tokio::io::duplex(1 << 20);
        let ((mut tx, _), (_, mut rx)) = tokio::join!(end(a), end(b));

        assert!(tx.send(stream).await.is_ok(), "the stream crosses");
        let stream = rx.recv().await.unwrap().unwrap();
        let mut sink = Vec::new();
        let (got, ()) = tokio::join!(
            stream.receive(
                &mut sink,
                DEFAULT_BUNDLE_STREAM_DEADLINE,
                DEFAULT_BUNDLE_STREAM_IDLE
            ),
            writer
        );
        let (len, meta, meta_len) = got.unwrap();
        assert_eq!(len, cwasm.len() as u64);
        assert_eq!(meta_len, meta_encoded.len() as u64);
        assert_eq!(sink, cwasm);
        assert_eq!(meta.embedded_imports.len(), 1);
        assert!(meta.catalogs[0].decls.disclosure_fields.contains("dob"));
    }
}
