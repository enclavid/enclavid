//! Client for the hatch's OCI pulls: `manifest`, then `blob`.
//!
//! Pulls OCI artifacts (policy bundles, plugin components) from whichever
//! registry the supplied OCI reference points at — our Angos by default, but
//! any OCI-compliant registry works. The hatch fetches by pinned-digest
//! reference and hands the bytes back: a manifest whole, a blob as a stream
//! beside the reply.
//!
//! Trust model: what the hatch hands back is a registry's, which can answer
//! with anything at all, but cannot make api accept what the pinned reference
//! does not name. The caller MUST recompute the manifest's digest against the
//! pin before parsing it, and hold each blob to the digest and size its
//! verified manifest declares as it reads it. See architecture.md → Network
//! Isolation for the full analysis.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use hatch_rpc::{BlobRequest, HatchService, ManifestRequest};
use tokio::time::{Instant, timeout_at};

use crate::boundary;
use crate::error::BridgeError;
use crate::link::{Link, hatch, within};
use enclavid_boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};

/// How long a pull has, unless the host says otherwise (api's
/// `pull-deadline-secs` setting) or a session's terms ask for less: a manifest
/// whole, or a blob from the request to its last byte.
///
/// The most generous of the hatch's deadlines, because it is the only one whose
/// work is unbounded from here: the hatch fetches from a registry this process
/// does not choose. Still bounded, and the reason is where it runs — api's pull
/// check and its compile path are both on the applicant round path, so a pull
/// that never returns parks a round holding that round's captures.
pub const DEFAULT_PULL_DEADLINE: Duration = Duration::from_secs(60);

/// A blob's pieces as the hatch streams them, in order. An error ends the
/// blob, and what came before it is not the blob.
pub type BlobPieces = BoxStream<'static, Result<Bytes, BridgeError>>;

/// How long a blob's stream may go without a new byte: the hatch's own wait
/// between two reads from the registry, and a little over.
const BLOB_IDLE: Duration = Duration::from_secs(25);

/// Client for the hatch's OCI pulls.
#[derive(Clone)]
pub struct RegistryClient {
    link: Arc<dyn Link>,
    deadline: Duration,
}

impl RegistryClient {
    /// A client whose every pull has `deadline` at most.
    pub fn new(link: Arc<dyn Link>, deadline: Duration) -> Self {
        Self { link, deadline }
    }

    /// The deadline a pull is given: `within` where a session's terms name one
    /// shorter than this client's, this client's otherwise.
    fn deadline(&self, within: Option<Duration>) -> Duration {
        within.map_or(self.deadline, |w| w.min(self.deadline))
    }

    /// The raw manifest of a pinned reference, as the hatch answers.
    ///
    /// The request arrives vouched by the api producer (which holds the
    /// consumer-supplied ref + registry bearer): courier-forwarding the
    /// consumer's bearer to the registry is the producer's call, not ours to
    /// self-approve. The answer is wrapped in `Untrusted` — the caller MUST
    /// check it hashes to the pinned digest before parsing it.
    pub async fn manifest(
        &self,
        req: Exposed<ManifestRequest>,
        within_terms: Option<Duration>,
    ) -> Result<Untrusted<Vec<u8>, (AuthN, AuthZ, Replay)>, BridgeError> {
        let hatch = hatch(self.link.as_ref())?;
        let manifest = within(self.deadline(within_terms), "manifest", async {
            Ok(hatch.manifest(req.into_inner()).await?)
        })
        .await?;
        Ok(boundary::inbound::from_untrusted(manifest.0))
    }

    /// One blob, its bytes as they come, held to the size the request names.
    /// Wrapped in `Untrusted` like the manifest: the caller MUST hold the
    /// pieces to the digest its verified manifest declares, and act on none of
    /// them before the blob has ended and passed.
    ///
    /// One deadline covers it, from the request to the last byte: the hatch's
    /// answer, the stream's opening and every piece share what is left of it.
    pub async fn blob(
        &self,
        req: Exposed<BlobRequest>,
        within_terms: Option<Duration>,
    ) -> Result<Untrusted<BlobPieces, (AuthN, AuthZ, Replay)>, BridgeError> {
        let deadline = self.deadline(within_terms);
        let end = Instant::now() + deadline;
        let hatch = hatch(self.link.as_ref())?;
        let req = req.into_inner();
        let size = req.size.get();
        let body = within(deadline, "blob", async { Ok(hatch.blob(req).await?) }).await?;
        let stream_failed = |e: fleet_stream::StreamError| BridgeError::Transport(e.to_string());
        let incoming = timeout_at(end, fleet_stream::Incoming::open(body, size, BLOB_IDLE))
            .await
            .map_err(|_| BridgeError::Transport(format!("blob: no stream in {deadline:?}")))?
            .map_err(stream_failed)?;
        let pieces = incoming
            .into_pieces(end.saturating_duration_since(Instant::now()), None)
            .map_err(stream_failed)
            .boxed();
        Ok(boundary::inbound::from_untrusted(pieces))
    }
}
