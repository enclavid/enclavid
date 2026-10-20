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

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use tokio::time::{Instant, timeout_at};

use enclavid_boundary::{Exposed, Receives, Untrusted};
use fleet_stream::bin;
use hatch_rpc::{BlobRequest, Manifest, ManifestRequest, RemoteHatchCalls};

use crate::error::BridgeError;
use crate::link::{Link, hatch, within};

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

/// Client for the hatch's OCI pulls, held at end `B` of the hatch leg, whose
/// declaration says what is open on each value that crosses it.
pub struct RegistryClient<B> {
    link: Arc<dyn Link<B>>,
    deadline: Duration,
    _end: PhantomData<fn() -> B>,
}

impl<B> Clone for RegistryClient<B> {
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
            deadline: self.deadline,
            _end: PhantomData,
        }
    }
}

impl<B> RegistryClient<B> {
    /// A client whose every pull has `deadline` at most.
    pub fn new(link: Arc<dyn Link<B>>, deadline: Duration) -> Self {
        Self {
            link,
            deadline,
            _end: PhantomData,
        }
    }

    /// The deadline a pull is given: `within` where a session's terms name one
    /// shorter than this client's, this client's otherwise.
    fn deadline(&self, within: Option<Duration>) -> Duration {
        within.map_or(self.deadline, |w| w.min(self.deadline))
    }
}

impl<B: RemoteHatchCalls + 'static> RegistryClient<B> {
    /// The raw manifest of a pinned reference, as the hatch answers, open on what
    /// `B` left open on a manifest — the caller MUST check it hashes to the pinned
    /// digest before parsing it.
    ///
    /// `req` arrives answered, as an authorization's does. A failure comes back as
    /// `BridgeError`, from an error `B`'s declaration answered in full.
    pub async fn manifest(
        &self,
        req: Exposed<ManifestRequest, (), B>,
        within_terms: Option<Duration>,
    ) -> Result<Untrusted<Vec<u8>, <B as Receives<Manifest>>::Open, B>, BridgeError> {
        let hatch = hatch(self.link.as_ref())?;
        let manifest = within(self.deadline(within_terms), "manifest", async {
            Ok(hatch.manifest(req).await?)
        })
        .await?;
        Ok(manifest.map(|Manifest(bytes)| bytes))
    }

    /// One blob, its bytes as they come, held to the size the request names, open
    /// on what `B` left open on a blob's stream like the manifest: the caller MUST
    /// hold the pieces to the digest its verified manifest declares, and act on
    /// none of them before the blob has ended and passed.
    ///
    /// One deadline covers it, from the request to the last byte: the hatch's
    /// answer, the stream's opening and every piece share what is left of it. The
    /// stream opens on the first read, so a blob that never starts is the first
    /// piece failing.
    pub async fn blob(
        &self,
        req: Exposed<BlobRequest, (), B>,
        within_terms: Option<Duration>,
    ) -> Result<Untrusted<BlobPieces, <B as Receives<bin::Receiver>>::Open, B>, BridgeError> {
        let deadline = self.deadline(within_terms);
        let end = Instant::now() + deadline;
        let hatch = hatch(self.link.as_ref())?;
        let (body, size) = within(deadline, "blob", async { Ok(hatch.blob(req).await?) }).await?;
        Ok(body.map(|body| pieces(body, size.get(), end, deadline)))
    }
}

/// `body`'s pieces, `size` bytes of them, the stream opened as they are first
/// read — all by `end`, the last of a pull's `deadline`.
fn pieces(body: bin::Receiver, size: u64, end: Instant, deadline: Duration) -> BlobPieces {
    let stream_failed = |e: fleet_stream::StreamError| BridgeError::Transport(e.to_string());
    futures::stream::once(async move {
        let incoming = timeout_at(end, fleet_stream::Incoming::open(body, size, BLOB_IDLE))
            .await
            .map_err(|_| BridgeError::Transport(format!("blob: no stream in {deadline:?}")))?
            .map_err(stream_failed)?;
        Ok::<_, BridgeError>(
            incoming
                .into_pieces(end.saturating_duration_since(Instant::now()), None)
                .map_err(stream_failed),
        )
    })
    .try_flatten()
    .boxed()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fleet_stream::bin;
    use futures::StreamExt;
    use tokio::time::Instant;

    use super::pieces;
    use crate::error::BridgeError;

    /// A blob whose stream never opens fails its first piece and ends there,
    /// never reading as an empty blob: whether its sender went away, or never
    /// came and the pull's time ran out.
    #[tokio::test(start_paused = true)]
    async fn a_blob_never_opened_fails_its_first_piece() {
        let (gone, body) = bin::channel();
        drop(gone);
        let deadline = Duration::from_secs(1);
        let mut blob = pieces(body, 1, Instant::now() + deadline, deadline);
        assert!(matches!(
            blob.next().await,
            Some(Err(BridgeError::Transport(_)))
        ));
        assert!(blob.next().await.is_none());

        let (_held, body) = bin::channel();
        let mut blob = pieces(body, 1, Instant::now() + deadline, deadline);
        assert!(matches!(
            blob.next().await,
            Some(Err(BridgeError::Transport(_)))
        ));
        assert!(blob.next().await.is_none());
    }
}
