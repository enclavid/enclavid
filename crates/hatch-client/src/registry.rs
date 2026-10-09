//! Client for the hatch's OCI pull endpoints: `/oci/manifest`, then
//! `/oci/blob`.
//!
//! Pulls OCI artifacts (policy bundles, plugin components) from whichever
//! registry the supplied OCI reference points at — our Angos by default, but
//! any OCI-compliant registry works. The TEE has no network stack: the hatch
//! fetches by pinned-digest reference and forwards bytes over the channel — a
//! manifest whole, a blob as a stream.
//!
//! Trust model: the hatch can answer with anything at all, but cannot make
//! the TEE accept what the pinned reference does not name. The caller MUST
//! recompute the manifest's digest against the pin before parsing it, and hold
//! each blob to the digest and size its verified manifest declares as it reads
//! it. See architecture.md → Network Isolation for the full analysis.

use std::time::Duration;

use hatch_protocol::{BlobRequest, ManifestRequest, ManifestResponse};
use hyper::StatusCode;

use crate::backend::BlobPieces;
use crate::boundary;
use crate::error::BridgeError;
use crate::transport::HatchClient;
use enclavid_boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};

/// How long the hatch has to answer a pull, unless the host says otherwise
/// (api's `pull-deadline-secs` setting): a manifest whole, or a blob from the
/// request to its last byte.
///
/// The most generous of the four, because it is the only one whose work is
/// unbounded from here: the hatch fetches from a registry this process cannot
/// see, cannot reach and does not choose. Still bounded, and the reason is
/// where it runs — `cold_compile` is on the applicant round path, so a pull
/// that never returns parks a round holding that round's captures, with
/// nothing beneath it to notice. The host's to tune, as the hatch's own pace
/// already is: a larger artifact takes longer to pull, and a longer deadline
/// holds a waiting round's captures longer.
pub const DEFAULT_PULL_DEADLINE: Duration = Duration::from_secs(60);

/// How long a blob's stream may go without a new byte: the hatch's own wait
/// between two reads from the registry, and a little over.
const BLOB_IDLE: Duration = Duration::from_secs(25);

/// Client for the hatch's OCI pull endpoints over the shared hatch connection.
#[derive(Clone)]
pub struct RegistryClient {
    hatch: HatchClient,
    deadline: Duration,
}

impl RegistryClient {
    /// A client whose every pull the hatch has `deadline` to answer.
    pub fn new(hatch: HatchClient, deadline: Duration) -> Self {
        Self { hatch, deadline }
    }

    /// The raw manifest of a pinned reference, as the hatch answers.
    ///
    /// The request arrives vouched by the api producer (which holds the
    /// consumer-supplied ref + registry bearer): courier-forwarding the
    /// consumer's bearer to the registry is the producer's call, not ours to
    /// self-approve. The answer is wrapped in `Untrusted` — the caller MUST
    /// check it hashes to the pinned digest before parsing it. A 404 from the
    /// hatch surfaces as the typed `BridgeError::NotFound`.
    pub async fn manifest(
        &self,
        req: Exposed<ManifestRequest>,
    ) -> Result<Untrusted<Vec<u8>, (AuthN, AuthZ, Replay)>, BridgeError> {
        let bytes = hatch_protocol::encode(&req.into_inner())?;
        let resp = self
            .hatch
            .post("/oci/manifest", bytes, self.deadline)
            .await?;
        match resp.status {
            StatusCode::OK => {
                let r: ManifestResponse = hatch_protocol::decode(&resp.body)?;
                Ok(boundary::inbound::from_untrusted(r.manifest))
            }
            StatusCode::NOT_FOUND => Err(BridgeError::NotFound),
            s => Err(BridgeError::Transport(format!("manifest: status {s}"))),
        }
    }

    /// One blob, its bytes as they come. Wrapped in `Untrusted` like the
    /// manifest: the caller MUST hold the pieces to the size and digest its
    /// verified manifest declares, and act on none of them before the blob has
    /// ended and passed. A 404 surfaces as `BridgeError::NotFound`.
    pub async fn blob(
        &self,
        req: Exposed<BlobRequest>,
    ) -> Result<Untrusted<BlobPieces, (AuthN, AuthZ, Replay)>, BridgeError> {
        let bytes = hatch_protocol::encode(&req.into_inner())?;
        let (status, pieces) = self
            .hatch
            .post_stream("/oci/blob", bytes, self.deadline, BLOB_IDLE)
            .await?;
        match status {
            StatusCode::OK => Ok(boundary::inbound::from_untrusted(pieces)),
            StatusCode::NOT_FOUND => Err(BridgeError::NotFound),
            s => Err(BridgeError::Transport(format!("blob: status {s}"))),
        }
    }
}
