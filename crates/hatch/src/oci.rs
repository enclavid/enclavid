//! OCI pulls: the raw manifest a pinned reference names, then one blob of it,
//! from whichever registry the reference names, with the bearer api hands over.
//! The hatch authenticates to no registry on its own.
//!
//! The hatch parses neither. Whether any of the bytes are what the reference
//! pins, api decides: it recomputes the manifest's digest against the pin,
//! picks the layer from the manifest it verified, and holds the blob to that
//! layer's digest and size as it reads it.
//!
//! What one pull may cost the hatch is bounded: so many manifests and so many
//! blobs at a time, counted apart, a blob counted for as long as its stream
//! runs; a manifest small enough to read, a blob no longer than the size api
//! asked for, and each within a deadline — none of it sized by what the
//! registry says. Nothing of a blob is held here beyond the piece in hand.
//!
//! A fresh registry client per call: oci-client caches the first auth value it
//! sees with no way to drop it, so a client per call keeps one consumer's
//! bearer from another's pull.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use oci_client::Reference;
use oci_client::client::{Client, ClientConfig, ClientProtocol};
use oci_client::errors::{OciDistributionError, OciErrorCode};
use oci_client::secrets::RegistryAuth;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout, timeout_at};

use fleet_stream::bin;
use hatch_rpc::{BlobRequest, Manifest, ManifestRequest, PullError};
use safe_logger::debug;

const MANIFEST_ACCEPTS: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// Manifests fetched at once, unless the host says otherwise (the
/// `concurrent-manifests` setting). Counted apart from blobs, so a check waits
/// on no blob stream; each is read whole, at most [`MANIFEST_BYTES`], so all of
/// them together are 32 MiB at most.
pub const DEFAULT_CONCURRENT_MANIFESTS: usize = 128;
/// Blobs streamed at once, unless the host says otherwise (the
/// `concurrent-blobs` setting), each counted for as long as its stream runs.
/// More of them only share the guest's bandwidth further.
pub const DEFAULT_CONCURRENT_BLOBS: usize = 8;

/// The longest manifest read: real ones are a few KiB.
const MANIFEST_BYTES: usize = 256 << 10;
/// From the request to the manifest's last byte, under api's own wait.
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(55);
/// From the request to the blob's last byte: a blob at its longest, at a pace
/// well below what a registry serves.
const BLOB_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Between two reads from the registry.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// The guest's turns at registries, shared by every pull.
#[derive(Clone)]
pub struct Pulls {
    manifests: Arc<Semaphore>,
    blobs: Arc<Semaphore>,
}

impl Pulls {
    pub fn new(manifests: usize, blobs: usize) -> Self {
        Self {
            manifests: Arc::new(Semaphore::new(manifests)),
            blobs: Arc::new(Semaphore::new(blobs)),
        }
    }

    /// The raw manifest a pinned reference names.
    pub async fn manifest(&self, req: ManifestRequest) -> Result<Manifest, PullError> {
        let (protocol, reference) = scheme(&req.reference);
        let reference = parse_ref(reference)?;
        let auth = build_auth(&req.registry_auth)?;
        let client = build_client(protocol)?;

        let manifest = timeout(MANIFEST_TIMEOUT, async {
            let _turn = self.manifests.acquire().await.map_err(failed)?;
            let (manifest, _) = client
                .pull_manifest_raw(&reference, &auth, MANIFEST_ACCEPTS)
                .await
                .map_err(|e| {
                    debug!("manifest pull of {reference}: {e}");
                    classify(e)
                })?;
            Ok::<_, PullError>(manifest)
        })
        .await
        .map_err(|_| PullError::Failed("manifest: timed out".into()))??;
        if manifest.len() > MANIFEST_BYTES {
            return Err(PullError::Failed(format!(
                "a manifest past {MANIFEST_BYTES} bytes"
            )));
        }
        Ok(Manifest(manifest.to_vec()))
    }

    /// One blob, its bytes passed on as they come from the registry, as one
    /// message on the returned channel of at most `req.size` bytes. The answer
    /// says whether the stream started; a failure after that — the registry's,
    /// the size's, the deadline's — abandons the message, which api reads as a
    /// blob that did not arrive.
    pub async fn blob(&self, req: BlobRequest) -> Result<bin::Receiver, PullError> {
        let (protocol, reference) = scheme(&req.reference);
        let reference = parse_ref(reference)?;
        let digest = parse_digest(&req.digest)?;
        let auth = build_auth(&req.registry_auth)?;
        let client = build_client(protocol)?;

        let end = Instant::now() + BLOB_TIMEOUT;
        let (turn, stream) = timeout_at(end, async {
            let turn = self.blobs.clone().acquire_owned().await.map_err(failed)?;
            // The digest alone, never a descriptor: a descriptor's `urls` would
            // have the client fetch from wherever the manifest names. This
            // client has fetched nothing yet, so it holds no token to send.
            client
                .auth(&reference, &auth, oci_client::RegistryOperation::Pull)
                .await
                .map_err(classify)?;
            let stream = client
                .pull_blob_stream(&reference, digest)
                .await
                .map_err(|e| {
                    debug!("blob pull of {reference}: {e}");
                    classify(e)
                })?;
            Ok::<_, PullError>((turn, stream))
        })
        .await
        .map_err(|_| PullError::Failed("blob: timed out".into()))??;

        let (tx, rx) = bin::channel();
        let pieces = pass_on(
            stream.stream.map_err(std::io::Error::other),
            req.size.get(),
            end,
            turn,
        );
        tokio::spawn(async move {
            if let Err(e) = fleet_stream::send_from(tx, Box::pin(pieces)).await {
                debug!("blob stream ended early: {e:?}");
            }
        });
        Ok(rx)
    }
}

fn failed(e: impl std::fmt::Display) -> PullError {
    PullError::Failed(e.to_string())
}

/// `pieces`, refused past `cap` bytes together or past `end`, and ended at the
/// first refusal or failure. `turn` is held for as long as the stream runs —
/// given back when it ends or is dropped, and not before.
fn pass_on<S, T>(
    pieces: S,
    cap: u64,
    end: Instant,
    turn: T,
) -> impl futures::Stream<Item = std::io::Result<Bytes>> + Send
where
    S: futures::Stream<Item = std::io::Result<Bytes>> + Send + Unpin,
    T: Send,
{
    futures::stream::unfold(
        (pieces, 0u64, Some(turn)),
        move |(mut pieces, mut sent, turn)| async move {
            let turn = turn?;
            let piece = match timeout_at(end, pieces.next()).await {
                Err(_) => Err(std::io::Error::other("blob: past its deadline")),
                Ok(None) => return None,
                Ok(Some(Err(e))) => Err(e),
                Ok(Some(Ok(piece))) => {
                    sent += piece.len() as u64;
                    if sent > cap {
                        Err(std::io::Error::other(format!("blob past {cap} bytes")))
                    } else {
                        Ok(piece)
                    }
                }
            };
            let turn = piece.is_ok().then_some(turn);
            Some((piece, (pieces, sent, turn)))
        },
    )
}

/// A registry refusing the bearer → `Refused`; a 404, or an error envelope
/// saying the manifest, blob or repository is unknown → `NotFound`; so api can
/// tell both from a registry that did not answer. Read off the error's fields,
/// never its rendering: a rendering spells the envelope's codes as Rust names,
/// and carries the digest, which can hold any run of digits.
fn classify(e: OciDistributionError) -> PullError {
    let any_code = |envelope: &oci_client::errors::OciEnvelope, codes: &[OciErrorCode]| {
        envelope.errors.iter().any(|e| codes.contains(&e.code))
    };
    let (refused, unknown) = match &e {
        OciDistributionError::UnauthorizedError { .. } => (true, false),
        OciDistributionError::ImageManifestNotFoundError(_) => (false, true),
        OciDistributionError::ServerError { code, .. } => (matches!(code, 401 | 403), *code == 404),
        OciDistributionError::RegistryError { envelope, .. } => (
            any_code(
                envelope,
                &[OciErrorCode::Unauthorized, OciErrorCode::Denied],
            ),
            any_code(
                envelope,
                &[
                    OciErrorCode::ManifestUnknown,
                    OciErrorCode::BlobUnknown,
                    OciErrorCode::NameUnknown,
                    OciErrorCode::NotFound,
                ],
            ),
        ),
        _ => (false, false),
    };
    if refused {
        PullError::Refused
    } else if unknown {
        PullError::NotFound
    } else {
        PullError::Failed(format!("pull: {e}"))
    }
}

/// Require digest form (`@sha256:<hex>`): api only ever pins by digest, so a
/// tag is not a reference the hatch fetches.
fn parse_ref(reference: &str) -> Result<Reference, PullError> {
    let parsed = Reference::try_from(reference).map_err(|e| {
        debug!("invalid reference: {e}");
        PullError::Refused
    })?;
    if parsed.digest().is_none() {
        return Err(PullError::Refused);
    }
    Ok(parsed)
}

/// A blob digest is `sha256:` and 64 hex digits, and nothing else is fetched
/// by one.
fn parse_digest(digest: &str) -> Result<&str, PullError> {
    let hex = digest
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    hex.map(|_| digest).ok_or(PullError::Refused)
}

/// The opaque bearer as oci-client's typed `RegistryAuth`: empty → anonymous,
/// `Bearer <token>` → that token, and nothing else.
fn build_auth(registry_auth: &[u8]) -> Result<RegistryAuth, PullError> {
    if registry_auth.is_empty() {
        return Ok(RegistryAuth::Anonymous);
    }
    let s = std::str::from_utf8(registry_auth)
        .map_err(|_| PullError::Refused)?
        .trim();
    s.strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))
        .map(|token| RegistryAuth::Bearer(token.to_string()))
        .ok_or(PullError::Refused)
}

/// The registry's scheme as the consumer wrote it at the front of the
/// reference — `http://` for plain HTTP, `https://` or none for HTTPS, as
/// every client takes a reference that names none — and the reference
/// without it.
fn scheme(reference: &str) -> (ClientProtocol, &str) {
    if let Some(rest) = reference.strip_prefix("http://") {
        (ClientProtocol::Http, rest)
    } else if let Some(rest) = reference.strip_prefix("https://") {
        (ClientProtocol::Https, rest)
    } else {
        (ClientProtocol::Https, reference)
    }
}

fn build_client(protocol: ClientProtocol) -> Result<Client, PullError> {
    Client::try_from(ClientConfig {
        protocol,
        connect_timeout: Some(CONNECT_TIMEOUT),
        read_timeout: Some(READ_TIMEOUT),
        ..Default::default()
    })
    .map_err(|e| PullError::Failed(format!("registry client: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_is_the_one_written_and_https_without_one() {
        let pinned = "127.0.0.1:5000/enclavid/p@sha256:00";
        let (p, r) = scheme("http://127.0.0.1:5000/enclavid/p@sha256:00");
        assert!(matches!(p, ClientProtocol::Http));
        assert_eq!(r, pinned);
        let (p, r) = scheme("https://127.0.0.1:5000/enclavid/p@sha256:00");
        assert!(matches!(p, ClientProtocol::Https));
        assert_eq!(r, pinned);
        // No name is taken to mean plain HTTP: only what is written.
        for unmarked in [
            pinned,
            "localhost:5050/p@sha256:00",
            "localhost.example/p@sha256:00",
        ] {
            let (p, r) = scheme(unmarked);
            assert!(matches!(p, ClientProtocol::Https), "{unmarked}");
            assert_eq!(r, unmarked);
        }
    }

    /// A blob is passed on up to the cap and refused past it, nothing follows
    /// the refusal, and the turn is given back with it.
    #[tokio::test]
    async fn a_blob_is_passed_on_up_to_its_cap() {
        let pieces = futures::stream::iter(
            [&b"12345"[..], b"678", b"9", b"after"]
                .into_iter()
                .map(|p| Ok(Bytes::from_static(p))),
        );
        let turn = std::sync::Arc::new(());
        let end = Instant::now() + Duration::from_secs(10);
        let got: Vec<_> = pass_on(pieces, 8, end, turn.clone()).collect().await;
        assert_eq!(got.len(), 3);
        assert!(got[0].is_ok() && got[1].is_ok());
        assert!(got[2].is_err(), "the piece past the cap is refused");
        assert_eq!(std::sync::Arc::strong_count(&turn), 1, "the turn is back");
    }

    /// A registry refusing the bearer is told apart from one that is absent
    /// and from one that did not answer, so api can tell a session to stop
    /// from a session to ask again.
    #[test]
    fn a_refusal_is_told_apart_from_no_answer() {
        use oci_client::errors::{OciEnvelope, OciError};
        let server = |code| OciDistributionError::ServerError {
            code,
            url: String::new(),
            message: String::new(),
        };
        let envelope = |code| OciDistributionError::RegistryError {
            envelope: OciEnvelope {
                errors: vec![OciError {
                    code,
                    message: String::new(),
                    detail: serde_json::Value::Null,
                }],
            },
            url: String::new(),
        };
        let unauthorized = OciDistributionError::UnauthorizedError { url: String::new() };
        for refused in [
            unauthorized,
            server(401),
            server(403),
            envelope(OciErrorCode::Denied),
            envelope(OciErrorCode::Unauthorized),
        ] {
            assert!(matches!(classify(refused), PullError::Refused));
        }
        for unknown in [
            server(404),
            envelope(OciErrorCode::ManifestUnknown),
            envelope(OciErrorCode::BlobUnknown),
            envelope(OciErrorCode::NameUnknown),
        ] {
            assert!(matches!(classify(unknown), PullError::NotFound));
        }
        // A digest is no evidence of anything, whatever digits it holds.
        assert!(matches!(
            classify(OciDistributionError::ServerError {
                code: 503,
                url: "http://r/v2/p/manifests/sha256:404404".to_string(),
                message: "code: 404".to_string(),
            }),
            PullError::Failed(_)
        ));
        for unanswered in [
            server(429),
            server(503),
            envelope(OciErrorCode::Toomanyrequests),
        ] {
            assert!(matches!(classify(unanswered), PullError::Failed(_)));
        }
    }

    /// A stream that stalls past its deadline ends in an error, not a wait.
    #[tokio::test(start_paused = true)]
    async fn a_blob_past_its_deadline_ends() {
        let pieces =
            futures::stream::iter([Ok(Bytes::from_static(b"1"))]).chain(futures::stream::pending());
        let end = Instant::now() + Duration::from_secs(5);
        let got: Vec<_> = pass_on(Box::pin(pieces), 8, end, ()).collect().await;
        assert_eq!(got.len(), 2);
        assert!(got[1].is_err());
    }

    #[test]
    fn only_a_sha256_digest_names_a_blob() {
        let hex = "ab".repeat(32);
        assert!(parse_digest(&format!("sha256:{hex}")).is_ok());
        for bad in [
            hex.clone(),
            format!("sha512:{hex}"),
            format!("sha256:{}", &hex[..63]),
            format!("sha256:{hex}/../x"),
            format!("sha256:{}", "zz".repeat(32)),
        ] {
            assert!(parse_digest(&bad).is_err(), "{bad}");
        }
    }

    /// Only a bearer, or none, is sent to a registry.
    #[test]
    fn a_registry_is_sent_a_bearer_or_nothing() {
        assert!(matches!(build_auth(b"").unwrap(), RegistryAuth::Anonymous));
        assert!(matches!(build_auth(b"Bearer t").unwrap(), RegistryAuth::Bearer(t) if t == "t"));
        for refused in [&b"Basic dTpw"[..], b"t", &[0xff, 0xfe]] {
            assert!(build_auth(refused).is_err());
        }
    }
}
