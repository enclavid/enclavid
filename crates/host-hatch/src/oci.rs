//! OCI pull handlers: fetch from whichever registry the TEE-supplied reference
//! points at, attaching `registry_auth` verbatim. The hatch authenticates to no
//! registry on its own.
//!
//! Two steps, and the hatch parses neither: the raw manifest a pinned reference
//! names (`/oci/manifest`), then the one blob of it the TEE chose by digest
//! (`/oci/blob`), streamed as the response body as it comes from the registry.
//! Which blob, and whether any of the bytes are what the reference pins, the TEE
//! decides — it recomputes the manifest's digest against the pin, picks the
//! layer from the manifest it verified, and holds the blob to that layer's
//! digest and size as it reads it.
//!
//! A fresh `Client` per call: oci-client caches the first auth value it sees
//! with no invalidation API, so per-call clients keep auth correct.
//!
//! Every guest on this host shares the hatch, so what one pull may cost it is
//! bounded: so many manifests and so many blobs at a time, counted apart, a
//! blob counted for as long as its stream runs, a manifest small enough to
//! read, a blob's bytes capped and its stream given a deadline — none of it
//! sized by what the registry says. Nothing of a blob is held here beyond the
//! piece in hand. How many of those one consumer's sessions have under way at
//! once is bounded where the consumer is known, inside the TEE.

use std::time::Duration;

use anyhow::Context;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::Response;
use futures::{StreamExt, TryStreamExt};
use oci_client::Reference;
use oci_client::client::{Client, ClientConfig, ClientProtocol};
use oci_client::errors::{OciDistributionError, OciErrorCode};
use oci_client::secrets::RegistryAuth;
use tokio::time::{Instant, timeout, timeout_at};
use tracing::warn;

use hatch_protocol::{BlobRequest, ManifestRequest, ManifestResponse};

use crate::AppState;
use crate::error::{HatchError, decode_body, encode_body};

const MANIFEST_ACCEPTS: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// Manifests fetched at once, unless the host says otherwise
/// (`HATCH_CONCURRENT_MANIFESTS`). Counted apart from blobs, so a check waits
/// on no blob stream; each is read whole, at most [`MANIFEST_BYTES`], so all of
/// them together are 32 MiB at most. Many times what one consumer may have
/// under way at once, so it takes that many consumers to hold them all.
pub const DEFAULT_CONCURRENT_MANIFESTS: usize = 128;
/// Blobs streamed at once, unless the host says otherwise
/// (`HATCH_CONCURRENT_BLOBS`), each counted for as long as its stream runs and
/// each holding one piece at a time. More of them only share the host's
/// bandwidth further.
pub const DEFAULT_CONCURRENT_BLOBS: usize = 8;

/// The count a setting names: `default` when it is unset, a count above zero
/// otherwise, or no start.
pub fn concurrent(name: &str, default: usize) -> anyhow::Result<usize> {
    let count = match std::env::var(name).ok() {
        None => default,
        Some(n) => n
            .parse()
            .with_context(|| format!("{name}: a count above zero"))?,
    };
    anyhow::ensure!(count > 0, "{name}: a count above zero");
    Ok(count)
}
/// A manifest names its layers in a few kilobytes; one far past that is not
/// parsed.
const MANIFEST_BYTES: usize = 256 << 10;
/// The most of one blob this passes on: above the largest a TEE takes, which
/// it holds to the size the manifest declares.
const BLOB_BYTES: u64 = 2 << 30;
/// Under the TEE's own minute for a manifest, waiting for a turn included, so
/// the hatch gives up no sooner than its caller and not long after.
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(55);
/// The longest one blob's stream may hold a turn, waiting for it included. The
/// TEE ends its read sooner, at its own deadline, which ends this stream with
/// it; this bounds a stream nobody is reading any more.
const BLOB_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Between two reads of one response.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// POST /oci/manifest
pub async fn manifest(State(state): State<AppState>, body: Bytes) -> Result<Vec<u8>, HatchError> {
    let req: ManifestRequest = decode_body(&body)?;
    let (protocol, reference) = scheme(&req.reference);
    let reference = parse_ref(reference)?;
    let auth = build_auth(&req.registry_auth)?;
    let client = build_client(protocol)?;

    let manifest = timeout(MANIFEST_TIMEOUT, async {
        let _turn = state
            .manifests
            .acquire()
            .await
            .map_err(|e| HatchError::Internal(format!("pull: {e}")))?;
        let (manifest, _) = client
            .pull_manifest_raw(&reference, &auth, MANIFEST_ACCEPTS)
            .await
            .map_err(|e| {
                warn!(reference = %reference, err = %e, "manifest pull failed");
                classify_oci_error(e)
            })?;
        Ok::<_, HatchError>(manifest)
    })
    .await
    .map_err(|_| {
        warn!(reference = %reference, "manifest pull timed out");
        HatchError::Internal("manifest: timed out".to_string())
    })??;
    if manifest.len() > MANIFEST_BYTES {
        return Err(HatchError::Internal(format!(
            "manifest of {} bytes, past {MANIFEST_BYTES}",
            manifest.len()
        )));
    }
    encode_body(&ManifestResponse {
        manifest: manifest.to_vec(),
    })
}

/// POST /oci/blob
///
/// The answer's status says whether the blob's stream started; a failure after
/// that — the registry's, the cap's, the deadline's — ends the body short,
/// which the TEE reads as a blob that did not arrive.
pub async fn blob(State(state): State<AppState>, body: Bytes) -> Result<Response, HatchError> {
    let req: BlobRequest = decode_body(&body)?;
    let (protocol, reference) = scheme(&req.reference);
    let reference = parse_ref(reference)?;
    let digest = parse_digest(&req.digest)?;
    let auth = build_auth(&req.registry_auth)?;
    let client = build_client(protocol)?;

    let end = Instant::now() + BLOB_TIMEOUT;
    let (turn, stream) = timeout_at(end, async {
        let turn = state
            .blobs
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| HatchError::Internal(format!("pull: {e}")))?;
        // The digest alone, never a descriptor: a descriptor's `urls` would
        // have the client fetch from wherever the manifest names.
        // This client has fetched nothing yet, so it holds no token to send.
        client
            .auth(&reference, &auth, oci_client::RegistryOperation::Pull)
            .await
            .map_err(classify_oci_error)?;
        let stream = client
            .pull_blob_stream(&reference, digest)
            .await
            .map_err(|e| {
                warn!(reference = %reference, err = %e, "blob pull failed");
                classify_oci_error(e)
            })?;
        Ok::<_, HatchError>((turn, stream))
    })
    .await
    .map_err(|_| HatchError::Internal("blob: timed out".to_string()))??;

    let pieces = pass_on(
        stream.stream.map_err(std::io::Error::other),
        BLOB_BYTES,
        end,
        turn,
    );
    Ok(Response::new(Body::from_stream(pieces)))
}

/// `pieces` as the answer's body: refused past `cap` bytes together or past
/// `end`, and ended at the first refusal or failure. `turn` is held for as long
/// as the stream runs — given back when it ends or is dropped, and not before.
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

/// Map an OCI error to an HTTP status. The registry refusing the bearer →
/// `Forbidden`; 404 / `MANIFEST_UNKNOWN` / `BLOB_UNKNOWN` → `NotFound`; so the
/// TEE-side client can tell both from a registry that did not answer.
fn classify_oci_error(e: OciDistributionError) -> HatchError {
    let refused = match &e {
        OciDistributionError::UnauthorizedError { .. } => true,
        OciDistributionError::ServerError { code, .. } => matches!(code, 401 | 403),
        OciDistributionError::RegistryError { envelope, .. } => envelope
            .errors
            .iter()
            .any(|e| matches!(e.code, OciErrorCode::Unauthorized | OciErrorCode::Denied)),
        _ => false,
    };
    if refused {
        return HatchError::Forbidden;
    }
    let msg = format!("{e:?}");
    if msg.contains("MANIFEST_UNKNOWN")
        || msg.contains("BLOB_UNKNOWN")
        || msg.contains("code: 404")
        || msg.contains("404")
    {
        HatchError::NotFound
    } else {
        HatchError::Internal(format!("pull: {e}"))
    }
}

/// Require digest form (`@sha256:<hex>`) — the TEE only ever pins by
/// digest; a tag-form ref is a TEE bug or a host trying to move digest
/// resolution into our boundary. Loud reject (400).
fn parse_ref(reference: &str) -> Result<Reference, HatchError> {
    let parsed = Reference::try_from(reference)
        .map_err(|e| HatchError::BadRequest(format!("invalid reference: {e}")))?;
    if parsed.digest().is_none() {
        return Err(HatchError::BadRequest(
            "reference must be digest-pinned (`<registry>/<repo>@sha256:<hex>`)".to_string(),
        ));
    }
    Ok(parsed)
}

/// A blob digest is `sha256:` and 64 hex digits, and nothing else is fetched
/// by one.
fn parse_digest(digest: &str) -> Result<&str, HatchError> {
    let hex = digest
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    hex.map(|_| digest)
        .ok_or_else(|| HatchError::BadRequest("a blob digest is `sha256:<64 hex>`".to_string()))
}

/// Translate the opaque bearer into oci-client's typed `RegistryAuth`.
/// Empty → anonymous. Only `Bearer <token>` is recognized today.
fn build_auth(registry_auth: &[u8]) -> Result<RegistryAuth, HatchError> {
    if registry_auth.is_empty() {
        return Ok(RegistryAuth::Anonymous);
    }
    let s = std::str::from_utf8(registry_auth)
        .map_err(|_| HatchError::BadRequest("registry_auth not utf-8".to_string()))?
        .trim();
    if let Some(token) = s
        .strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))
    {
        return Ok(RegistryAuth::Bearer(token.to_string()));
    }
    Err(HatchError::BadRequest(
        "registry_auth must be `Bearer <token>` (or empty for anonymous)".to_string(),
    ))
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

fn build_client(protocol: ClientProtocol) -> Result<Client, HatchError> {
    Client::try_from(ClientConfig {
        protocol,
        connect_timeout: Some(CONNECT_TIMEOUT),
        read_timeout: Some(READ_TIMEOUT),
        ..Default::default()
    })
    .map_err(|e| HatchError::Internal(format!("registry client: {e}")))
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
    /// and from one that did not answer, so the TEE can tell a session to stop
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
            assert!(matches!(classify_oci_error(refused), HatchError::Forbidden));
        }
        assert!(matches!(
            classify_oci_error(server(404)),
            HatchError::NotFound
        ));
        for unanswered in [
            server(429),
            server(503),
            envelope(OciErrorCode::Toomanyrequests),
        ] {
            assert!(matches!(
                classify_oci_error(unanswered),
                HatchError::Internal(_)
            ));
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
}
