//! OCI pull handler: fetches artifacts from whichever registry the
//! TEE-supplied `policy_ref` points at, attaching `registry_auth`
//! verbatim. The hatch authenticates to no registry on its own.
//!
//! Trust note: the TEE recomputes `manifest_digest` and each layer
//! digest after receiving the response. We compute `manifest_digest`
//! as a convenience; the security property comes from TEE-side
//! recomputation.
//!
//! A fresh `Client` per pull: oci-client caches the first auth value it
//! sees with no invalidation API, so per-pull clients keep auth correct.
//!
//! Every guest on this host shares the hatch, so what one pull may cost it is
//! bounded: a few pulls at a time, each within a deadline, a manifest small
//! enough to read, and a total of bytes held — none of it sized by what the
//! registry says.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use oci_client::Reference;
use oci_client::client::{Client, ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
use oci_client::secrets::RegistryAuth;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWrite;
use tracing::warn;

use hatch_protocol::{PullRequest, PullResponse};

use crate::AppState;
use crate::error::{HatchError, decode_body, encode_body};

const MANIFEST_ACCEPTS: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// Pulls under way at once; the unit's memory limit is sized against it.
pub const CONCURRENT_PULLS: usize = 4;
/// What one pull holds, its layers together.
const PULL_BYTES: usize = 256 << 20;
/// A manifest names its layers in a few kilobytes; one far past that is not
/// parsed.
const MANIFEST_BYTES: usize = 256 << 10;
const LAYERS: usize = 16;
/// Under the TEE's own minute for a pull, waiting for a turn included, so the
/// hatch gives up on a pull no sooner than its caller and not long after.
const PULL_TIMEOUT: Duration = Duration::from_secs(55);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Between two reads of one response.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// POST /oci/pull
pub async fn pull(State(state): State<AppState>, body: Bytes) -> Result<Vec<u8>, HatchError> {
    let req: PullRequest = decode_body(&body)?;
    let (protocol, policy_ref) = scheme(&req.policy_ref);
    let reference = parse_ref(policy_ref)?;
    let auth = build_auth(&req.registry_auth)?;
    let client = build_client(protocol)?;

    let pulled = tokio::time::timeout(PULL_TIMEOUT, async {
        let _turn = state
            .pulls
            .acquire()
            .await
            .map_err(|e| HatchError::Internal(format!("pull: {e}")))?;
        do_pull(&client, &auth, &reference).await.map_err(|e| {
            warn!(reference = %reference, err = %e, "pull failed");
            classify_oci_error(e)
        })
    })
    .await
    .map_err(|_| {
        warn!(reference = %reference, "pull timed out");
        HatchError::Internal("pull: timed out".to_string())
    })?;
    let (manifest, layers) = pulled?;
    let digest = sha256_hex(&manifest);

    encode_body(&PullResponse {
        manifest,
        manifest_digest: format!("sha256:{digest}"),
        layers,
    })
}

/// Map an OCI error to an HTTP status. 404 / `MANIFEST_UNKNOWN` →
/// `NotFound` so the TEE-side client gets a typed not-found without the
/// substring-grep hack it used to do on gRPC status messages.
fn classify_oci_error(e: OciDistributionError) -> HatchError {
    let msg = format!("{e:?}");
    if msg.contains("MANIFEST_UNKNOWN") || msg.contains("code: 404") || msg.contains("404") {
        HatchError::NotFound
    } else {
        HatchError::Internal(format!("pull: {e}"))
    }
}

/// Require digest form (`@sha256:<hex>`) — the TEE only ever pins by
/// digest; a tag-form ref is a TEE bug or a host trying to move digest
/// resolution into our boundary. Loud reject (400).
fn parse_ref(policy_ref: &str) -> Result<Reference, HatchError> {
    let reference = Reference::try_from(policy_ref)
        .map_err(|e| HatchError::BadRequest(format!("invalid policy_ref: {e}")))?;
    if reference.digest().is_none() {
        return Err(HatchError::BadRequest(
            "policy_ref must be digest-pinned (`<registry>/<repo>@sha256:<hex>`)".to_string(),
        ));
    }
    Ok(reference)
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
fn scheme(policy_ref: &str) -> (ClientProtocol, &str) {
    if let Some(rest) = policy_ref.strip_prefix("http://") {
        (ClientProtocol::Http, rest)
    } else if let Some(rest) = policy_ref.strip_prefix("https://") {
        (ClientProtocol::Https, rest)
    } else {
        (ClientProtocol::Https, policy_ref)
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

/// Pull RAW manifest bytes + each layer payload. Raw bytes because the
/// registry's content-addressed digest is over these exact bytes;
/// re-serializing would change the sha256 and fail TEE verification.
async fn do_pull(
    client: &Client,
    auth: &RegistryAuth,
    reference: &Reference,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), OciDistributionError> {
    let (manifest_bytes, _server_digest) = client
        .pull_manifest_raw(reference, auth, MANIFEST_ACCEPTS)
        .await?;
    if manifest_bytes.len() > MANIFEST_BYTES {
        return Err(OciDistributionError::GenericError(Some(format!(
            "manifest of {} bytes, past {MANIFEST_BYTES}",
            manifest_bytes.len()
        ))));
    }
    let manifest_bytes = manifest_bytes.to_vec();

    let parsed: ManifestForLayers = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| OciDistributionError::GenericError(Some(format!("manifest parse: {e}"))))?;
    if parsed.layers.len() > LAYERS {
        return Err(OciDistributionError::GenericError(Some(format!(
            "manifest of {} layers, past {LAYERS}",
            parsed.layers.len()
        ))));
    }

    let mut left = PULL_BYTES;
    let mut payloads = Vec::with_capacity(parsed.layers.len());
    for descriptor in parsed.layers.iter() {
        // The digest alone, never the descriptor: a descriptor's `urls` would
        // have the client fetch from wherever the manifest names.
        let mut out = Capped::new(left);
        client
            .pull_blob(reference, descriptor.digest.as_str(), &mut out)
            .await?;
        left = out.left;
        payloads.push(out.held);
    }
    Ok((manifest_bytes, payloads))
}

/// Minimal manifest subset used to enumerate layer blobs. We deserialize
/// only to discover layer digests for `pull_blob`; bytes returned to the
/// TEE come straight from the registry.
#[derive(Deserialize)]
struct ManifestForLayers {
    layers: Vec<LayerForFetch>,
}

#[derive(Deserialize)]
struct LayerForFetch {
    digest: String,
}

/// A layer's bytes, taken as they arrive up to what the pull has left and
/// refused past it — however large the registry declared the layer.
struct Capped {
    held: Vec<u8>,
    left: usize,
}

impl Capped {
    fn new(left: usize) -> Self {
        Self {
            held: Vec::new(),
            left,
        }
    }
}

impl AsyncWrite for Capped {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.len() > self.left {
            return Poll::Ready(Err(io::Error::other(format!(
                "pull past {PULL_BYTES} bytes"
            ))));
        }
        self.left -= data.len();
        self.held.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

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

    #[tokio::test]
    async fn a_layer_is_taken_up_to_what_the_pull_has_left() {
        let mut out = Capped::new(8);
        out.write_all(b"12345").await.unwrap();
        assert!(out.write_all(b"6789").await.is_err());
        assert_eq!(out.held, b"12345");
        assert_eq!(out.left, 3);
    }
}
