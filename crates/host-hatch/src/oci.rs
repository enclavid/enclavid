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

use oci_client::Reference;
use oci_client::client::{Client, ClientConfig, ClientProtocol};
use oci_client::secrets::RegistryAuth;
use axum::body::Bytes;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

use hatch_protocol::{PullRequest, PullResponse};

use crate::error::{HatchError, decode_body, encode_body};

const MANIFEST_ACCEPTS: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// POST /oci/pull
pub async fn pull(body: Bytes) -> Result<Vec<u8>, HatchError> {
    let req: PullRequest = decode_body(&body)?;
    let reference = parse_ref(&req.policy_ref)?;
    let auth = build_auth(&req.registry_auth)?;
    let client = build_client(reference.registry());

    let (manifest, layers) = do_pull(&client, &auth, &reference).await.map_err(|e| {
        warn!(reference = %reference, err = %e, "pull failed");
        classify_oci_error(e)
    })?;
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
fn classify_oci_error(e: oci_client::errors::OciDistributionError) -> HatchError {
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
    if let Some(token) = s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")) {
        return Ok(RegistryAuth::Bearer(token.to_string()));
    }
    Err(HatchError::BadRequest(
        "registry_auth must be `Bearer <token>` (or empty for anonymous)".to_string(),
    ))
}

fn build_client(registry_host: &str) -> Client {
    Client::new(ClientConfig {
        protocol: detect_protocol(registry_host),
        ..Default::default()
    })
}

/// Pull RAW manifest bytes + each layer payload. Raw bytes because the
/// registry's content-addressed digest is over these exact bytes;
/// re-serializing would change the sha256 and fail TEE verification.
async fn do_pull(
    client: &Client,
    auth: &RegistryAuth,
    reference: &Reference,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), oci_client::errors::OciDistributionError> {
    let (manifest_bytes, _server_digest) = client
        .pull_manifest_raw(reference, auth, MANIFEST_ACCEPTS)
        .await?;
    let manifest_bytes = manifest_bytes.to_vec();

    let parsed: ManifestForLayers = serde_json::from_slice(&manifest_bytes).map_err(|e| {
        oci_client::errors::OciDistributionError::GenericError(Some(format!("manifest parse: {e}")))
    })?;

    let mut payloads = Vec::with_capacity(parsed.layers.len());
    for descriptor in parsed.layers.iter() {
        let mut buf = Vec::with_capacity(descriptor.size.max(0) as usize);
        client
            .pull_blob(reference, descriptor.digest.as_str(), &mut buf)
            .await?;
        payloads.push(buf);
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
    #[serde(default)]
    size: i64,
}

fn detect_protocol(registry: &str) -> ClientProtocol {
    if registry.starts_with("localhost") || registry.starts_with("127.0.0.1") {
        ClientProtocol::Http
    } else {
        ClientProtocol::Https
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
