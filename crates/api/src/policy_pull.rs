//! Policy artifact resolution: K_client validation at session create
//! time (cheap, manifest-only round-trip) and full pull-and-decrypt
//! lazily at /connect.
//!
//! Verifies digests at every step (host is NOT trusted on response
//! content — see Network Isolation), extracts the encrypted layer,
//! and age-decrypts it with K_client.

use std::collections::HashMap;
use std::io::Read;

use age::x25519::Identity;
use base64ct::Encoding;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use enclavid_host_bridge::{AuthN, RegistryClient};

const POLICY_LAYER_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.wasm.v1.encrypted";
/// Manifest annotation key holding an age-ciphertext token encrypted
/// to `K_client_pub`. POST /sessions decrypts this with the supplied
/// K_client to confirm the key matches the artifact, before storing
/// K_client in the session metadata. Saves us the cost of a full
/// policy pull at create time.
const VALIDATOR_ANNOTATION: &str = "com.enclavid.policy.validator";
/// Plaintext that the validator annotation is expected to decrypt to.
/// Semantically a "true" bool — the only information conveyed is
/// "K_client matches", which is binary. Single byte; the actual age
/// envelope is ~hundreds of bytes regardless because of the header
/// framing, so plaintext minimisation is purely for clarity, not
/// wire size.
const VALIDATOR_PLAINTEXT: &[u8] = &[1u8];

#[derive(Debug, thiserror::Error)]
pub enum PullError {
    #[error("registry transport: {0}")]
    Transport(String),
    #[error("manifest JSON malformed: {0}")]
    ManifestParse(String),
    #[error("manifest digest mismatch: expected {expected}, got {actual}")]
    ManifestDigest { expected: String, actual: String },
    #[error("layer digest mismatch at index {index}: expected {expected}, got {actual}")]
    LayerDigest {
        index: usize,
        expected: String,
        actual: String,
    },
    #[error("manifest declares no layer with the policy media type")]
    NoPolicyLayer,
    #[error("manifest layer/payload count mismatch: {layers} vs {payloads}")]
    LayerCountMismatch { layers: usize, payloads: usize },
    #[error("decryption failed (wrong K_client?)")]
    Decrypt,
    #[error("manifest is missing the validator annotation")]
    MissingValidator,
    #[error("validator token base64 malformed: {0}")]
    ValidatorBase64(String),
    #[error("validator token did not decrypt to the expected plaintext")]
    ValidatorMismatch,
}

/// Result of a successful pull-and-decrypt.
pub struct DecryptedPolicy {
    /// Decrypted wasm. Ready to compile with wasmtime.
    pub wasm_bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct OciManifest {
    layers: Vec<OciDescriptor>,
    #[serde(default)]
    annotations: HashMap<String, String>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
}

/// Cheap K_client validation against the manifest's validator
/// annotation. Pulls only the manifest (no layer payloads), verifies
/// digest, decrypts the validator ciphertext with K_client, and
/// confirms it produces the expected plaintext.
///
/// Used at `POST /sessions` so that wrong-K_client errors surface
/// synchronously to the client API call instead of breaking later
/// during applicant flow.
pub async fn validate_k_client(
    registry: &RegistryClient,
    workspace_id: &str,
    policy_name: &str,
    policy_digest: &str,
    k_client: &Identity,
) -> Result<(), PullError> {
    let response = registry
        .pull_manifest(workspace_id, policy_name, policy_digest)
        .await
        .map_err(|e| PullError::Transport(format!("{e:?}")))?
        .trust::<AuthN, _, _, _>(|r| {
            // Same digest verification as in `pull_and_decrypt` — the
            // bytes must hash to the digest the session record was
            // pinned against.
            let manifest_actual = sha256_hex(&r.manifest);
            if !digest_matches(policy_digest, &manifest_actual) {
                return Err(PullError::ManifestDigest {
                    expected: policy_digest.to_string(),
                    actual: format!("sha256:{manifest_actual}"),
                });
            }
            if r.manifest_digest != manifest_actual
                && r.manifest_digest != format!("sha256:{manifest_actual}")
            {
                return Err(PullError::ManifestDigest {
                    expected: format!("sha256:{manifest_actual}"),
                    actual: r.manifest_digest.clone(),
                });
            }
            Ok(())
        })?
        .into_inner();

    let manifest: OciManifest = serde_json::from_slice(&response.manifest)
        .map_err(|e| PullError::ManifestParse(e.to_string()))?;
    let token_b64 = manifest
        .annotations
        .get(VALIDATOR_ANNOTATION)
        .ok_or(PullError::MissingValidator)?;
    let token = base64ct::Base64::decode_vec(token_b64)
        .map_err(|e| PullError::ValidatorBase64(format!("{e:?}")))?;
    let plaintext = age_decrypt(&token, k_client).map_err(|_| PullError::Decrypt)?;
    if plaintext != VALIDATOR_PLAINTEXT {
        return Err(PullError::ValidatorMismatch);
    }
    Ok(())
}

pub async fn pull_and_decrypt(
    registry: &RegistryClient,
    workspace_id: &str,
    policy_name: &str,
    policy_digest: &str,
    k_client: &Identity,
) -> Result<DecryptedPolicy, PullError> {
    // The registry response carries only (AuthN) — Replay is N/A
    // for content-addressed pulls. The AuthN trust gate below closes
    // via cryptographic verification: we only accept the response if
    // all digests recompute to what the session record asked for.
    let response = registry
        .pull(workspace_id, policy_name, policy_digest)
        .await
        .map_err(|e| PullError::Transport(format!("{e:?}")))?
        .trust::<AuthN, _, _, _>(|r| {
            // Manifest bytes must hash to what the session record was
            // created against (passed in as `policy_digest`).
            let manifest_actual = sha256_hex(&r.manifest);
            if !digest_matches(policy_digest, &manifest_actual) {
                return Err(PullError::ManifestDigest {
                    expected: policy_digest.to_string(),
                    actual: format!("sha256:{manifest_actual}"),
                });
            }
            // Soft check: host's self-reported manifest_digest should
            // agree with the recomputed one. If not, the host is
            // internally inconsistent — treat as a transport bug.
            if r.manifest_digest != manifest_actual
                && r.manifest_digest != format!("sha256:{manifest_actual}")
            {
                return Err(PullError::ManifestDigest {
                    expected: format!("sha256:{manifest_actual}"),
                    actual: r.manifest_digest.clone(),
                });
            }

            // Parse manifest, validate per-layer payload digests.
            let manifest: OciManifest = serde_json::from_slice(&r.manifest)
                .map_err(|e| PullError::ManifestParse(e.to_string()))?;

            if manifest.layers.len() != r.layers.len() {
                return Err(PullError::LayerCountMismatch {
                    layers: manifest.layers.len(),
                    payloads: r.layers.len(),
                });
            }
            for (idx, (descriptor, payload)) in
                manifest.layers.iter().zip(r.layers.iter()).enumerate()
            {
                let layer_actual = sha256_hex(payload);
                if !digest_matches(&descriptor.digest, &layer_actual) {
                    return Err(PullError::LayerDigest {
                        index: idx,
                        expected: descriptor.digest.clone(),
                        actual: format!("sha256:{layer_actual}"),
                    });
                }
            }
            Ok(())
        })?
        .into_inner();

    // After trust gate: response is plain `PullResponse`. Re-parse the
    // manifest (cheap — JSON is small) to find the encrypted-policy layer.
    let manifest: OciManifest = serde_json::from_slice(&response.manifest)
        .map_err(|e| PullError::ManifestParse(e.to_string()))?;
    let (idx, _descriptor) = manifest
        .layers
        .iter()
        .enumerate()
        .find(|(_, l)| l.media_type == POLICY_LAYER_MEDIA_TYPE)
        .ok_or(PullError::NoPolicyLayer)?;

    // Decrypt with K_client. Failure here is a domain error (wrong
    // key, corrupted artifact) — surfaces from /connect as 410 Gone.
    let layer_bytes = &response.layers[idx];
    let wasm_bytes = age_decrypt(layer_bytes, k_client).map_err(|_| PullError::Decrypt)?;
    Ok(DecryptedPolicy { wasm_bytes })
}

fn age_decrypt(ciphertext: &[u8], identity: &Identity) -> Result<Vec<u8>, age::DecryptError> {
    let decryptor = age::Decryptor::new(ciphertext)?;
    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out).map_err(age::DecryptError::Io)?;
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Accepts `expected` either as `sha256:<hex>` or just `<hex>`, compares
/// against the bare hex `actual`.
fn digest_matches(expected: &str, actual_hex: &str) -> bool {
    let expected_hex = expected.strip_prefix("sha256:").unwrap_or(expected);
    expected_hex.eq_ignore_ascii_case(actual_hex)
}
