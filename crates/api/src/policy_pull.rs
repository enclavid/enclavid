//! Pull-and-decrypt of an encrypted policy artifact.
//!
//! Called from /init after K_client is unwrapped. Walks the OCI manifest
//! returned by `RegistryClient`, verifies digests at every step (host is
//! NOT trusted on response content — see Network Isolation), extracts
//! the encrypted layer, and age-decrypts it with K_client.

use std::io::Read;

use age::x25519::Identity;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use enclavid_session_store::RegistryClient;

const POLICY_LAYER_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.wasm.v1.encrypted";

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
}

/// Result of a successful pull-and-decrypt.
pub struct DecryptedPolicy {
    /// sha256 of the encrypted policy layer = manifest layer digest. The
    /// "encrypted hash" we bind into attestation as `D_enc`.
    pub d_enc: String,
    /// sha256 of the decrypted wasm bytes. The "plaintext hash" bound
    /// into attestation as `D_plain`.
    pub d_plain: String,
    /// Decrypted wasm. Ready to compile with wasmtime.
    pub wasm_bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct OciManifest {
    layers: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
}

pub async fn pull_and_decrypt(
    registry: &RegistryClient,
    workspace_id: &str,
    policy_name: &str,
    policy_digest: &str,
    k_client: &Identity,
) -> Result<DecryptedPolicy, PullError> {
    // The registry response is `Untrusted<PullResponse>` — host can swap
    // bytes freely. The trust gate below is the cryptographic verification
    // that closes the gap: we only accept the response if all digests
    // recompute to what the session record asked for.
    let response = registry
        .pull(workspace_id, policy_name, policy_digest)
        .await
        .map_err(|e| PullError::Transport(format!("{e:?}")))?
        .trust(|r| {
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
        })?;

    // After trust gate: response is plain `PullResponse`. Re-parse the
    // manifest (cheap — JSON is small) to find the encrypted-policy layer.
    let manifest: OciManifest = serde_json::from_slice(&response.manifest)
        .map_err(|e| PullError::ManifestParse(e.to_string()))?;
    let (idx, descriptor) = manifest
        .layers
        .iter()
        .enumerate()
        .find(|(_, l)| l.media_type == POLICY_LAYER_MEDIA_TYPE)
        .ok_or(PullError::NoPolicyLayer)?;

    // Decrypt with K_client. Failure here is a domain error (wrong key,
    // corrupted artifact) and is what triggers FailedInit at the handler
    // layer.
    let layer_bytes = &response.layers[idx];
    let wasm_bytes = age_decrypt(layer_bytes, k_client).map_err(|_| PullError::Decrypt)?;
    let d_plain = sha256_hex(&wasm_bytes);

    Ok(DecryptedPolicy {
        d_enc: descriptor.digest.clone(),
        d_plain: format!("sha256:{d_plain}"),
        wasm_bytes,
    })
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
