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

use crate::limits::MAX_POLICY_MANIFEST_BYTES;

/// OCI layer media-type for the encrypted polici wasm. Decrypted
/// inside the TEE with K_client.
const POLICY_WASM_LAYER: &str = "application/vnd.enclavid.policy.wasm.v1.encrypted";
/// OCI layer media-type for the polici manifest (frozen text-ref
/// registry: disclosure_fields + localized translations + schema
/// version). Plain JSON — applicant-facing UI strings are public by
/// nature, integrity comes from the OCI manifest content-addressing.
/// Optional: polici with no host-visible UI (decision-only stubs)
/// can ship without this layer.
const POLICY_MANIFEST_LAYER: &str = "application/vnd.enclavid.policy.manifest.v1.json";
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
    #[error("policy_ref must be `<registry>/<repository>@sha256:<hex>`: {0}")]
    InvalidRef(String),
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
    #[error("policy manifest layer is {size} bytes, max is {max}")]
    ManifestTooLarge { size: usize, max: usize },
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

/// Result of a successful pull-and-decrypt: the polici's executable
/// wasm plus its (optional) frozen policy manifest. The two layers
/// live side-by-side in the OCI artifact but ship with different
/// confidentiality treatments — wasm is K_client-encrypted
/// (proprietary algorithm), policy manifest is plain JSON
/// (applicant-facing UI strings + machine keys, inspectable for
/// audit). Both are integrity-checked by the OCI content-addressing
/// chain.
pub struct PolicyArtifact {
    /// Decrypted wasm. Ready to compile with wasmtime.
    pub wasm_bytes: Vec<u8>,
    /// Policy manifest bytes verbatim (JSON). `None` if the OCI
    /// manifest declares no manifest layer — polici without
    /// host-visible UI (decision-only stubs, test fixtures) can omit
    /// it. Engine caller treats `None` as an empty registry.
    pub manifest_bytes: Option<Vec<u8>>,
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
    policy_ref: &str,
    registry_auth: &[u8],
    k_client: &Identity,
) -> Result<(), PullError> {
    let policy_digest = extract_digest(policy_ref)
        .ok_or_else(|| PullError::InvalidRef(policy_ref.to_string()))?;
    let response = registry
        .pull_manifest(policy_ref, registry_auth)
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
    policy_ref: &str,
    registry_auth: &[u8],
    k_client: &Identity,
) -> Result<PolicyArtifact, PullError> {
    let policy_digest = extract_digest(policy_ref)
        .ok_or_else(|| PullError::InvalidRef(policy_ref.to_string()))?;
    // The registry response carries only (AuthN) — Replay is N/A
    // for content-addressed pulls. The AuthN trust gate below closes
    // via cryptographic verification: we only accept the response if
    // all digests recompute to what the session record asked for.
    let response = registry
        .pull(policy_ref, registry_auth)
        .await
        .map_err(|e| PullError::Transport(format!("{e:?}")))?
        .trust::<AuthN, _, _, _>(|r| {
            // Manifest bytes must hash to the digest baked into
            // `policy_ref` (which was pinned at session-create time).
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
    // manifest (cheap — JSON is small) to dispatch layers by
    // media-type. Wasm layer is required; assets layer is optional.
    let manifest: OciManifest = serde_json::from_slice(&response.manifest)
        .map_err(|e| PullError::ManifestParse(e.to_string()))?;

    let mut wasm_bytes: Option<Vec<u8>> = None;
    let mut manifest_bytes: Option<Vec<u8>> = None;
    for (idx, descriptor) in manifest.layers.iter().enumerate() {
        let payload = &response.layers[idx];
        match descriptor.media_type.as_str() {
            POLICY_WASM_LAYER => {
                // K_client-encrypted; decrypt for compilation.
                let plaintext =
                    age_decrypt(payload, k_client).map_err(|_| PullError::Decrypt)?;
                wasm_bytes = Some(plaintext);
            }
            POLICY_MANIFEST_LAYER => {
                // Plain JSON; integrity already verified via the
                // descriptor digest in the trust gate above.
                // Transport cap: protect TEE from a malformed /
                // malicious artifact that ships a megabyte-sized
                // manifest. Engine-side `load_manifest` still
                // applies an entry-count cap on top of this.
                if payload.len() > MAX_POLICY_MANIFEST_BYTES {
                    return Err(PullError::ManifestTooLarge {
                        size: payload.len(),
                        max: MAX_POLICY_MANIFEST_BYTES,
                    });
                }
                manifest_bytes = Some(payload.clone());
            }
            _ => {
                // Unknown media-type — ignore for forward-compat.
                // Future versions may add new layer types; older
                // hosts should skip them rather than refuse to load.
            }
        }
    }

    let wasm_bytes = wasm_bytes.ok_or(PullError::NoPolicyLayer)?;
    Ok(PolicyArtifact { wasm_bytes, manifest_bytes })
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

/// Split a pinned OCI reference `<repo>@sha256:<hex>` into its parts.
/// `<repo>` may include the registry hostname (e.g.
/// `registry.example.com/path`). Returns None for tag-form refs (no
/// `@`) or non-sha256 digest algorithms — TEE only accepts pinned
/// sha256 refs.
pub fn split_pinned_ref(policy_ref: &str) -> Option<(&str, &str)> {
    let (repo, digest) = policy_ref.rsplit_once('@')?;
    if !digest.starts_with("sha256:") {
        return None;
    }
    Some((repo, digest))
}

/// Extract just the `sha256:<hex>` digest substring from a pinned ref.
fn extract_digest(policy_ref: &str) -> Option<&str> {
    split_pinned_ref(policy_ref).map(|(_, d)| d)
}
