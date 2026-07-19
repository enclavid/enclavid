//! Policy + plugin artifact resolution. Pulls OCI artifacts (manifest +
//! single wasm layer), verifies every digest in the TEE against the
//! pinned reference, and returns wasm bytes ready to compile. The
//! policy and plugin paths share a common trust gate so a single
//! integrity-check path covers both artifact kinds.

use std::collections::HashMap;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use broker_client::{
    AuthN, AuthZ, Covert, Key, PullRequest, RegistryClient, Replay, boundary, reason,
};
use enclavid_crypto::ocicrypt;

use crate::keyprovider::{self, KbsContext};

/// OCI layer media type for wasm component layers (policies and
/// plugins both). Per `[[project-wkg-wac-poc-findings]]`, wkg's pull
/// whitelist accepts only `application/wasm` — unified across all
/// artifact kinds.
const WASM_LAYER: &str = "application/wasm";

#[derive(Debug, thiserror::Error)]
pub enum PullError {
    /// Registry told us "this manifest doesn't exist" (HTTP 404
    /// `MANIFEST_UNKNOWN`). Distinct from `Transport` so callers can
    /// surface 404 to the API consumer rather than swallowing it as
    /// a generic transport / processing error.
    #[error("manifest not found in registry")]
    NotFound,
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
    #[error("manifest declares no layer with the wasm media type")]
    NoWasmLayer,
    #[error("manifest layer/payload count mismatch: {layers} vs {payloads}")]
    LayerCountMismatch { layers: usize, payloads: usize },
    #[error("artifact decryption failed: {0}")]
    Decrypt(String),
}

/// Map a bridge transport error to a `PullError`. The broker classifies
/// OCI 404 / `MANIFEST_UNKNOWN` natively (it's the one talking OCI) and
/// returns the typed `BridgeError::NotFound`, so we match on the variant
/// instead of grepping a Debug string.
fn classify_transport_error(e: broker_client::BridgeError) -> PullError {
    match e {
        broker_client::BridgeError::NotFound => PullError::NotFound,
        other => PullError::Transport(format!("{other:?}")),
    }
}

/// Result of a successful policy pull: the policy's wasm component
/// bytes, ready for compile. Any embedded text-ref declarations
/// (`enclavid:embedded.disclosure-fields.v1`,
/// `enclavid:embedded.i18n.v1`) live inside the wasm as component-
/// level custom sections; the caller extracts them via
/// `engine_compiler::load_embedded`. No sidecar layer.
pub struct PolicyArtifact {
    /// Wasm bytes ready to compile with wasmtime.
    pub wasm_bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct OciManifest {
    layers: Vec<OciDescriptor>,
    #[serde(default)]
    #[allow(dead_code)]
    annotations: HashMap<String, String>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    /// ocicrypt stores the wrapped key + public cipher opts here (on the
    /// layer descriptor). Empty for plaintext layers.
    #[serde(default)]
    annotations: HashMap<String, String>,
}

/// Pull and integrity-check a policy OCI artifact. Returns the
/// `application/wasm` layer bytes after recomputing every digest
/// against the pinned reference.
pub async fn pull_policy(
    registry: &RegistryClient,
    policy_ref: &str,
    registry_auth: &[u8],
    key: Option<&Key>,
    kbs_ctx: Option<&KbsContext<'_>>,
) -> Result<PolicyArtifact, PullError> {
    let wasm_bytes = pull_wasm_layer(registry, policy_ref, registry_auth, key, kbs_ctx).await?;
    Ok(PolicyArtifact { wasm_bytes })
}

/// One pulled plugin component. Same shape as `PolicyArtifact`; kept as
/// a distinct type so future plugin-specific metadata (per-plugin
/// embedded sections, signed attestation, …) can land without
/// touching policy code paths.
///
/// Plugins are pure compute under our trust model — they may not import
/// any host function — so they ship no embedded declarations sections.
pub struct PluginArtifact {
    /// Plain wasm component bytes — ready to compile with wasmtime.
    pub wasm_bytes: Vec<u8>,
}

/// Pull and integrity-check a plugin OCI artifact. Identical trust
/// path to `pull_policy` (host is untrusted on response content;
/// every hash recomputed in the TEE against the pinned digest).
pub async fn pull_plugin(
    registry: &RegistryClient,
    plugin_ref: &str,
    registry_auth: &[u8],
    key: Option<&Key>,
    kbs_ctx: Option<&KbsContext<'_>>,
) -> Result<PluginArtifact, PullError> {
    let wasm_bytes = pull_wasm_layer(registry, plugin_ref, registry_auth, key, kbs_ctx).await?;
    Ok(PluginArtifact { wasm_bytes })
}

/// Shared trust path for policy and plugin pulls. Verifies manifest
/// digest + every layer digest against the pinned reference inside the
/// trust gate, then extracts the first `application/wasm` layer.
async fn pull_wasm_layer(
    registry: &RegistryClient,
    artifact_ref: &str,
    registry_auth: &[u8],
    key: Option<&Key>,
    kbs_ctx: Option<&KbsContext<'_>>,
) -> Result<Vec<u8>, PullError> {
    let artifact_digest = extract_digest(artifact_ref)
        .ok_or_else(|| PullError::InvalidRef(artifact_ref.to_string()))?;
    let req = boundary::outbound::to_untrusted(PullRequest {
        policy_ref: artifact_ref.to_string(),
        registry_auth: registry_auth.to_vec(),
    })
    .vouch_unchecked::<AuthN, _>(reason!(
        "policy_ref public (digest-pinned); registry_auth is the consumer's bearer, \
         courier-forwarded — not a TEE secret"
    ))
    .vouch_unchecked::<AuthZ, _>(reason!(
        "forwarding the bearer to its registry IS the courier op"
    ))
    .vouch_unchecked::<Covert, _>(reason!(
        "both consumer-supplied at session create, not policy-controlled"
    ));
    let response = registry
        .pull(req)
        .await
        .map_err(classify_transport_error)?
        .trust::<AuthN, _, _, _, _>(|r| {
            // Manifest bytes must hash to the pinned digest.
            let manifest_actual = sha256_hex(&r.manifest);
            if !digest_matches(artifact_digest, &manifest_actual) {
                return Err(PullError::ManifestDigest {
                    expected: artifact_digest.to_string(),
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
            Ok(r)
        })?
        .trust_unchecked::<AuthZ, _>(reason!(
            "OCI registry server enforces pull authorisation with the host-supplied \
             bearer; TEE doesn't gate access at this layer"
        ))
        .trust_unchecked::<Replay, _>(reason!(
            "content-addressed by digest — bit-identical responses for the same digest"
        ))
        .into_inner();

    let manifest: OciManifest = serde_json::from_slice(&response.manifest)
        .map_err(|e| PullError::ManifestParse(e.to_string()))?;

    // Select the wasm layer: plaintext `application/wasm`, or the
    // ocicrypt-encrypted `application/wasm+encrypted`. Digests above were
    // verified over the (cipher)text bytes exactly as the manifest pins
    // them, so the integrity gate is unaffected by encryption.
    for (idx, descriptor) in manifest.layers.iter().enumerate() {
        if descriptor.media_type == WASM_LAYER {
            // Plaintext layer. A supplied key means the client expected
            // encryption — refuse rather than silently serving cleartext.
            if key.is_some() {
                return Err(PullError::Decrypt(
                    "a key was supplied but the layer is not encrypted".to_string(),
                ));
            }
            return Ok(response.layers[idx].clone());
        }
        if let Some(inner) = descriptor.media_type.strip_suffix(ocicrypt::ENCRYPTED_MEDIA_SUFFIX) {
            if inner != WASM_LAYER {
                continue;
            }
            let key = key.ok_or_else(|| {
                PullError::Decrypt("layer is encrypted but no key was supplied".to_string())
            })?;
            return decrypt_layer(
                &response.layers[idx],
                &descriptor.annotations,
                key,
                kbs_ctx,
            )
            .await;
        }
    }
    Err(PullError::NoWasmLayer)
}

/// Decrypt an ocicrypt-encrypted wasm layer: read the public cipher opts
/// from the `enc.pubopts` annotation, obtain the private opts via the
/// key dispatch, and run the AES-256-CTR+HMAC decryption.
async fn decrypt_layer(
    ciphertext: &[u8],
    annotations: &HashMap<String, String>,
    key: &Key,
    kbs_ctx: Option<&KbsContext<'_>>,
) -> Result<Vec<u8>, PullError> {
    let pubopts = annotations
        .get(ocicrypt::ANNOTATION_PUBOPTS)
        .ok_or_else(|| PullError::Decrypt("missing enc.pubopts annotation".to_string()))?;
    let public = ocicrypt::pubopts_from_annotation(pubopts)
        .map_err(|e| PullError::Decrypt(e.to_string()))?;
    let private = keyprovider::obtain_priv_opts(annotations, key, kbs_ctx)
        .await
        .map_err(|e| PullError::Decrypt(e.to_string()))?;
    ocicrypt::decrypt(ciphertext, &public, &private).map_err(|e| PullError::Decrypt(e.to_string()))
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

/// Extract the registry hostname (authority portion) from a pinned
/// OCI ref. The host is everything up to the first `/` in the
/// `<repo>` part, so for `closed.vendor.com/path/foo@sha256:HEX` the
/// answer is `closed.vendor.com`. Returns None for malformed refs
/// (tag-form, non-sha256, or no path component).
///
/// Used to drive the `Client.registry_auth` hostname-keyed bearer
/// lookup at pull time — same hostname rule for policy and plugin
/// refs, so the API consumer only has to populate one entry per
/// registry.
pub fn registry_hostname(oci_ref: &str) -> Option<&str> {
    let (repo, _) = split_pinned_ref(oci_ref)?;
    repo.split_once('/').map(|(host, _)| host)
}

/// Look up the bearer for an OCI ref against the hostname-keyed
/// `Client.registry_auth` map. Returns an empty slice when the
/// hostname has no entry (anonymous pull) — the existing RegistryClient
/// API treats empty bytes as "no Authorization header".
pub fn bearer_for_ref<'a>(
    registry_auth: &'a std::collections::HashMap<String, Vec<u8>>,
    oci_ref: &str,
) -> &'a [u8] {
    let Some(host) = registry_hostname(oci_ref) else {
        return &[];
    };
    registry_auth
        .get(host)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Extract just the `sha256:<hex>` digest substring from a pinned ref.
fn extract_digest(policy_ref: &str) -> Option<&str> {
    split_pinned_ref(policy_ref).map(|(_, d)| d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_client::Key;

    /// The full decrypt seam for an `inline`-keyed layer: ocicrypt-encrypt
    /// some bytes the way `enclavid oci push --encrypt inline` does, lay the
    /// `enc.pubopts` annotation as the manifest would carry it, then run
    /// `decrypt_layer` (pubopts read + keyprovider Inline dispatch + ocicrypt
    /// decrypt) and assert it reproduces the plaintext.
    #[tokio::test]
    async fn decrypt_layer_inline_round_trips() {
        let plaintext = b"\x00asm\x01\x00\x00\x00 pretend wasm component bytes".to_vec();

        let (ciphertext, public, private) = ocicrypt::encrypt(&plaintext);
        assert_ne!(ciphertext, plaintext, "layer must actually be encrypted");

        let mut annotations = HashMap::new();
        annotations.insert(
            ocicrypt::ANNOTATION_PUBOPTS.to_string(),
            ocicrypt::pubopts_to_annotation(&public).unwrap(),
        );
        let key = Key::Inline(ocicrypt::privopts_to_json(&private).unwrap());

        let out = decrypt_layer(&ciphertext, &annotations, &key, None)
            .await
            .expect("decrypt should succeed with the matching inline key");
        assert_eq!(out, plaintext);
    }

    /// A wrong inline key must fail closed (HMAC over the ciphertext rejects
    /// it), never return garbage plaintext.
    #[tokio::test]
    async fn decrypt_layer_rejects_wrong_inline_key() {
        let plaintext = b"sensitive policy bytes".to_vec();
        let (ciphertext, public, _private) = ocicrypt::encrypt(&plaintext);

        // A private-opts JSON from an UNRELATED encryption (different key).
        let (_ct2, _pub2, other_private) = ocicrypt::encrypt(b"unrelated");

        let mut annotations = HashMap::new();
        annotations.insert(
            ocicrypt::ANNOTATION_PUBOPTS.to_string(),
            ocicrypt::pubopts_to_annotation(&public).unwrap(),
        );
        let key = Key::Inline(ocicrypt::privopts_to_json(&other_private).unwrap());

        let err = decrypt_layer(&ciphertext, &annotations, &key, None)
            .await
            .expect_err("wrong key must fail");
        assert!(matches!(err, PullError::Decrypt(_)));
    }

    /// A supplied key on a plaintext `application/wasm` layer is rejected —
    /// no silent cleartext when encryption was expected.
    #[test]
    fn encrypted_media_suffix_recognised() {
        let encrypted = format!("{WASM_LAYER}{}", ocicrypt::ENCRYPTED_MEDIA_SUFFIX);
        assert_eq!(
            encrypted.strip_suffix(ocicrypt::ENCRYPTED_MEDIA_SUFFIX),
            Some(WASM_LAYER)
        );
    }
}
