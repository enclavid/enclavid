//! Policy artifact resolution: client_policy_key validation at session create
//! time (cheap, manifest-only round-trip) and full pull-and-decrypt
//! lazily at /connect.
//!
//! Verifies digests at every step (host is NOT trusted on response
//! content — see Network Isolation), extracts the encrypted layer,
//! and age-decrypts it with client_policy_key.

use std::collections::HashMap;
use std::io::Read;

use age::x25519::Identity;
use base64ct::Encoding;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use enclavid_host_bridge::{AuthN, AuthZ, RegistryClient, Replay, reason};

/// OCI layer media-type for the encrypted policy wasm. Single layer
/// in the artifact — any embedded text-ref declarations live
/// **inside** this wasm as component-level custom sections, not as
/// separate OCI layers.
const POLICY_WASM_LAYER: &str = "application/vnd.enclavid.policy.wasm.v1.encrypted";
/// Manifest annotation key holding a base64-encoded prefix of the
/// encrypted wasm layer's age stream: header (version line +
/// recipient stanzas + MAC) + 16-byte nonce. POST /sessions feeds
/// this prefix to `age::Decryptor::new(...)?.decrypt(client_policy_key)`
/// — successful recipient-stanza unwrap proves the supplied key
/// matches the artifact's recipient, *without pulling the full layer*.
/// Saves the cost of a multi-megabyte pull on bad-key calls.
///
/// Must match the constant on the CLI side
/// (`crates/cli/src/commands/policy/push.rs::AGE_HEADER_ANNOTATION`).
const AGE_HEADER_ANNOTATION: &str = "com.enclavid.policy.age-header";

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
    #[error("manifest declares no layer with the policy media type")]
    NoPolicyLayer,
    #[error("manifest layer/payload count mismatch: {layers} vs {payloads}")]
    LayerCountMismatch { layers: usize, payloads: usize },
    #[error("decryption failed (wrong client_policy_key?)")]
    Decrypt,
    #[error("manifest is missing the age-header annotation")]
    MissingAgeHeader,
    #[error("age-header annotation base64 malformed: {0}")]
    AgeHeaderBase64(String),
    #[error("age-header annotation is not a valid age stream prefix: {0}")]
    AgeHeaderParse(String),
}

/// Stringly-typed 404 detection for the host-bridge registry error.
/// `RegistryClient::pull_*` currently returns `tonic::Status` whose
/// message string we don't structure. Standard OCI Distribution spec
/// errors land here as `code: 404` ± `MANIFEST_UNKNOWN`; we match on
/// the substring to surface `NotFound` rather than treat as generic
/// transport. Fragile by nature — should be replaced when host-bridge
/// grows a typed `RegistryError::NotFound` variant.
fn classify_transport_error<E: std::fmt::Debug>(e: E) -> PullError {
    let msg = format!("{e:?}");
    if msg.contains("code: 404") || msg.contains("MANIFEST_UNKNOWN") {
        PullError::NotFound
    } else {
        PullError::Transport(msg)
    }
}

/// Result of a successful pull-and-decrypt: the policy's decrypted
/// wasm component bytes, ready for compile. Any embedded text-ref
/// declarations
/// (`enclavid:embedded.disclosure-fields.v1`,
/// `enclavid:embedded.i18n.v1`) live inside the wasm as component-
/// level custom sections; the caller extracts them via
/// `enclavid_engine::load_embedded`. No sidecar layer.
pub struct PolicyArtifact {
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

/// Cheap client_policy_key validation against the manifest's
/// age-header annotation. Pulls only the manifest (no layer payloads),
/// verifies digest, then runs `age::Decryptor::new(prefix)?
/// .decrypt(client_policy_key)` against the embedded stream prefix.
/// Successful unwrap of the recipient stanza proves the supplied key
/// matches what `enclavid encrypt` sealed against.
///
/// Used at `POST /sessions` so that wrong-client_policy_key errors surface
/// synchronously to the client API call instead of breaking later
/// during applicant flow. Cost: 1 RTT for the manifest, no layer pull.
pub async fn validate_client_policy_key(
    registry: &RegistryClient,
    policy_ref: &str,
    registry_auth: &[u8],
    client_policy_key: &Identity,
) -> Result<(), PullError> {
    let policy_digest = extract_digest(policy_ref)
        .ok_or_else(|| PullError::InvalidRef(policy_ref.to_string()))?;
    let response = registry
        .pull_manifest(policy_ref, registry_auth)
        .await
        .map_err(classify_transport_error)?
        .trust::<AuthN, _, _, _, _>(|r| {
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
            Ok(r)
        })?
        .trust_unchecked::<AuthZ, _>(reason!(
            "OCI registry server enforces pull authorisation with the host-supplied \
             bearer; TEE doesn't gate access at this layer"
        ))
        .trust_unchecked::<Replay, _>(reason!(
            "content-addressed by digest in the request — an 'old' response for the \
             same digest is bit-identical to the current one"
        ))
        .into_inner();

    let manifest: OciManifest = serde_json::from_slice(&response.manifest)
        .map_err(|e| PullError::ManifestParse(e.to_string()))?;

    let prefix_b64 = manifest
        .annotations
        .get(AGE_HEADER_ANNOTATION)
        .ok_or(PullError::MissingAgeHeader)?;
    let prefix = base64ct::Base64::decode_vec(prefix_b64)
        .map_err(|e| PullError::AgeHeaderBase64(format!("{e:?}")))?;

    // `Decryptor::new` parses version line + recipient stanzas + MAC
    // + 16-byte nonce; on success the stream's header is structurally
    // valid and HMAC-consistent. `.decrypt(...)` then performs the
    // ECDH unwrap of the file_key against the supplied identity —
    // that's the actual key-match check. We drop the returned reader:
    // no payload bytes follow in this prefix and we never intended
    // to decrypt content here anyway.
    let decryptor = age::Decryptor::new(&prefix[..])
        .map_err(|e| PullError::AgeHeaderParse(format!("{e:?}")))?;
    if decryptor.is_scrypt() {
        // Passphrase-encrypted policy would imply "anyone with the
        // passphrase can mint sessions" — not our threat model. CLI
        // push rejects these up-front, so reaching here means the
        // artifact was crafted outside our toolchain.
        return Err(PullError::AgeHeaderParse(
            "passphrase-recipient streams not supported".to_string(),
        ));
    }
    let _ = decryptor
        .decrypt(std::iter::once(client_policy_key as &dyn age::Identity))
        .map_err(|_| PullError::Decrypt)?;
    Ok(())
}

pub async fn pull_and_decrypt(
    registry: &RegistryClient,
    policy_ref: &str,
    registry_auth: &[u8],
    client_policy_key: &Identity,
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
        .map_err(classify_transport_error)?
        .trust::<AuthN, _, _, _, _>(|r| {
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

    // After trust gate: response is plain `PullResponse`. Re-parse the
    // manifest (cheap — JSON is small) to find the wasm layer.
    // Single-layer artifact: the policy manifest is no longer a
    // sibling OCI layer, it's embedded as a wasm custom section
    // inside the encrypted wasm (extracted after decrypt below).
    let manifest: OciManifest = serde_json::from_slice(&response.manifest)
        .map_err(|e| PullError::ManifestParse(e.to_string()))?;

    let mut wasm_bytes: Option<Vec<u8>> = None;
    for (idx, descriptor) in manifest.layers.iter().enumerate() {
        let payload = &response.layers[idx];
        match descriptor.media_type.as_str() {
            POLICY_WASM_LAYER => {
                // client_policy_key-encrypted; decrypt for compilation.
                let plaintext =
                    age_decrypt(payload, client_policy_key).map_err(|_| PullError::Decrypt)?;
                wasm_bytes = Some(plaintext);
            }
            _ => {
                // Unknown media-type — ignore for forward-compat.
                // Future versions may add new layer types; older
                // hosts should skip them rather than refuse to load.
            }
        }
    }

    let wasm_bytes = wasm_bytes.ok_or(PullError::NoPolicyLayer)?;
    Ok(PolicyArtifact { wasm_bytes })
}

/// OCI layer media type for plain (unencrypted) wasm component layers.
/// Used by tier-1 OSS plugins. Encrypted plugins (tier-2/tier-3) also
/// publish under this media type — `wkg`'s pull whitelist accepts only
/// `application/wasm` (see `[[project-wkg-wac-poc-findings]]`); encryption
/// is signalled via OCI manifest annotations or a config-blob extension
/// rather than the layer media type.
const PLAIN_WASM_LAYER: &str = "application/wasm";

/// One pulled plugin component. Same shape as `PolicyArtifact` but no
/// decryption step — plugin bytes are plain (or, for tier-3, encrypted
/// with the vendor's own scheme that the TEE handles via KBS attestation
/// rather than the client_policy_key path used for policies).
///
/// Plugins are pure compute under our trust model — they may not import
/// any host function — so they ship no embedded declarations sections.
pub struct PluginArtifact {
    /// Plain wasm component bytes — ready to compile with wasmtime.
    pub wasm_bytes: Vec<u8>,
}

/// Pull and integrity-check a plugin OCI artifact.
///
/// Same trust path as `pull_and_decrypt` (host is untrusted on response
/// content; every hash recomputed in the TEE against the pinned digest)
/// minus the age decryption — plugin bytes are not client_policy_key-
/// encrypted. The pinned ref `plugin_ref` MUST be of the form
/// `<repo>@sha256:<hex>` (digest-pinned); tag-only refs are rejected
/// because they break replay reproducibility.
pub async fn pull_plugin(
    registry: &RegistryClient,
    plugin_ref: &str,
    registry_auth: &[u8],
) -> Result<PluginArtifact, PullError> {
    let plugin_digest = extract_digest(plugin_ref)
        .ok_or_else(|| PullError::InvalidRef(plugin_ref.to_string()))?;
    let response = registry
        .pull(plugin_ref, registry_auth)
        .await
        .map_err(classify_transport_error)?
        .trust::<AuthN, _, _, _, _>(|r| {
            // Identical digest-validation flow as `pull_and_decrypt`:
            // (1) manifest bytes hash to the pinned digest, (2) host's
            // self-reported digest agrees with our recompute,
            // (3) each layer payload hashes to its descriptor digest.
            let manifest_actual = sha256_hex(&r.manifest);
            if !digest_matches(plugin_digest, &manifest_actual) {
                return Err(PullError::ManifestDigest {
                    expected: plugin_digest.to_string(),
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

    // Find the plain wasm layer. We accept the first matching layer
    // (single-layer is the norm; multi-layer plugin artifacts are
    // explicitly unsupported by wkg's pull validation anyway, see
    // `[[project-wkg-wac-poc-findings]]`).
    let mut wasm_bytes: Option<Vec<u8>> = None;
    for (idx, descriptor) in manifest.layers.iter().enumerate() {
        if descriptor.media_type == PLAIN_WASM_LAYER {
            wasm_bytes = Some(response.layers[idx].clone());
            break;
        }
    }
    let wasm_bytes = wasm_bytes.ok_or(PullError::NoPolicyLayer)?;
    Ok(PluginArtifact { wasm_bytes })
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
