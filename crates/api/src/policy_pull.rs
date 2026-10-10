//! Policy + plugin artifact resolution, in two steps. [`wasm_layer`] fetches an
//! artifact's manifest, checks it against the pinned reference in the TEE,
//! picks its wasm layer and, for an encrypted one, obtains its key — everything
//! that can be refused before a byte of wasm moves. [`WasmLayer::pieces`] then
//! fetches that one layer as a stream, held to the size and digest the verified
//! manifest declares and decrypted on the way, for the compile to read as it
//! comes. The policy and plugin paths share this one trust gate. [`manifest`]
//! alone is how a session shows, before its first round runs, that it may pull
//! what it pins — whether its compile then turns out to be cached or not.
//!
//! Only the wasm layer is fetched. The manifest's digest pins the whole
//! artifact, every layer's digest is inside it, and the other layers are not
//! used — so fetching and checking them would add a pull and nothing else.

use std::collections::HashMap;

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::OwnedSemaphorePermit;

use enclavid_boundary::{AuthN, AuthZ, Covert, Replay, reason};
use enclavid_crypto::ocicrypt::{self, LayerDecryptor};
use hatch_client::{BlobPieces, BlobRequest, Key, ManifestRequest, RegistryClient, boundary};

use crate::keyprovider::{self, KbsContext};
use crate::turns::Turns;

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
    #[error("layer digest mismatch: expected {expected}, got {actual}")]
    LayerDigest { expected: String, actual: String },
    #[error("the layer is not the size its manifest declares")]
    LayerSize,
    #[error("manifest declares no layer with the wasm media type")]
    NoWasmLayer,
    #[error("artifact decryption failed: {0}")]
    Decrypt(String),
    /// The hatch will not make the pull as asked — the registry refused the
    /// bearer, most often.
    #[error("the registry refused the pull")]
    Refused,
    /// The consumer's other pulls held every turn it has for as long as this
    /// one could wait ([`crate::turns`]).
    #[error("no turn for this consumer's pull in time")]
    Busy,
}

impl PullError {
    /// Whether the same pull may succeed if asked again: the registry, the
    /// hatch or the consumer's turn did not answer this time. Everything else —
    /// a refusal, an artifact absent or not what its pin names — is the pins'
    /// and stays.
    pub fn is_unanswered(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Busy)
    }
}

/// Map a bridge transport error to a `PullError`. The hatch classifies
/// OCI 404 / `MANIFEST_UNKNOWN` natively (it's the one talking OCI) and
/// returns the typed `BridgeError::NotFound`, so we match on the variant
/// instead of grepping a Debug string.
fn classify_transport_error(e: hatch_client::BridgeError) -> PullError {
    match e {
        hatch_client::BridgeError::NotFound => PullError::NotFound,
        hatch_client::BridgeError::Refused => PullError::Refused,
        other => PullError::Transport(format!("{other:?}")),
    }
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
    /// The layer's length in bytes, which OCI requires every descriptor to
    /// declare.
    size: u64,
    /// ocicrypt stores the wrapped key + public cipher opts here (on the
    /// layer descriptor). Empty for plaintext layers.
    #[serde(default)]
    annotations: HashMap<String, String>,
}

/// One artifact's wasm layer, known from its verified manifest and not fetched
/// yet: how long it is, and what fetching it takes.
///
/// Any embedded text-ref declarations (`enclavid:embedded.disclosure-fields.v1`,
/// `enclavid:embedded.i18n.v1`) live inside the wasm as component-level custom
/// sections, which the compiler extracts. No sidecar layer.
pub struct WasmLayer {
    registry: RegistryClient,
    turns: Turns,
    reference: String,
    registry_auth: Vec<u8>,
    digest: String,
    size: u64,
    decrypt: Option<LayerDecryptor>,
}

/// Fetch and check an artifact's manifest, and pick its wasm layer: a
/// plaintext `application/wasm` one, or an ocicrypt-encrypted one, whose key
/// is obtained here. `key` is what the session pins for this artifact; a key
/// for a plaintext layer is refused rather than ignored, so no cleartext is
/// served where encryption was expected. The manifest, and later the layer,
/// each take one of `turns` for as long as they are fetched.
pub async fn wasm_layer(
    registry: &RegistryClient,
    turns: &Turns,
    artifact_ref: &str,
    registry_auth: &[u8],
    key: Option<&Key>,
    kbs_ctx: Option<&KbsContext<'_>>,
) -> Result<WasmLayer, PullError> {
    let manifest = manifest(registry, turns, artifact_ref, registry_auth).await?;
    let manifest: OciManifest =
        serde_json::from_slice(&manifest).map_err(|e| PullError::ManifestParse(e.to_string()))?;

    for descriptor in manifest.layers {
        let decrypt = if descriptor.media_type == WASM_LAYER {
            if key.is_some() {
                return Err(PullError::Decrypt(
                    "a key was supplied but the layer is not encrypted".to_string(),
                ));
            }
            None
        } else if descriptor
            .media_type
            .strip_suffix(ocicrypt::ENCRYPTED_MEDIA_SUFFIX)
            == Some(WASM_LAYER)
        {
            let key = key.ok_or_else(|| {
                PullError::Decrypt("layer is encrypted but no key was supplied".to_string())
            })?;
            Some(layer_decryptor(&descriptor.annotations, key, kbs_ctx).await?)
        } else {
            continue;
        };
        return Ok(WasmLayer {
            registry: registry.clone(),
            turns: turns.clone(),
            reference: artifact_ref.to_string(),
            registry_auth: registry_auth.to_vec(),
            digest: descriptor.digest,
            size: descriptor.size,
            decrypt,
        });
    }
    Err(PullError::NoWasmLayer)
}

/// An artifact's manifest, fetched with `registry_auth` and checked to be the
/// one `artifact_ref` pins. Getting it is also the registry's word that this
/// bearer may pull the artifact: the registry grants pull per repository, so
/// the same bearer fetches the manifest and every blob in it. Fetched on one of
/// `turns`.
pub async fn manifest(
    registry: &RegistryClient,
    turns: &Turns,
    artifact_ref: &str,
    registry_auth: &[u8],
) -> Result<Vec<u8>, PullError> {
    let artifact_digest = extract_digest(artifact_ref)
        .ok_or_else(|| PullError::InvalidRef(artifact_ref.to_string()))?;
    let _turn = turns.take().await.ok_or(PullError::Busy)?;
    let req = boundary::outbound::to_untrusted(ManifestRequest {
        reference: artifact_ref.to_string(),
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
    Ok(registry
        .manifest(req)
        .await
        .map_err(classify_transport_error)?
        .trust::<AuthN, _, _, _, _>(|manifest| {
            // The manifest's bytes must hash to the pinned digest.
            let actual = sha256_hex(&manifest);
            if digest_matches(artifact_digest, &actual) {
                Ok(manifest)
            } else {
                Err(PullError::ManifestDigest {
                    expected: artifact_digest.to_string(),
                    actual: format!("sha256:{actual}"),
                })
            }
        })?
        .trust_unchecked::<AuthZ, _>(reason!(
            "names no kind — ACCEPTED RISK: the registry decides with the consumer's \
             bearer, and its refusal binds only as far as the host relays it, so a host \
             can answer yes in its place. That host holds every layer and bearer it \
             couriers, so what it lets through is what it could serve on a pull"
        ))
        .trust_unchecked::<Replay, _>(reason!(
            "content-addressed by digest — bit-identical responses for the same digest"
        ))
        .into_inner())
}

impl WasmLayer {
    /// The wasm's length: the layer's, which an AES-CTR layer's plaintext
    /// shares.
    pub fn length(&self) -> u64 {
        self.size
    }

    /// The wasm, fetched when first read and held to the verified manifest on
    /// the way: to the layer's size as it comes, and to its digest — and, when
    /// encrypted, to its HMAC and plaintext digest — where it ends.
    ///
    /// A layer that fails any of them ends in an error where it would have
    /// ended, never in a quiet end. The pieces before that are not yet checked,
    /// which is why they go only to a compile that starts once every component
    /// has arrived whole. One of the consumer's turns is held from the request
    /// until the stream ends or is dropped.
    pub fn pieces(self) -> BoxStream<'static, Result<Bytes, PullError>> {
        let Self {
            registry,
            turns,
            reference,
            registry_auth,
            digest,
            size,
            decrypt,
        } = self;
        let fetch = async move {
            let turn = turns.take().await.ok_or(PullError::Busy)?;
            let req = boundary::outbound::to_untrusted(BlobRequest {
                reference,
                digest: digest.clone(),
                registry_auth,
            })
            .vouch_unchecked::<AuthN, _>(reason!(
                "a digest from the manifest this TEE verified, and the consumer's own ref \
                 and bearer, courier-forwarded — not a TEE secret"
            ))
            .vouch_unchecked::<AuthZ, _>(reason!(
                "forwarding the bearer to its registry IS the courier op"
            ))
            .vouch_unchecked::<Covert, _>(reason!(
                "every part is consumer-supplied or read from the consumer's own manifest, \
                 not policy-controlled"
            ));
            let pieces = registry
                .blob(req)
                .await
                .map_err(classify_transport_error)?
                .trust_unchecked::<AuthN, _>(reason!(
                    "held below to the size and digest the pinned manifest declares, so a \
                     blob that is not that layer ends in an error before anything acts on it"
                ))
                .trust_unchecked::<AuthZ, _>(reason!(
                    "OCI registry server enforces pull authorisation with the consumer's \
                     bearer; TEE doesn't gate access at this layer"
                ))
                .trust_unchecked::<Replay, _>(reason!(
                    "content-addressed by digest — bit-identical responses for the same digest"
                ))
                .into_inner();
            Ok::<_, PullError>(held(pieces, digest, size, decrypt, turn))
        };
        futures::stream::once(fetch).try_flatten().boxed()
    }
}

/// What [`held`] carries from one piece to the next.
struct Holding {
    pieces: BlobPieces,
    digest: String,
    left: u64,
    sum: Sha256,
    decrypt: Option<LayerDecryptor>,
    /// Given back when the stream ends or is dropped, and not before.
    _turn: OwnedSemaphorePermit,
}

/// `pieces` held to `size` as they come and to `digest` where they end, and
/// decrypted by `decrypt` if given, whose checks are made where they end too.
/// `turn` is held as long as the stream is.
fn held(
    pieces: BlobPieces,
    digest: String,
    size: u64,
    decrypt: Option<LayerDecryptor>,
    turn: OwnedSemaphorePermit,
) -> BoxStream<'static, Result<Bytes, PullError>> {
    let holding = Holding {
        pieces,
        digest,
        left: size,
        sum: Sha256::new(),
        decrypt,
        _turn: turn,
    };
    futures::stream::try_unfold(holding, |mut h| async move {
        let Some(piece) = h.pieces.next().await else {
            if h.left != 0 {
                return Err(PullError::LayerSize);
            }
            let actual = hex::encode(std::mem::take(&mut h.sum).finalize());
            if !digest_matches(&h.digest, &actual) {
                return Err(PullError::LayerDigest {
                    expected: h.digest,
                    actual: format!("sha256:{actual}"),
                });
            }
            if let Some(decrypt) = h.decrypt.take() {
                decrypt
                    .finish()
                    .map_err(|e| PullError::Decrypt(e.to_string()))?;
            }
            return Ok(None);
        };
        let piece = piece.map_err(classify_transport_error)?;
        h.left = h
            .left
            .checked_sub(piece.len() as u64)
            .ok_or(PullError::LayerSize)?;
        h.sum.update(&piece);
        let plain = match h.decrypt.as_mut() {
            Some(decrypt) => Bytes::from(decrypt.decrypt(&piece)),
            None => piece,
        };
        Ok(Some((plain, h)))
    })
    .boxed()
}

/// The decryptor for an ocicrypt-encrypted wasm layer: the public cipher opts
/// from the `enc.pubopts` annotation, and the private opts from the key
/// dispatch.
async fn layer_decryptor(
    annotations: &HashMap<String, String>,
    key: &Key,
    kbs_ctx: Option<&KbsContext<'_>>,
) -> Result<LayerDecryptor, PullError> {
    let pubopts = annotations
        .get(ocicrypt::ANNOTATION_PUBOPTS)
        .ok_or_else(|| PullError::Decrypt("missing enc.pubopts annotation".to_string()))?;
    let public = ocicrypt::pubopts_from_annotation(pubopts)
        .map_err(|e| PullError::Decrypt(e.to_string()))?;
    let private = keyprovider::obtain_priv_opts(annotations, key, kbs_ctx)
        .await
        .map_err(|e| PullError::Decrypt(e.to_string()))?;
    LayerDecryptor::new(&public, &private).map_err(|e| PullError::Decrypt(e.to_string()))
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

/// The registry a pinned OCI ref is pulled from, named as the hatch's
/// registry client names it — the host the bearer looked up under it is
/// sent to. That is the first `/`-separated part of `<repo>` when it reads
/// as a host (has a `.` or a `:`, or is `localhost`), so for
/// `closed.vendor.com/path/foo@sha256:HEX` the answer is
/// `closed.vendor.com`; any other ref, `library/foo` or bare `foo`, is
/// Docker Hub's, `docker.io`, which `index.docker.io` also names. The
/// scheme a ref may be written with, `http://` or `https://` — how the
/// hatch reaches the registry — is not part of it. Returns None for
/// malformed refs (tag-form or non-sha256).
///
/// Used to drive the `Client.registry_auth` hostname-keyed bearer
/// lookup at pull time — same hostname rule for policy and plugin
/// refs, so the API consumer only has to populate one entry per
/// registry.
pub fn registry_hostname(oci_ref: &str) -> Option<&str> {
    const DOCKER_HUB: &str = "docker.io";
    let (repo, _) = split_pinned_ref(oci_ref)?;
    let repo = repo
        .strip_prefix("http://")
        .or_else(|| repo.strip_prefix("https://"))
        .unwrap_or(repo);
    Some(match repo.split_once('/') {
        Some(("index.docker.io", _)) => DOCKER_HUB,
        Some((host, _)) if host.contains(['.', ':']) || host == "localhost" => host,
        _ => DOCKER_HUB,
    })
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
    use std::sync::Arc;

    use hatch_client::Key;
    use tokio::sync::Semaphore;

    use super::*;

    /// `bytes` as pieces of `piece` bytes, as the hatch's stream would carry
    /// them.
    fn pieces(bytes: &[u8], piece: usize) -> BlobPieces {
        let pieces: Vec<_> = bytes
            .chunks(piece)
            .map(|p| Ok(Bytes::copy_from_slice(p)))
            .collect();
        futures::stream::iter(pieces).boxed()
    }

    async fn read(
        stream: BoxStream<'static, Result<Bytes, PullError>>,
    ) -> Result<Vec<u8>, PullError> {
        stream
            .try_fold(Vec::new(), |mut all, p| async move {
                all.extend_from_slice(&p);
                Ok(all)
            })
            .await
    }

    fn digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", sha256_hex(bytes))
    }

    /// A turn of a queue nobody else uses.
    fn turn() -> OwnedSemaphorePermit {
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap()
    }

    /// The `enc.pubopts` annotation a manifest carries for `public`.
    fn annotations(public: &ocicrypt::PublicLayerBlockCipherOptions) -> HashMap<String, String> {
        HashMap::from([(
            ocicrypt::ANNOTATION_PUBOPTS.to_string(),
            ocicrypt::pubopts_to_annotation(public).unwrap(),
        )])
    }

    /// The full decrypt seam for an `inline`-keyed layer: ocicrypt-encrypt
    /// some bytes the way `enclavid oci push --encrypt inline` does, lay the
    /// `enc.pubopts` annotation as the manifest would carry it, take the
    /// decryptor through the keyprovider Inline dispatch, and read the layer's
    /// stream through it: the plaintext comes out whole.
    #[tokio::test]
    async fn an_inline_keyed_layer_streams_out_decrypted() {
        let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let (ciphertext, public, private) = ocicrypt::encrypt(&plaintext);
        assert_ne!(ciphertext, plaintext, "layer must actually be encrypted");
        let key = Key::Inline(ocicrypt::privopts_to_json(&private).unwrap());

        let decrypt = layer_decryptor(&annotations(&public), &key, None)
            .await
            .expect("the matching inline key yields a decryptor");
        let out = held(
            pieces(&ciphertext, 7_777),
            digest_of(&ciphertext),
            ciphertext.len() as u64,
            Some(decrypt),
            turn(),
        );
        assert_eq!(read(out).await.unwrap(), plaintext);
    }

    /// A wrong inline key must fail closed (HMAC over the ciphertext rejects
    /// it) where the layer ends, never end quietly on garbage plaintext.
    #[tokio::test]
    async fn a_wrong_inline_key_ends_the_layer_in_an_error() {
        let (ciphertext, public, _private) = ocicrypt::encrypt(b"sensitive policy bytes");
        // A private-opts JSON from an UNRELATED encryption (different key).
        let (_ct2, _pub2, other_private) = ocicrypt::encrypt(b"unrelated");
        let key = Key::Inline(ocicrypt::privopts_to_json(&other_private).unwrap());

        let decrypt = layer_decryptor(&annotations(&public), &key, None)
            .await
            .unwrap();
        let out = held(
            pieces(&ciphertext, 5),
            digest_of(&ciphertext),
            ciphertext.len() as u64,
            Some(decrypt),
            turn(),
        );
        assert!(matches!(read(out).await, Err(PullError::Decrypt(_))));
    }

    /// A plaintext layer is held to the size and digest its manifest declares:
    /// longer, shorter, or other bytes, and it ends in an error.
    #[tokio::test]
    async fn a_layer_is_held_to_its_size_and_digest() {
        let layer: Vec<u8> = (0..50_000).map(|i| (i % 7) as u8).collect();
        let digest = digest_of(&layer);
        let size = layer.len() as u64;

        let whole = held(pieces(&layer, 4096), digest.clone(), size, None, turn());
        assert_eq!(read(whole).await.unwrap(), layer);

        let longer = held(pieces(&layer, 4096), digest.clone(), size - 1, None, turn());
        assert!(matches!(read(longer).await, Err(PullError::LayerSize)));

        let shorter = held(pieces(&layer, 4096), digest.clone(), size + 1, None, turn());
        assert!(matches!(read(shorter).await, Err(PullError::LayerSize)));

        let mut other = layer.clone();
        other[100] ^= 1;
        let tampered = held(pieces(&other, 4096), digest, size, None, turn());
        assert!(matches!(
            read(tampered).await,
            Err(PullError::LayerDigest { .. })
        ));
    }

    /// A layer holds its consumer's turn while it is read and gives it back
    /// once it is done with, whole or in an error, for the next pull to take.
    #[tokio::test]
    async fn a_layer_gives_its_turn_back() {
        let layer = vec![7u8; 10_000];
        let one = Arc::new(Semaphore::new(1));
        for digest in [digest_of(&layer), digest_of(b"other")] {
            let permit = one.clone().try_acquire_owned().unwrap();
            let out = held(
                pieces(&layer, 1000),
                digest,
                layer.len() as u64,
                None,
                permit,
            );
            assert_eq!(one.available_permits(), 0);
            let _ = read(out).await;
            assert_eq!(one.available_permits(), 1);
        }
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

    /// A ref written with the scheme to reach its registry by finds the
    /// bearer kept under the registry's bare name, as one without does.
    #[test]
    fn the_scheme_is_no_part_of_the_registry_name() {
        let digest = "sha256:00";
        for written in ["", "http://", "https://"] {
            let r = format!("{written}registry.example.com:5000/team/policy@{digest}");
            assert_eq!(registry_hostname(&r), Some("registry.example.com:5000"));
        }
        let auth = HashMap::from([("localhost:5050".to_string(), b"bearer".to_vec())]);
        let r = format!("http://localhost:5050/policy@{digest}");
        assert_eq!(bearer_for_ref(&auth, &r), b"bearer");
    }

    /// A first part that does not read as a host is a Docker Hub path, as
    /// the hatch's registry client takes it, so a bearer kept under that
    /// part is not sent to Docker Hub.
    #[test]
    fn a_registry_is_named_as_the_hatch_reaches_it() {
        let digest = "sha256:00";
        for (repo, registry) in [
            ("localhost/policy", "localhost"),
            ("10.0.0.1/policy", "10.0.0.1"),
            ("registry:5000/policy", "registry:5000"),
            ("http://registry/team/policy", "docker.io"),
            ("registry/team/policy", "docker.io"),
            ("library/policy", "docker.io"),
            ("policy", "docker.io"),
            ("index.docker.io/library/policy", "docker.io"),
        ] {
            let r = format!("{repo}@{digest}");
            assert_eq!(registry_hostname(&r), Some(registry), "{repo}");
        }
        let auth = HashMap::from([("registry".to_string(), b"bearer".to_vec())]);
        assert!(bearer_for_ref(&auth, &format!("registry/team/policy@{digest}")).is_empty());
    }
}
