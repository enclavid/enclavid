//! Faithful ocicrypt layer encryption — the `AES_256_CTR_HMAC_SHA256`
//! scheme, byte-exact to `containers/ocicrypt`'s `LayerBlockCipherOptions`
//! format so artifacts interop with standard ocicrypt tooling (skopeo,
//! coco-keyprovider). We implement it in-house because the upstream
//! `ocicrypt-rs` crate is pinned to an old RustCrypto generation that
//! conflicts with this workspace's `cipher`/`aes` versions.
//!
//! Layout (matches ocicrypt):
//! - The layer blob is AES-256-CTR over the plaintext; integrity is an
//!   HMAC-SHA256 over the **ciphertext**, keyed by the same 32-byte
//!   symmetric key. The 16-byte CTR IV (`nonce`) and the key are SECRET
//!   (private opts); the HMAC and cipher name are PUBLIC.
//! - [`PublicLayerBlockCipherOptions`]  → base64(JSON) in the layer
//!   annotation [`ANNOTATION_PUBOPTS`].
//! - [`PrivateLayerBlockCipherOptions`] → JSON, wrapped per-recipient
//!   under `org.opencontainers.image.enc.keys.<scheme>` (or delivered to
//!   the TEE by its key_source). Carries symkey + nonce + plaintext digest.
//!
//! Both [`encrypt`] (CLI push side) and [`decrypt`] (TEE pull side) live
//! here so they are exercised as a pair against the exact format.

use std::collections::HashMap;
use std::fmt;

use aes::Aes256;
use base64ct::{Base64, Encoding};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::CryptoError;

type Aes256Ctr = Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// ocicrypt cipher identifier for AES-256-CTR with HMAC-SHA256.
pub const CIPHER_AES256CTR_HMAC_SHA256: &str = "AES_256_CTR_HMAC_SHA256";

/// Layer annotation: base64(JSON) of [`PublicLayerBlockCipherOptions`].
pub const ANNOTATION_PUBOPTS: &str = "org.opencontainers.image.enc.pubopts";
/// Layer-annotation prefix for the wrapped private opts; the keywrap
/// scheme name is appended (e.g. `...keys.provider.enclavid-kbs`).
pub const ANNOTATION_KEYS_PREFIX: &str = "org.opencontainers.image.enc.keys.";
/// mediaType suffix ocicrypt appends to the original layer type.
pub const ENCRYPTED_MEDIA_SUFFIX: &str = "+encrypted";

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
const NONCE_KEY: &str = "nonce";

/// Public block-cipher options — non-secret, carried plaintext in the
/// layer annotation. Field names match ocicrypt's JSON exactly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicLayerBlockCipherOptions {
    #[serde(rename = "cipher")]
    pub cipher_type: String,
    #[serde(rename = "cipheroptions", default, with = "b64map")]
    pub cipher_options: HashMap<String, Vec<u8>>,
    #[serde(default, with = "b64vec")]
    pub hmac: Vec<u8>,
}

/// Private block-cipher options — secret. Wrapped per-recipient (or
/// delivered to the TEE by its key_source, e.g. a live KBS release). Holds
/// the symmetric key, the CTR nonce, and the plaintext digest.
///
/// The `symmetric_key` is real per-artifact key material, so this type zeroizes
/// it (and the nonce) on drop and redacts them from `Debug` — the same
/// key-hygiene the `tee_seal_key`-derived keys get. It stays a plain `Vec<u8>`
/// (not a `SecretBox`) because the ocicrypt format requires serializing it
/// byte-exact; the manual `Drop` + `Debug` add the protection without breaking
/// the wire format.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateLayerBlockCipherOptions {
    #[serde(rename = "symkey", with = "b64vec")]
    pub symmetric_key: Vec<u8>,
    #[serde(rename = "cipheroptions", default, with = "b64map")]
    pub cipher_options: HashMap<String, Vec<u8>>,
    #[serde(default)]
    pub digest: String,
}

impl fmt::Debug for PrivateLayerBlockCipherOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the key or nonce — only the non-secret digest + option keys.
        f.debug_struct("PrivateLayerBlockCipherOptions")
            .field("symmetric_key", &"[REDACTED]")
            .field("cipher_options", &"[REDACTED]")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Drop for PrivateLayerBlockCipherOptions {
    fn drop(&mut self) {
        // Zeroize the key + the CTR nonce (a `cipher_options` value) before the
        // heap is freed, so a live KBS-released layer key doesn't linger in RAM.
        self.symmetric_key.zeroize();
        for v in self.cipher_options.values_mut() {
            v.zeroize();
        }
    }
}

/// Encrypt `plaintext` under a fresh random key + nonce. Returns the
/// ciphertext layer plus the split public/private options. The CLI writes
/// the public opts into the layer annotation and delivers/wraps the
/// private opts per the chosen key_source.
pub fn encrypt(
    plaintext: &[u8],
) -> (
    Vec<u8>,
    PublicLayerBlockCipherOptions,
    PrivateLayerBlockCipherOptions,
) {
    use rand_core::{OsRng, RngCore};

    let mut symmetric_key = vec![0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut symmetric_key);
    let mut nonce = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    let digest = format!("sha256:{}", hex::encode(Sha256::digest(plaintext)));

    let mut buf = plaintext.to_vec();
    let mut cipher = Aes256Ctr::new(
        symmetric_key.as_slice().into(),
        nonce.as_slice().into(),
    );
    cipher.apply_keystream(&mut buf);

    let mut mac = HmacSha256::new_from_slice(&symmetric_key).expect("hmac accepts any key length");
    mac.update(&buf);
    let hmac = mac.finalize().into_bytes().to_vec();

    let mut private_opts = HashMap::new();
    private_opts.insert(NONCE_KEY.to_string(), nonce);

    let public = PublicLayerBlockCipherOptions {
        cipher_type: CIPHER_AES256CTR_HMAC_SHA256.to_string(),
        cipher_options: HashMap::new(),
        hmac,
    };
    let private = PrivateLayerBlockCipherOptions {
        symmetric_key,
        cipher_options: private_opts,
        digest,
    };
    (buf, public, private)
}

/// Decrypt an ocicrypt `AES_256_CTR_HMAC_SHA256` layer. Verifies the HMAC
/// over the ciphertext (constant-time) before decrypting, then checks the
/// plaintext digest if present.
pub fn decrypt(
    ciphertext: &[u8],
    public: &PublicLayerBlockCipherOptions,
    private: &PrivateLayerBlockCipherOptions,
) -> Result<Vec<u8>, CryptoError> {
    if public.cipher_type != CIPHER_AES256CTR_HMAC_SHA256 {
        return Err(CryptoError::new(format!(
            "unsupported ocicrypt cipher: {}",
            public.cipher_type
        )));
    }
    if private.symmetric_key.len() != KEY_SIZE {
        return Err(CryptoError::new("ocicrypt symkey must be 32 bytes"));
    }
    // ocicrypt `get_opt`: public has priority, falling back to private.
    // The nonce is written to the private opts at encrypt time.
    let nonce = public
        .cipher_options
        .get(NONCE_KEY)
        .or_else(|| private.cipher_options.get(NONCE_KEY))
        .ok_or_else(|| CryptoError::new("ocicrypt nonce missing"))?;
    if nonce.len() != NONCE_SIZE {
        return Err(CryptoError::new("ocicrypt nonce must be 16 bytes"));
    }

    // Verify HMAC over the ciphertext before touching plaintext.
    let mut mac =
        HmacSha256::new_from_slice(&private.symmetric_key).expect("hmac accepts any key length");
    mac.update(ciphertext);
    mac.verify_slice(&public.hmac)
        .map_err(|_| CryptoError::new("ocicrypt hmac verification failed"))?;

    let mut buf = ciphertext.to_vec();
    let mut cipher = Aes256Ctr::new(private.symmetric_key.as_slice().into(), nonce.as_slice().into());
    cipher.apply_keystream(&mut buf);

    if !private.digest.is_empty() {
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&buf)));
        if !private.digest.eq_ignore_ascii_case(&actual) {
            return Err(CryptoError::new("ocicrypt plaintext digest mismatch"));
        }
    }
    Ok(buf)
}

/// Encode public opts for the `enc.pubopts` layer annotation: base64(JSON).
pub fn pubopts_to_annotation(
    public: &PublicLayerBlockCipherOptions,
) -> Result<String, CryptoError> {
    let json = serde_json::to_vec(public).map_err(|e| CryptoError::new(e.to_string()))?;
    Ok(Base64::encode_string(&json))
}

/// Decode the `enc.pubopts` layer annotation value into public opts.
pub fn pubopts_from_annotation(
    value: &str,
) -> Result<PublicLayerBlockCipherOptions, CryptoError> {
    let json = Base64::decode_vec(value).map_err(|e| CryptoError::new(e.to_string()))?;
    serde_json::from_slice(&json).map_err(|e| CryptoError::new(e.to_string()))
}

/// Serialize private opts to JSON (the unwrapped form a key_source yields).
pub fn privopts_to_json(
    private: &PrivateLayerBlockCipherOptions,
) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(private).map_err(|e| CryptoError::new(e.to_string()))
}

/// Parse private opts from JSON bytes (the unwrapped form a key_source
/// yields — from the inbound key, or the KBS response).
pub fn privopts_from_json(bytes: &[u8]) -> Result<PrivateLayerBlockCipherOptions, CryptoError> {
    serde_json::from_slice(bytes).map_err(|e| CryptoError::new(e.to_string()))
}

/// serde adapter: `Vec<u8>` ⇄ standard-base64 string (ocicrypt JSON).
mod b64vec {
    use super::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&Base64::encode_string(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        Base64::decode_vec(&s).map_err(serde::de::Error::custom)
    }
}

/// serde adapter: `HashMap<String, Vec<u8>>` ⇄ map of base64 strings.
mod b64map {
    use std::collections::HashMap;

    use super::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeMap};

    pub fn serialize<S: Serializer>(m: &HashMap<String, Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(m.len()))?;
        for (k, v) in m {
            map.serialize_entry(k, &Base64::encode_string(v))?;
        }
        map.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<HashMap<String, Vec<u8>>, D::Error> {
        let raw = HashMap::<String, String>::deserialize(d)?;
        raw.into_iter()
            .map(|(k, v)| {
                Base64::decode_vec(&v)
                    .map(|b| (k, b))
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let plaintext = b"the quick brown wasm component".repeat(100);
        let (ct, public, private) = encrypt(&plaintext);
        assert_ne!(ct, plaintext);
        let out = decrypt(&ct, &public, &private).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn round_trip_through_annotation_and_json() {
        let plaintext = b"policy bytes".to_vec();
        let (ct, public, private) = encrypt(&plaintext);

        // public opts survive the base64(JSON) annotation form.
        let ann = pubopts_to_annotation(&public).unwrap();
        let public2 = pubopts_from_annotation(&ann).unwrap();
        // private opts survive the JSON wrap form.
        let json = privopts_to_json(&private).unwrap();
        let private2 = privopts_from_json(&json).unwrap();

        let out = decrypt(&ct, &public2, &private2).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_hmac() {
        let (mut ct, public, private) = encrypt(b"secret");
        ct[0] ^= 0xff;
        let err = decrypt(&ct, &public, &private).unwrap_err();
        assert!(err.to_string().contains("hmac"));
    }

    #[test]
    fn wrong_key_fails() {
        let (ct, public, _private) = encrypt(b"secret");
        let mut bad = PrivateLayerBlockCipherOptions {
            symmetric_key: vec![0u8; KEY_SIZE],
            cipher_options: HashMap::new(),
            digest: String::new(),
        };
        bad.cipher_options
            .insert(NONCE_KEY.to_string(), vec![0u8; NONCE_SIZE]);
        assert!(decrypt(&ct, &public, &bad).is_err());
    }
}
