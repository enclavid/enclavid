//! Anonymous public-key sealing to a consumer's X25519 key — libsodium's
//! `crypto_box_seal` construction, byte-compatible with any libsodium binding.
//!
//! Used for outbound data the host stores opaquely but a downstream consumer
//! reads: disclosure entries sealed to `client_disclosure_pubkey`.
//!
//! Symmetric counterpart to [`crate::aead`], but for a recipient whose private
//! key the TEE never holds. Two properties follow from the construction rather
//! than from discipline:
//!
//! * The sender's keypair is **ephemeral and discarded** inside `seal`, so the
//!   TEE cannot decrypt what it just wrote. There is no key to subpoena, lose or
//!   misuse — it stopped existing when the function returned.
//! * The ciphertext does not identify the sender.
//!
//! Wire format is libsodium's: `ephemeral_pk (32) || XSalsa20-Poly1305 box`,
//! the nonce derived as `BLAKE2b(ephemeral_pk || recipient_pk)`. A consumer
//! decrypts with one call — `crypto_box_seal_open` in C, `SealedBox` in PyNaCl,
//! `sealedbox.Open` in Go — using a library they already have rather than a
//! format-specific one.
//!
//! Keys cross our API as lowercase hex: 64 characters, no padding, no encoding
//! variants to get wrong.

use crypto_box::aead::OsRng;
use crypto_box::{PublicKey, SecretKey};

use crate::error::CryptoError;

/// Bytes a sealed box adds to its plaintext: the ephemeral public key plus the
/// Poly1305 tag.
pub const SEAL_OVERHEAD_BYTES: usize = 32 + 16;

/// Seal `plaintext` to the X25519 recipient in `recipient_hex` (64 hex chars).
/// Returns the libsodium sealed box, ready to hand to a host store.
pub fn seal_to_recipient(plaintext: &[u8], recipient_hex: &str) -> Result<Vec<u8>, CryptoError> {
    let public = PublicKey::from(decode_key(recipient_hex, "recipient")?);
    public
        .seal(&mut OsRng, plaintext)
        .map_err(|e| CryptoError::new(format!("sealed box: {e}")))
}

/// Open a sealed box with the recipient's secret key (64 hex chars). Not used
/// in the TEE — it holds no secret key — but shared with the CLI so both sides
/// agree on the encoding by construction.
pub fn open_sealed(ciphertext: &[u8], secret_hex: &str) -> Result<Vec<u8>, CryptoError> {
    let secret = SecretKey::from(decode_key(secret_hex, "secret")?);
    secret
        .unseal(ciphertext)
        .map_err(|_| CryptoError::new("sealed box open failed (wrong disclosure key?)".to_string()))
}

/// Generate a recipient keypair, returned as `(secret_hex, public_hex)`.
pub fn generate_recipient() -> (String, String) {
    let secret = SecretKey::generate(&mut OsRng);
    let public = secret.public_key();
    (
        hex::encode(secret.to_bytes()),
        hex::encode(public.as_bytes()),
    )
}

/// Recover the recipient's public key from its secret. Lets a caller that was
/// handed only a secret still name the recipient, without keeping the pair
/// together on disk.
pub fn public_from_secret(secret_hex: &str) -> Result<String, CryptoError> {
    let secret = SecretKey::from(decode_key(secret_hex, "secret")?);
    Ok(hex::encode(secret.public_key().as_bytes()))
}

fn decode_key(s: &str, what: &str) -> Result<[u8; 32], CryptoError> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(CryptoError::new(format!(
            "invalid {what} key: expected 64 hex chars, got {}",
            s.len()
        )));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out)
        .map_err(|_| CryptoError::new(format!("invalid {what} key: not hex")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (secret, public) = generate_recipient();
        let sealed = seal_to_recipient(b"disclosure", &public).unwrap();
        assert_eq!(open_sealed(&sealed, &secret).unwrap(), b"disclosure");
    }

    #[test]
    fn wrong_key_fails() {
        let (_, public) = generate_recipient();
        let (other_secret, _) = generate_recipient();
        let sealed = seal_to_recipient(b"disclosure", &public).unwrap();
        assert!(open_sealed(&sealed, &other_secret).is_err());
    }

    #[test]
    fn malformed_recipient_is_rejected() {
        assert!(seal_to_recipient(b"x", "not-hex").is_err());
        assert!(seal_to_recipient(b"x", &"aa".repeat(31)).is_err());
    }

    /// Why the disclosure size-padding is both necessary and sufficient:
    /// sealed-box ciphertext length is exactly plaintext + [`SEAL_OVERHEAD_BYTES`],
    /// so a colluding policy could ride a field value's byte length into the
    /// host-observable length — which is why every disclosure envelope is padded
    /// to a constant plaintext frame before sealing (api's
    /// `SEALED_DISCLOSURE_PLAINTEXT_BYTES`). Unlike age there is no header
    /// randomness here, so the length is a pure function of the plaintext length:
    /// once that is pinned, the ciphertext length carries no signal at all.
    #[test]
    fn ciphertext_length_is_plaintext_length_plus_fixed_overhead() {
        let (_, public) = generate_recipient();
        for len in [0usize, 1, 1024, 64 * 1024] {
            let sealed = seal_to_recipient(&vec![0u8; len], &public).unwrap();
            assert_eq!(sealed.len(), len + SEAL_OVERHEAD_BYTES);
        }
    }
}
