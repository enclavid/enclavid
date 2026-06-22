//! KBS artifact-key sealed box.
//!
//! A KBS releases an artifact's layer key (the ocicrypt private opts) by
//! wrapping it to the TEE's **ephemeral public key** — the same key the
//! TEE bound into its attestation report. Only the enclave that minted
//! that key can open the box, so the broker (which relays the bytes) and
//! anyone else see only ciphertext.
//!
//! Construction (libsodium-sealed-box shape): the sender generates its own
//! ephemeral X25519 keypair, does ECDH against the recipient's public key,
//! derives a key with HKDF-SHA256 (salt = sender_pub ‖ recipient_pub), and
//! seals with ChaCha20-Poly1305. The recipient repeats the ECDH with its
//! secret and the carried sender public key.
//!
//! This is an in-house equivalent of `kbs_protocol::TeeKeyPair` — we run
//! our own stub KBS for the MVP, so we own both ends of the wire; Trustee
//! RCAR/JWE wire-compat is a later enhancement.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;

const HKDF_INFO: &[u8] = b"enclavid-kbs-artifact-key-wrap-v1";

/// A sealed artifact key: the sender's ephemeral public key, the AEAD
/// nonce, and the ciphertext. Carried in the KBS response (the fields are
/// re-assembled by the caller into whatever wire DTO it uses).
pub struct Sealed {
    pub sender_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Generate a recipient (TEE) ephemeral keypair: `(secret, public)`. The
/// public half is bound into the attestation report; the secret never
/// leaves the enclave.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// Seal `plaintext` to `recipient_pub` (the KBS side). Returns the sealed
/// box for the caller to ship back to the TEE.
pub fn seal(recipient_pub: &[u8; 32], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    let sender_secret = StaticSecret::random_from_rng(OsRng);
    let sender_pub = PublicKey::from(&sender_secret).to_bytes();
    let recipient = PublicKey::from(*recipient_pub);
    let shared = sender_secret.diffie_hellman(&recipient);

    let key = derive_key(shared.as_bytes(), &sender_pub, recipient_pub);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| CryptoError::new("kbs wrap: seal failed"))?;

    Ok(Sealed {
        sender_pub,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Open a sealed box with the recipient (TEE) secret. Fails if the box was
/// not sealed to this key.
pub fn open(recipient_secret: &[u8; 32], sealed: &Sealed) -> Result<Vec<u8>, CryptoError> {
    let recipient = StaticSecret::from(*recipient_secret);
    let recipient_pub = PublicKey::from(&recipient).to_bytes();
    let sender = PublicKey::from(sealed.sender_pub);
    let shared = recipient.diffie_hellman(&sender);

    let key = derive_key(shared.as_bytes(), &sealed.sender_pub, &recipient_pub);
    let cipher = ChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(Nonce::from_slice(&sealed.nonce), sealed.ciphertext.as_ref())
        .map_err(|_| CryptoError::new("kbs wrap: open failed"))
}

fn derive_key(shared: &[u8], sender_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(sender_pub);
    salt.extend_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("32 is a valid HKDF-SHA256 output length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let (sk, pk) = generate_keypair();
        let sealed = seal(&pk, b"layer key opts").unwrap();
        let out = open(&sk, &sealed).unwrap();
        assert_eq!(out, b"layer key opts");
    }

    #[test]
    fn wrong_recipient_fails() {
        let (_sk, pk) = generate_keypair();
        let (other_sk, _) = generate_keypair();
        let sealed = seal(&pk, b"secret").unwrap();
        assert!(open(&other_sk, &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (sk, pk) = generate_keypair();
        let mut sealed = seal(&pk, b"secret").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(open(&sk, &sealed).is_err());
    }
}
