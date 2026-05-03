//! AEAD primitives for session-blob encryption.
//!
//! ChaCha20-Poly1305 with a random 12-byte nonce per call. Nonce is
//! prefixed to the ciphertext on the wire: `blob = nonce[0..12] ||
//! ciphertext_with_tag`.
//!
//! `aad` carries the session_id (and any other binding context) so a
//! ciphertext copied between sessions fails authentication on `open`.
//!
//! Key length: 32 bytes (ChaCha20-Poly1305 standard).
//!
//! Layered encryption (e.g. STATE = inner(applicant_key) +
//! outer(TEE_key)) is composed at the call site by chaining `seal`
//! twice — each layer carries its own random nonce, and AAD is the
//! same on both layers.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::OsRng;

use crate::error::BridgeError;

const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` under `key` with `aad` binding, return
/// `nonce || ciphertext_with_tag`.
pub fn seal(plaintext: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>, BridgeError> {
    let cipher = cipher_for(key)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| BridgeError::Transport("aead seal failed".to_string()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `nonce || ciphertext_with_tag` under `key` with `aad`
/// binding. Returns the plaintext.
///
/// AEAD authentication failure (wrong key, wrong AAD, tampered
/// ciphertext) collapses to a transport error — caller treats it the
/// same as a host-supplied bogus blob.
pub fn open(blob: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>, BridgeError> {
    if blob.len() < NONCE_LEN {
        return Err(BridgeError::Transport("aead blob too short".to_string()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = cipher_for(key)?;
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| BridgeError::Transport("aead open failed".to_string()))
}

fn cipher_for(key: &[u8]) -> Result<ChaCha20Poly1305, BridgeError> {
    if key.len() != 32 {
        return Err(BridgeError::Transport(format!(
            "aead key must be 32 bytes, got {}",
            key.len()
        )));
    }
    Ok(ChaCha20Poly1305::new(Key::from_slice(key)))
}
