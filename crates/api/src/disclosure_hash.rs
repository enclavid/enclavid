//! SHA-256 hash chain over disclosure-list ciphertexts. Used by the
//! persister to maintain `SessionMetadata.disclosure_hash` and by
//! the disclosures handler to verify the host-served list.
//!
//! Chain:
//!   h_0     = SHA-256("enclavid-disclosure-chain" || session_id)
//!   h_{i+1} = SHA-256(h_i || ciphertext_{i+1})
//!
//! Living inside AEAD-sealed metadata, the chain end value can be
//! recomputed on read and compared to detect host fabrication,
//! truncation, reordering, or swap-with-other-session. Doesn't close
//! full-snapshot rollback (stateless TEE limitation; would require
//! external freshness oracle).

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"enclavid-disclosure-chain";

/// Seed of the chain for a session — used when no disclosures have
/// been committed yet, so the metadata always carries a non-empty
/// hash bound to session_id.
pub fn init(session_id: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(session_id.as_bytes());
    h.finalize().to_vec()
}

/// Extend the chain with one more ciphertext.
pub fn append(prev: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(ciphertext);
    h.finalize().to_vec()
}

/// Recompute the chain end value over a list of ciphertexts. Used at
/// read time to verify against `metadata.disclosure_hash`.
pub fn fold(session_id: &str, ciphertexts: &[Vec<u8>]) -> Vec<u8> {
    ciphertexts
        .iter()
        .fold(init(session_id), |acc, c| append(&acc, c))
}
