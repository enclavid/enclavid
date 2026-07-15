//! HKDF-SHA256 subkey derivation.
//!
//! Domain-separated 32-byte subkeys from a 32-byte master (e.g.
//! `tee_seal_key`): [`derive_key`] runs HKDF-Extract-then-Expand with
//! `info` as the context label, so distinct labels yield
//! cryptographically independent keys and the master is never used
//! directly for two purposes. Used by the L2 cwasm-cache to split the
//! master into a seal key and a filename-labelling key, and to compute
//! the identity-hiding blob name.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 32-byte subkey from `master` under the context label
/// `info`. Deterministic in `(master, info)`; distinct `info` values
/// are independent. `info` may be any length (it is the HKDF-Expand
/// context, not the IKM).
pub fn derive_key(master: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32-byte OKM fits in one HKDF-SHA256 block");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_domain_separated() {
        let master = [7u8; 32];
        // Same (master, info) → same key.
        assert_eq!(derive_key(&master, b"a"), derive_key(&master, b"a"));
        // Distinct info → independent keys.
        assert_ne!(derive_key(&master, b"a"), derive_key(&master, b"b"));
        // Distinct master → independent keys.
        assert_ne!(derive_key(&master, b"a"), derive_key(&[8u8; 32], b"a"));
    }
}
