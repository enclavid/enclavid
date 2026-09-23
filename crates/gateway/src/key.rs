//! The key this role serves on, and why it is the same one at every boot.
//!
//! ## What a new key would cost
//!
//! A certificate is issued for a key. Mint a fresh one at every boot and every
//! boot needs a fresh certificate — and a public authority will not issue them
//! at that rate: Let's Encrypt allows five per week for one set of names. A
//! role restarted six times in a week would simply stop having a certificate.
//!
//! The same key is also the only thing a caller can hold on to. One that
//! checked this role's quote once knows which key it belongs to, and can then
//! require that key on every later connection — an ordinary public-key pin,
//! which standard tools already do. A key that changed at every restart would
//! make that worth nothing.
//!
//! ## So it is DERIVED, not stored
//!
//! The chip derives a key from a secret fused into the part and this image's
//! measurement. This role derives its serving key from that, and therefore
//! arrives at the same key on every boot without keeping anything anywhere:
//! no blob, no disk, nothing handed to the host and handed back.
//!
//! What that binds it to is the pair (part, build). Another build on the same
//! part derives a different key; the same build on another part does too. Two
//! guests of this build on one part derive the SAME key — which is right, and
//! useful: they are one key domain, so one certificate serves them all and a
//! caller's pin holds across them.
//!
//! It cannot be derived by anyone else: the input is a chip secret. A caller
//! holding the measurement and the certificate still learns which key belongs
//! to this build only from the quote — which is the whole point of serving one.
//!
//! ## Why a certificate still has to be asked for
//!
//! The key is stable; the certificate around it is not this role's to make. A
//! browser-trusted one is issued by an authority, expires, and is renewed —
//! and a renewal replaces the wrapper, never the key, which is what keeps the
//! quote's binding and a caller's pin alive across it. See `crate::tls`.

/// What this key is derived FOR, so that no other value derived from the same
/// chip key can be mistaken for it — or arrived at by accident.
const PURPOSE: &[u8] = b"enclavid.gateway.serving-key.v1";

/// What a build with no chip derives from instead.
///
/// A developer build has no attestation and nothing secret to bind a key to, so
/// this is not a secret and is not pretending to be one: every developer build
/// serves on the same key. It exists so that such a build takes the SAME path
/// as the attested one — a key that is the same at every run, a certificate
/// issued over it, a pin that holds — rather than a second path that is only
/// exercised by developers.
#[cfg(not(feature = "sev-snp"))]
pub const NO_CHIP: [u8; 32] = *b"a developer build has no chip...";

/// The key this process serves on.
///
/// The quote binds its `SubjectPublicKeyInfo`, so a caller comparing the quote
/// to the certificate in front of it is comparing something that has not moved
/// — see `crate::attest`.
pub struct Identity {
    key: rcgen::KeyPair,
    spki: Vec<u8>,
}

impl Identity {
    /// The key this (part, build) serves on, arrived at again at every boot.
    ///
    /// `chip` is what the firmware derived for this guest. The curve is P-256
    /// because that is what a public authority will issue for and what every
    /// client verifies; the derivation therefore has to land on a valid scalar,
    /// and tries again with the next counter on the vanishingly rare occasion
    /// that it does not.
    pub fn derived(chip: &[u8; 32]) -> Result<Identity, String> {
        for counter in 0u8..8 {
            let mut info = PURPOSE.to_vec();
            info.push(counter);
            let scalar = enclavid_crypto::kdf::derive_key(chip, &info);

            let Ok(secret) = p256::SecretKey::from_bytes(&scalar.into()) else {
                continue;
            };
            let der = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&secret)
                .map_err(|e| format!("encode the derived key: {e}"))?;
            let key = rcgen::KeyPair::try_from(der.as_bytes())
                .map_err(|e| format!("the derived bytes are not a key: {e}"))?;
            return Ok(Identity {
                spki: key.public_key_der(),
                key,
            });
        }
        Err("the derivation found no valid key in eight tries".into())
    }

    /// A key nothing derived, for a test that wants two different ones.
    ///
    /// Not a build's way of obtaining a key: a developer build derives from
    /// [`NO_CHIP`] so that it takes the same path as the attested one.
    #[cfg(test)]
    pub fn generated() -> Result<Identity, String> {
        let key = rcgen::KeyPair::generate().map_err(|e| format!("generate key: {e}"))?;
        Ok(Identity {
            spki: key.public_key_der(),
            key,
        })
    }

    /// The bytes a quote binds, and what a caller parses out of the certificate
    /// it validated — see `crate::attest`.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    pub(crate) fn key(&self) -> &rcgen::KeyPair {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: the same chip key gives the same serving key, so a
    /// certificate issued for it and a pin taken on it survive a restart.
    #[test]
    fn the_same_chip_key_gives_the_same_serving_key() {
        let first = Identity::derived(&[7; 32]).unwrap();
        let again = Identity::derived(&[7; 32]).unwrap();
        assert_eq!(first.spki(), again.spki());
        assert!(!first.spki().is_empty());
    }

    /// And another part, or another build on the same part, is another key —
    /// which is what binds the key to the pair rather than to the machine.
    #[test]
    fn another_chip_key_gives_another_serving_key() {
        let one = Identity::derived(&[7; 32]).unwrap();
        let other = Identity::derived(&[8; 32]).unwrap();
        assert_ne!(one.spki(), other.spki());
    }

    /// A build with nothing to derive from gets a different key every time, and
    /// says so by construction rather than by pretending to be stable.
    #[test]
    fn a_generated_key_is_a_new_key() {
        let one = Identity::generated().unwrap();
        let other = Identity::generated().unwrap();
        assert_ne!(one.spki(), other.spki());
    }

    /// The certificate this role serves is over the derived key, so what a
    /// caller pins and what the quote binds are the same bytes.
    #[test]
    fn the_certificate_carries_the_derived_key() {
        let identity = Identity::derived(&[7; 32]).unwrap();
        // Minting it at all is the assertion that rustls accepted the derived
        // key as one that signs for this certificate; what they carry is
        // checked by the tests in `crate::tls`.
        crate::tls::certified(&identity, &["verify.example.com"]).unwrap();
        assert_eq!(identity.spki(), Identity::derived(&[7; 32]).unwrap().spki());
    }
}
