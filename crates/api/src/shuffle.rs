//! TEE-keyed shuffle seed derivation for the disclosure-envelope
//! `DisplayField` order shuffle.
//!
//! Shuffle target: bytes that reach the consumer through
//! `DisclosureEnvelope` (the `/api/v1/sessions/{id}/disclosures`
//! payload). Policy-controlled field order is `log2(N!)` covert bits
//! per disclosure to the consumer — the consumer is the leak target
//! (relying party that the policy author can collude with). The
//! applicant's consent screen is **not** a leak surface (applicant
//! is the user, not the attacker) and renders policy order
//! unchanged for UX consistency.
//!
//! Engine doesn't pick its own randomness — host can subtly bias the
//! Linux entropy pool inputs (interrupt timing, virtio-rng) even with
//! CVM memory encryption protecting pool state. We dodge the entire
//! surface by deriving the per-envelope shuffle seed from
//! [`tee_seal_key`](crate::state::AppState::shuffle_key), an
//! attested 32-byte secret only the enclave knows. Consumer can't
//! reverse the shuffle to decode policy-encoded field order, host
//! can't game the entropy to produce predictable shuffles.
//!
//! Derivation chain:
//!
//! ```text
//! tee_seal_key  ──HKDF-SHA256──> ShuffleKey   (process-lifetime,
//!                                    │           domain-separated from
//!                                    │           AEAD usage)
//!                                    │
//!                                    │  per (session, disclosure index)
//!                                    ▼
//!                             HKDF-SHA256(session_id || disclosure_idx)
//!                                    │
//!                                    ▼
//!                             ChaCha20 PRNG ──> shuffle order
//! ```

use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;

/// Process-lifetime shuffle key. Loaded once at startup from
/// `tee_seal_key`; lives behind an `Arc` in
/// [`AppState`](crate::state::AppState) so both client and applicant
/// routes can derive per-envelope seeds without re-running HKDF on
/// the AEAD key. `SecretBox` zeroizes it on drop and keeps it out of any
/// `Debug` — this is a `tee_seal_key`-derived subkey, held for the whole run.
pub struct ShuffleKey(SecretBox<[u8; 32]>);

impl ShuffleKey {
    /// Expand `tee_seal_key` once under a static info string so the
    /// shuffle key is domain-separated from the AEAD usage of the
    /// same secret.
    pub fn from_tee_seal_key(tee_seal_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, tee_seal_key);
        let mut out = [0u8; 32];
        hk.expand(b"enclavid.shuffle-key.v1", &mut out)
            .expect("32-byte OKM fits in one HKDF-SHA256 block");
        Self(SecretBox::new(Box::new(out)))
    }

    /// Per-envelope seed. `disclosure_index` is the position of the
    /// envelope in the session's running disclosure list (matches
    /// `SessionMetadata.disclosure_count` immediately before this
    /// envelope is appended). Distinct envelopes within a session
    /// produce independent shuffles; the same envelope on replay
    /// reproduces the same shuffle bit-for-bit.
    pub fn derive_envelope_seed(
        &self,
        session_id: &str,
        disclosure_index: u64,
    ) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, self.0.expose_secret());
        let mut seed = [0u8; 32];
        hk.expand_multi_info(
            &[
                b"enclavid.envelope-shuffle.v1\0",
                session_id.as_bytes(),
                b"\0",
                &disclosure_index.to_be_bytes(),
            ],
            &mut seed,
        )
        .expect("32-byte OKM fits in one HKDF-SHA256 block");
        seed
    }
}
