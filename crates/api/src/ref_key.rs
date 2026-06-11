//! TEE-keyed per-policy seed for the engine's `EmbeddedRegistry` ref
//! token derivation.
//!
//! Engine derives every `enclavid:embedded/*` ref as
//! `hex(BLAKE3-keyed(ref_key, slot_be ‖ tag ‖ ':' ‖ key))[..32]` —
//! the `ref_key` is the only thing that distinguishes a legitimate
//! token from a synthesised one. We derive it per-policy:
//!
//! ```text
//! tee_seal_key  ──HKDF-SHA256──> RefKey   (process-lifetime, domain-
//!                                    │         separated from AEAD /
//!                                    │         shuffle usage)
//!                                    │
//!                                    │  per `policy_ref`
//!                                    ▼
//!                       HKDF-SHA256(policy_ref) ──> 32-byte ref_key
//!                                                   for the engine
//! ```
//!
//! Why per-policy:
//!
//!   * Stable across all sessions of one policy artifact (refs must
//!     round-trip across `/connect` → `/input` rounds within a
//!     session, and the api keeps a per-(policy_ref, client_policy_
//!     key) registry cache shared across sessions on the same TEE).
//!   * Distinct across policies so a guest in one composition can't
//!     replay a token observed in a disclosure of a different
//!     policy's session (would otherwise round-trip if `ref_key` were
//!     process-wide).
//!
//! Domain separated from both AEAD usage of `tee_seal_key` (used to
//! seal SessionState / SessionMetadata) and from `ShuffleKey`
//! (consent-envelope field-order PRNG) via distinct info strings.

use hkdf::Hkdf;
use sha2::Sha256;

/// Process-lifetime base for engine ref-key derivation. Stretched
/// once at startup from `tee_seal_key`; held behind an `Arc` in
/// [`AppState`](crate::state::AppState) so `lookup_policy` can derive
/// the per-policy 32-byte ref_key without re-running the base
/// HKDF every time.
pub struct RefKey([u8; 32]);

impl RefKey {
    /// Stretch `tee_seal_key` once under a static info string so the
    /// engine ref-key base is domain-separated from AEAD / shuffle
    /// usage of the same secret.
    pub fn from_tee_seal_key(tee_seal_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, tee_seal_key);
        let mut out = [0u8; 32];
        hk.expand(b"enclavid.embedded-ref-key.v1", &mut out)
            .expect("32-byte OKM fits in one HKDF-SHA256 block");
        Self(out)
    }

    /// Derive the per-policy ref_key handed to
    /// [`EmbeddedRegistry::builder`](enclavid_engine::EmbeddedRegistry::builder).
    /// `policy_ref` is the pinned `<registry>/<repo>@sha256:<hex>`
    /// identifier — stable per-policy across all sessions, distinct
    /// across policies. Different policies (or different digests of
    /// the same policy) produce unrelated ref_keys, so cross-policy
    /// ref replay is cryptographically infeasible.
    pub fn derive_for_policy(&self, policy_ref: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand_multi_info(
            &[
                b"enclavid.embedded-ref-key.per-policy.v1\0",
                policy_ref.as_bytes(),
            ],
            &mut out,
        )
        .expect("32-byte OKM fits in one HKDF-SHA256 block");
        out
    }
}
