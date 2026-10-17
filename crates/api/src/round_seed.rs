//! The seed of each round's randomness: what the round's `wasi:random` calls
//! draw from, on the worker that runs it.
//!
//! Derived, not drawn. The host can fail a round to have it run again, or hand
//! back a state it stored before, and a round drawing fresh entropy each time
//! would let it — with an applicant beside it — re-roll what the policy picks
//! at random (a liveness challenge) until it matches what they came prepared
//! for. So the seed is a function of the session and of how many rounds it has
//! run, which is sealed with the state the round starts from: whatever makes a
//! round run again, it draws the same bytes.
//!
//! Keyed by `tee_seal_key`, an attested secret only the enclave knows, so
//! neither the host nor whoever holds the policy can compute it, and every
//! (session, round) has one of its own.
//!
//! ```text
//! tee_seal_key ──HKDF-SHA256──> RoundSeeds ──HKDF-SHA256(session_id || rounds)──> seed
//! ```

use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;

/// Process-lifetime key the round seeds are derived from. `SecretBox` zeroizes
/// it on drop and keeps it out of any `Debug`.
pub struct RoundSeeds(SecretBox<[u8; 32]>);

impl RoundSeeds {
    /// Expand `tee_seal_key` under a label of its own, so this key is
    /// independent of every other use of the same secret.
    pub fn from_tee_seal_key(tee_seal_key: &[u8; 32]) -> Self {
        Self(SecretBox::new(Box::new(enclavid_crypto::kdf::derive_key(
            tee_seal_key,
            b"enclavid.round-seeds.v1",
        ))))
    }

    /// The seed of the round a session starts from a state that has run
    /// `rounds` rounds.
    pub fn for_round(&self, session_id: &str, rounds: u64) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, self.0.expose_secret());
        let mut seed = [0u8; 32];
        hk.expand_multi_info(
            &[
                b"enclavid.round-seed.v1\0",
                session_id.as_bytes(),
                b"\0",
                &rounds.to_be_bytes(),
            ],
            &mut seed,
        )
        .expect("32-byte OKM fits in one HKDF-SHA256 block");
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_round_has_one_seed_and_every_other_round_another() {
        let seeds = RoundSeeds::from_tee_seal_key(&[7u8; 32]);
        let seed = seeds.for_round("ses_a", 3);
        assert_eq!(seed, seeds.for_round("ses_a", 3));
        assert_ne!(seed, seeds.for_round("ses_a", 4));
        assert_ne!(seed, seeds.for_round("ses_b", 3));
        assert_ne!(
            seed,
            RoundSeeds::from_tee_seal_key(&[8u8; 32]).for_round("ses_a", 3)
        );
    }
}
