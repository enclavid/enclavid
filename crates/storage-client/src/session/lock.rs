//! A session's data keys, and the lock they are kept in.
//!
//! A session's state and media are sealed, inside, under keys of the session's
//! own: random, one made when an applicant first claims the session and one
//! more each time it is taken over to another device. Everything is sealed under
//! the newest; what was sealed earlier stays under the key it was sealed under.
//! The keys are kept only locked — sealed together under the key of the
//! applicant who holds the session — in the session's metadata
//! (`SessionMetadata::data_key_lock`).
//!
//! So the applicant's key is what opens the session, and handing the session to
//! another key locks these keys again rather than sealing anew everything the
//! applicant brought. And what is written after a take is sealed under a key the
//! device that gave the session away never held: a key that held the session
//! once — and any lock it opened, wherever a copy of it was kept — reaches only
//! what was sealed while it held it.

use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};

use enclavid_crypto::aead;

use crate::error::StoreError;

/// What a lock is labelled with, apart from every other seal.
const LOCK_AAD: &[u8] = b"enclavid.data-key-lock.v1";
/// What a lock's digest is labelled with.
const LOCK_DIGEST: &[u8] = b"enclavid.data-key-lock-digest.v1";

/// How many keys a lock holds at most: a session can be taken over one fewer
/// times — its own page's takes included, one each time a code is put away
/// untaken. A lock is one size whatever it holds — the count, the keys, the
/// rest zeros — so its size says nothing of how often the session changed
/// hands.
pub const MAX_DATA_KEYS: usize = 64;

/// The plaintext a lock seals: the count, then room for every key.
const LOCK_FRAME: usize = 1 + MAX_DATA_KEYS * 32;

/// A session's data keys, open, oldest first: the newest is the one everything
/// is sealed under now. Held for one request, each zeroized on drop.
pub struct DataKeys(Vec<SecretBox<[u8; 32]>>);

impl DataKeys {
    /// The keys of a session an applicant is claiming: one, fresh.
    pub fn fresh() -> Self {
        Self(vec![SecretBox::new(Box::new(aead::generate_key()))])
    }

    /// Whether a lock could hold no more: the session takes no more takes.
    pub fn is_full(&self) -> bool {
        self.0.len() >= MAX_DATA_KEYS
    }

    /// These keys and a fresh one, which everything is sealed under from now
    /// on: the keys of a session taken over. `None` once a lock could hold no
    /// more.
    pub fn and_another(&self) -> Option<Self> {
        if self.is_full() {
            return None;
        }
        let mut keys: Vec<_> = self
            .0
            .iter()
            .map(|key| SecretBox::new(Box::new(*key.expose_secret())))
            .collect();
        keys.push(SecretBox::new(Box::new(aead::generate_key())));
        Some(Self(keys))
    }

    /// The key everything is sealed under now.
    pub fn current(&self) -> &[u8; 32] {
        self.0
            .last()
            .expect("a session has a key from its claim on")
            .expose_secret()
    }

    /// Every key, newest first: what something sealed earlier is under.
    pub fn newest_first(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.0.iter().rev().map(|key| key.expose_secret())
    }

    /// Keys as a test names them.
    #[cfg(test)]
    pub(crate) fn of(keys: &[[u8; 32]]) -> Self {
        Self(
            keys.iter()
                .map(|key| SecretBox::new(Box::new(*key)))
                .collect(),
        )
    }
}

/// The AAD a lock is sealed under: the label, then the session. The label is
/// fixed-length, so the session id last cannot be read two ways.
fn aad(session_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LOCK_AAD.len() + session_id.len());
    aad.extend_from_slice(LOCK_AAD);
    aad.extend_from_slice(session_id.as_bytes());
    aad
}

/// `keys` locked under `applicant_key`, for the session `session_id`.
pub fn lock_data_keys(
    session_id: &str,
    keys: &DataKeys,
    applicant_key: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut frame = vec![0u8; LOCK_FRAME];
    frame[0] = u8::try_from(keys.0.len()).expect("at most MAX_DATA_KEYS");
    let (slots, _) = frame[1..].as_chunks_mut::<32>();
    for (slot, key) in slots.iter_mut().zip(&keys.0) {
        *slot = *key.expose_secret();
    }
    let frame = SecretBox::new(Box::new(frame));
    Ok(aead::seal(
        frame.expose_secret(),
        applicant_key,
        &aad(session_id),
    )?)
}

/// The digest of `lock`: what a hand-over names the lock it was made against.
/// Every lock is sealed under a fresh nonce, so a lock replaced — taken over,
/// reset, claimed again — has another digest, even under the same keys, and
/// a hand-over made against the old one opens nothing.
pub fn lock_digest(lock: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LOCK_DIGEST);
    h.update(lock);
    h.finalize().into()
}

/// The keys `lock` holds, opened with `applicant_key`. A key that does not open
/// it, or a lock moved here from another session, is a `StoreError::Crypto`.
pub fn unlock_data_keys(
    session_id: &str,
    lock: &[u8],
    applicant_key: &[u8],
) -> Result<DataKeys, StoreError> {
    let frame = SecretBox::new(Box::new(aead::open(lock, applicant_key, &aad(session_id))?));
    let frame = frame.expose_secret();
    let count = usize::from(frame[..].first().copied().unwrap_or(0));
    if frame.len() != LOCK_FRAME || count == 0 || count > MAX_DATA_KEYS {
        return Err(StoreError::Crypto(
            "a data key lock out of its frame".into(),
        ));
    }
    let (keys, _) = frame[1..].as_chunks::<32>();
    Ok(DataKeys(
        keys.iter()
            .take(count)
            .map(|key| SecretBox::new(Box::new(*key)))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lock opens with the key it was locked under, in its own session, and
    /// with nothing else.
    #[test]
    fn a_lock_opens_only_with_its_key_in_its_session() {
        let keys = DataKeys::fresh();
        let locked = lock_data_keys("ses_a", &keys, &[1; 32]).unwrap();
        let opened = unlock_data_keys("ses_a", &locked, &[1; 32]).unwrap();
        assert_eq!(opened.current(), keys.current());
        assert!(matches!(
            unlock_data_keys("ses_a", &locked, &[2; 32]),
            Err(StoreError::Crypto(_))
        ));
        assert!(matches!(
            unlock_data_keys("ses_b", &locked, &[1; 32]),
            Err(StoreError::Crypto(_))
        ));
    }

    /// A take locks the keys again with one more, under the taker's key: the
    /// taker opens every key, the old key only the lock it held, which has
    /// none of what is sealed from now on — and every lock is one size.
    #[test]
    fn a_take_adds_a_key_the_old_holder_never_had() {
        let claimed = DataKeys::fresh();
        let first = lock_data_keys("ses_a", &claimed, &[1; 32]).unwrap();

        let taken = unlock_data_keys("ses_a", &first, &[1; 32])
            .unwrap()
            .and_another()
            .unwrap();
        let second = lock_data_keys("ses_a", &taken, &[2; 32]).unwrap();
        let opened = unlock_data_keys("ses_a", &second, &[2; 32]).unwrap();
        assert_ne!(opened.current(), claimed.current());
        assert_eq!(
            opened.newest_first().collect::<Vec<_>>(),
            [taken.current(), claimed.current()]
        );

        let old = unlock_data_keys("ses_a", &first, &[1; 32]).unwrap();
        assert!(old.newest_first().all(|key| key != opened.current()));
        assert!(unlock_data_keys("ses_a", &second, &[1; 32]).is_err());
        assert_eq!(first.len(), second.len(), "one size however many keys");
    }

    /// A lock takes keys up to its frame, and no more.
    #[test]
    fn a_lock_holds_at_most_its_frame_of_keys() {
        let mut keys = DataKeys::fresh();
        for _ in 1..MAX_DATA_KEYS {
            assert!(!keys.is_full());
            keys = keys.and_another().unwrap();
        }
        assert!(keys.is_full());
        assert!(keys.and_another().is_none());
        let locked = lock_data_keys("ses_a", &keys, &[1; 32]).unwrap();
        let opened = unlock_data_keys("ses_a", &locked, &[1; 32]).unwrap();
        assert_eq!(opened.newest_first().count(), MAX_DATA_KEYS);
    }

    /// A lock made again — the same keys, under the same key — is another
    /// lock: what a hand-over names is the one lock it was made against.
    #[test]
    fn every_lock_has_a_digest_of_its_own() {
        let keys = DataKeys::fresh();
        let first = lock_data_keys("ses_a", &keys, &[1; 32]).unwrap();
        let again = lock_data_keys("ses_a", &keys, &[1; 32]).unwrap();
        assert_eq!(lock_digest(&first), lock_digest(&first));
        assert_ne!(lock_digest(&first), lock_digest(&again));
    }
}
