//! `STATE` session field. The policy reducer's sealed state. Double-AEAD'd:
//! inner layer under the session's data key, which only the applicant's key
//! unlocks (see `lock`), outer under `tee_seal_key`. Both layers are bound
//! (AAD) to the field, to the session, and to what the record's metadata says
//! of the session's applicant ([`StateBinding`]). So a state opens only beside
//! the metadata it was written with: not as metadata, not in another session,
//! and not after a reset, a hand-over, or another disclosure or capture than
//! the ones it was written beside.
//!
//! State is only present once the applicant claims the session via
//! `/connect` and the policy runs at least one round; before that the
//! field is absent, and a reset makes it absent again.

use sha2::{Digest, Sha256};

use session_types::{SEALED_STATE_PLAINTEXT_BYTES, SessionMetadata, SessionState};
use storage_rpc::{Fields, Ops, Slot, StateOp};

use crate::boundary::Storage;
use crate::error::StoreError;
use enclavid_boundary::{AuthN, AuthZ, ExposedBuilder, Replay, Untrusted};

use enclavid_crypto::aead;

use super::Ctx;
use super::core::{ReadField, WriteField, scalar};

/// What a state's seal is labelled with, apart from every other field's.
const STATE_AAD: &[u8] = b"enclavid.state.v1";
/// What a binding's digest is labelled with.
const BINDING: &[u8] = b"enclavid.state-binding.v1";

/// Encode `state` and pad it with trailing zeros to
/// [`SEALED_STATE_PLAINTEXT_BYTES`], so the sealed ciphertext is a fixed size
/// regardless of content. `ciborium::from_reader` reads exactly one value and
/// ignores the trailing padding, so [`session_types::decode`] needs NO un-pad —
/// the padding is write-only, transparent on read. Errors (traps the write) if
/// the encoding already exceeds the frame.
pub fn encode_padded(state: &SessionState) -> Result<Vec<u8>, StoreError> {
    let mut bytes = session_types::encode(state)?;
    if bytes.len() > SEALED_STATE_PLAINTEXT_BYTES {
        return Err(StoreError::Codec(format!(
            "encoded SessionState is {} bytes, over the {SEALED_STATE_PLAINTEXT_BYTES}-byte \
             sealed-state frame",
            bytes.len(),
        )));
    }
    bytes.resize(SEALED_STATE_PLAINTEXT_BYTES, 0);
    Ok(bytes)
}

/// What a state is bound to beside its session: everything of an applicant the
/// record's metadata records — the lock its data key is kept in, and the hashes
/// of its disclosures and of its captures, in the order the metadata keeps them.
///
/// In an honest record the state is always sealed to the metadata beside it: a
/// round that adds to either list writes the state with the lists it leaves, a
/// hand-over writes it with the lock it leaves, and a reset clears all three in
/// the write that drops the state. So a state put back from before a reset, a
/// hand-over, or a newer disclosure or capture, is bound to something else and
/// does not open; and a state missing beside metadata that records an applicant
/// was removed by whoever holds the volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateBinding {
    digest: [u8; 32],
    /// Whether the metadata records nothing of an applicant: the one record a
    /// state may be missing from.
    empty: bool,
}

impl StateBinding {
    pub fn of(metadata: &SessionMetadata) -> Self {
        let mut h = Sha256::new();
        h.update(BINDING);
        match &metadata.data_key_lock {
            Some(lock) => {
                h.update([1]);
                h.update((lock.len() as u64).to_le_bytes());
                h.update(lock);
            }
            None => h.update([0]),
        }
        h.update((metadata.disclosure_entry_hashes.len() as u64).to_le_bytes());
        for entry in &metadata.disclosure_entry_hashes {
            h.update(entry);
        }
        h.update((metadata.captured_media.len() as u64).to_le_bytes());
        for capture in &metadata.captured_media {
            h.update((capture.len() as u64).to_le_bytes());
            h.update(capture);
        }
        Self {
            digest: h.finalize().into(),
            empty: metadata.data_key_lock.is_none()
                && metadata.disclosure_entry_hashes.is_empty()
                && metadata.captured_media.is_empty(),
        }
    }
}

/// The AAD both of a state's layers are sealed under: the field, the binding,
/// the session. The label and the digest are fixed-length, so the session id
/// last cannot be read two ways.
fn aad(session_id: &str, binding: &StateBinding) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STATE_AAD.len() + 32 + session_id.len());
    aad.extend_from_slice(STATE_AAD);
    aad.extend_from_slice(&binding.digest);
    aad.extend_from_slice(session_id.as_bytes());
    aad
}

/// Read marker: the session's state as the store keeps it, still sealed —
/// shape-checked, every concern open. It is opened by
/// [`SessionStore::open_state`](super::SessionStore::open_state), beside the
/// record's metadata, which says what it must be bound to.
pub struct SealedState;

/// Write marker: replace session state with the freshly-encoded,
/// constant-size-padded, freshly-encrypted `SessionState`. Payload is a
/// [`StateOp`] being built, holding the encoded state padded to a fixed
/// plaintext size (`encode_padded`, the work the caller answered `Covert`
/// with), so the sealed ciphertext is constant every round; [`Storage`]
/// answers `AuthZ` for every state op. storage-client answers `AuthN` with the
/// double-AEAD seal it owns the keys for, which builds the op. `binding` is
/// that of the metadata this write leaves beside the state.
pub struct SetState<'a> {
    pub state: ExposedBuilder<Vec<u8>, StateOp, (AuthN,), Storage>,
    pub data_key: &'a [u8],
    pub binding: StateBinding,
}

impl ReadField for SealedState {
    type Output = Untrusted<Option<Vec<u8>>, (AuthN, AuthZ, Replay), Storage>;

    fn select(&self, fields: &mut Fields<Storage>) {
        fields.state();
    }

    fn decode(
        self,
        slot: Untrusted<Slot, (AuthN, AuthZ, Replay), Storage>,
        _ctx: &Ctx<'_>,
    ) -> Result<Self::Output, StoreError> {
        scalar(slot)
    }
}

/// Open `sealed` as the state of the record whose metadata, opened, is
/// `metadata`. Outer-AEAD-open under `tee_seal_key` and the binding closes
/// AuthN; inner-AEAD-open under the data key closes AuthZ — the key is only
/// ever had by unlocking it with the applicant's, so possession authorises. A
/// missing state is believed only beside metadata that records nothing of an
/// applicant — the check that answers AuthN for it — and is refused as a state
/// that does not open otherwise.
pub(super) fn open(
    ctx: &Ctx<'_>,
    sealed: Untrusted<Option<Vec<u8>>, (AuthN, AuthZ, Replay), Storage>,
    metadata: &SessionMetadata,
    data_key: &[u8],
) -> Result<Untrusted<Option<SessionState>, (Replay,), Storage>, StoreError> {
    let binding = StateBinding::of(metadata);
    let aad = aad(ctx.session_id, &binding);
    sealed
        .trust_with(AuthN::Verified, |sealed| match sealed {
            Some(raw) => Ok(Some(aead::open(&raw, ctx.tee_seal_key, &aad)?)),
            None if binding.empty => Ok(None),
            None => Err(StoreError::Crypto(
                "the record's metadata holds an applicant's data its state is missing from".into(),
            )),
        })?
        .trust_with(AuthZ::Matched, |outer| -> Result<_, StoreError> {
            outer
                .map(|outer| {
                    let inner = aead::open(&outer, data_key, &aad)?;
                    Ok(session_types::decode::<SessionState>(&inner)?)
                })
                .transpose()
        })
}

impl WriteField for SetState<'_> {
    fn add_to(&self, ops: &mut Ops<Storage>, ctx: &Ctx<'_>) -> Result<(), StoreError> {
        // `state` is already the encoded + padded plaintext. The double-AEAD
        // seal answers AuthN and builds the op: inner under the data key, outer
        // under tee_seal_key. Each layer gets its own random nonce; both are
        // bound to the same AAD, so a copy into another session, or beside other
        // metadata, fails at the outer layer.
        let aad = aad(ctx.session_id, &self.binding);
        let op = self
            .state
            .clone()
            .vouch_with(AuthN::Verified, |plaintext| -> Result<_, StoreError> {
                let inner = aead::seal(&plaintext, self.data_key, &aad)?;
                Ok(StateOp(aead::seal(&inner, ctx.tee_seal_key, &aad)?))
            })?
            .build();
        ops.state(op);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_encoding_is_constant_and_round_trips() {
        // The encoded+padded blob must be a FIXED size AND decode back to the
        // original — proving `ciborium::from_reader` reads one value and
        // ignores the trailing zero padding (so the pad is write-only, no
        // un-pad on read).
        let with_state = SessionState {
            state: b"step=3, age_ok, some verdict bytes".to_vec(),
            ..Default::default()
        };
        for s in [SessionState::default(), with_state] {
            let padded = encode_padded(&s).unwrap();
            assert_eq!(padded.len(), SEALED_STATE_PLAINTEXT_BYTES, "constant size");
            let decoded: SessionState = session_types::decode(&padded).unwrap();
            assert_eq!(decoded, s, "decode ignores trailing padding");
        }
    }

    /// A binding moves with the lock, and with every disclosure and capture the
    /// metadata records, and says the metadata records nothing only when it
    /// holds none of them.
    #[test]
    fn a_binding_follows_what_the_applicant_left() {
        let mut md = SessionMetadata::default();
        let none = StateBinding::of(&md);
        assert!(none.empty);
        md.data_key_lock = Some(vec![3; 60]);
        let claimed = StateBinding::of(&md);
        assert!(!claimed.empty);
        assert_ne!(claimed, none);
        md.data_key_lock = Some(vec![4; 60]);
        assert_ne!(StateBinding::of(&md), claimed, "a hand-over rebinds");
        md.data_key_lock = None;
        md.captured_media.push(vec![1; 32]);
        let captured = StateBinding::of(&md);
        assert!(!captured.empty);
        assert_ne!(captured, none);
        md.disclosure_entry_hashes.push([2; 32]);
        let disclosed = StateBinding::of(&md);
        assert_ne!(disclosed, captured);
        md.disclosure_entry_hashes.clear();
        md.captured_media.clear();
        assert_eq!(
            StateBinding::of(&md),
            none,
            "a reset's lists bind as none did"
        );
    }
}
