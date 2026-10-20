//! `STATE` session field. Encrypted replay log produced by the policy
//! engine. Double-AEAD'd: inner layer under the applicant's bearer
//! key, outer under `tee_seal_key`. AAD = session_id on both layers, so
//! cross-session copies fail at the outer check before the inner one
//! is even attempted.
//!
//! State is only present once the applicant claims the session via
//! `/connect` and the policy runs at least one round; before that the
//! field is absent (`Option::None` from the read marker).

use session_types::{SEALED_STATE_PLAINTEXT_BYTES, SessionState};
use storage_rpc::{BlobField, BlobWrite, FieldSelector, Op, Slot};

use crate::boundary;
use crate::error::StoreError;
use enclavid_boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};

use enclavid_crypto::aead;

use super::Ctx;
use super::core::{ReadField, WriteField, unwrap_scalar};

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

/// Read marker: session state blob. Carries the applicant key for
/// the inner AEAD layer. Output is `Untrusted<Option<SessionState>,
/// (Replay,)>` — the boundary entry hands us `(AuthN, AuthZ, Replay)`
/// open; outer-AEAD-open closes AuthN (real crypto), inner-AEAD-open
/// closes AuthZ (key possession authorises, real crypto). Only Replay
/// remains as a caller concern. `None` until the applicant connects
/// and runs the policy at least once.
pub struct State<'a> {
    pub applicant_session_token: &'a [u8],
}

/// Write marker: replace session state with the freshly-encoded,
/// constant-size-padded, freshly-encrypted `SessionState`. Payload is
/// `Exposed<Vec<u8>, (AuthN,)>` — the caller's Covert vouch already
/// encoded + padded it (`encode_padded`) to a fixed plaintext size, so the
/// sealed ciphertext is constant every round and the size covert channel is
/// closed; the caller also pre-vouches AuthZ (key-possession reasoning).
/// Host-bridge closes AuthN via the double-AEAD seal it owns the keys for.
pub struct SetState<'a> {
    pub state: Exposed<Vec<u8>, (AuthN,)>,
    pub applicant_session_token: &'a [u8],
}

impl ReadField for State<'_> {
    type Output = Untrusted<Option<SessionState>, (Replay,)>;

    fn selector(&self) -> FieldSelector {
        FieldSelector::Blob(BlobField::State)
    }

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, StoreError> {
        let Some(b) = unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None));
        };
        let decoded: Untrusted<SessionState, (Replay,)> = boundary::inbound::from_untrusted(b)
            .trust_with(AuthN::Verified, |raw| {
                aead::open(&raw, ctx.tee_seal_key, ctx.aad())
            })?
            .trust_with(AuthZ::Matched, |outer| -> Result<_, StoreError> {
                let inner = aead::open(&outer, self.applicant_session_token, ctx.aad())?;
                Ok(session_types::decode::<SessionState>(&inner)?)
            })?;
        Ok(decoded.map(Some))
    }
}

impl WriteField for SetState<'_> {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, StoreError> {
        // AuthZ + Covert (constant-size padding via `encode_padded`) are
        // pre-vouched at the construction site; `state` is already the encoded
        // + padded plaintext. Host-bridge closes AuthN with the double-AEAD
        // seal: inner under applicant_session_token, outer under tee_seal_key.
        // Each layer gets its own random nonce; AAD identical so cross-session
        // copies fail at the outer layer.
        let sealed = self.state.clone().vouch_with(
            AuthN::Verified,
            |plaintext| -> Result<Vec<u8>, StoreError> {
                let inner = aead::seal(&plaintext, self.applicant_session_token, ctx.aad())?;
                aead::seal(&inner, ctx.tee_seal_key, ctx.aad()).map_err(Into::into)
            },
        )?;
        Ok(sealed.map(|value| {
            Op::Blob(BlobWrite {
                field: BlobField::State,
                value,
            })
        }))
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
}
