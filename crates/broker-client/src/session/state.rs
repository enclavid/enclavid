//! `STATE` session field. Encrypted replay log produced by the policy
//! engine. Double-AEAD'd: inner layer under the applicant's bearer
//! key, outer under `tee_seal_key`. AAD = session_id on both layers, so
//! cross-session copies fail at the outer check before the inner one
//! is even attempted.
//!
//! State is only present once the applicant claims the session via
//! `/connect` and the policy runs at least one round; before that the
//! field is absent (`Option::None` from the read marker).

use broker_protocol::{BlobField, BlobWrite, FieldSelector, Op, Slot};

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::domain::{self, SessionState};
use crate::error::BridgeError;

use enclavid_crypto::aead;

use super::Ctx;
use super::core::{ReadField, WriteField, unwrap_scalar};

/// Constant plaintext size the encoded `SessionState` is padded to before
/// sealing, so the host-observable ciphertext size is FIXED every round —
/// closing the size covert channel for BOTH `state` and `current_prompt`
/// (the policy controls their sizes; a colluding host could otherwise relay
/// the length). Trust-contract constant: an encoded `SessionState` larger
/// than this traps the write (re-attest on change).
///
/// Must cover the max encoding — the policy `state` (≤ engine
/// `POLICY_MAX_STATE_BYTES`, 1 MiB) plus the largest resolved prompt plus CBOR
/// overhead; the 256 KiB over the state cap is that prompt/overhead headroom.
/// Because the padding is unconditional this is also the *floor* cost of every
/// state write: each round seals exactly this many plaintext bytes regardless of
/// how little real state the policy carries. Raising `POLICY_MAX_STATE_BYTES`
/// raises this frame — and thus every write's seal cost — in lockstep.
pub const SEALED_STATE_PLAINTEXT_BYTES: usize = 1024 * 1024 + 256 * 1024;

/// Encode `state` and pad it with trailing zeros to
/// [`SEALED_STATE_PLAINTEXT_BYTES`], so the sealed ciphertext is a fixed size
/// regardless of content. `ciborium::from_reader` reads exactly one value and
/// ignores the trailing padding, so [`domain::decode`] needs NO un-pad — the
/// padding is write-only, transparent on read. Errors (traps the write) if
/// the encoding already exceeds the frame.
pub fn encode_padded(state: &SessionState) -> Result<Vec<u8>, BridgeError> {
    let mut bytes = domain::encode(state)?;
    if bytes.len() > SEALED_STATE_PLAINTEXT_BYTES {
        return Err(BridgeError::Codec(format!(
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

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let Some(b) = unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None));
        };
        let decoded: Untrusted<SessionState, (Replay,)> = boundary::inbound::from_untrusted(b)
            .trust::<AuthN, _, _, _, _>(|raw| aead::open(&raw, ctx.tee_seal_key, ctx.aad()))?
            .trust::<AuthZ, _, _, _, _>(|outer| {
                let inner = aead::open(&outer, self.applicant_session_token, ctx.aad())?;
                domain::decode::<SessionState>(&inner)
            })?;
        Ok(decoded.map(Some))
    }
}

impl WriteField for SetState<'_> {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, BridgeError> {
        // AuthZ + Covert (constant-size padding via `encode_padded`) are
        // pre-vouched at the construction site; `state` is already the encoded
        // + padded plaintext. Host-bridge closes AuthN with the double-AEAD
        // seal: inner under applicant_session_token, outer under tee_seal_key.
        // Each layer gets its own random nonce; AAD identical so cross-session
        // copies fail at the outer layer.
        let sealed = self.state.clone().vouch::<AuthN, _, _, _, _>(
            |plaintext| -> Result<Vec<u8>, BridgeError> {
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
            let decoded: SessionState = domain::decode(&padded).unwrap();
            assert_eq!(decoded, s, "decode ignores trailing padding");
        }
    }
}

