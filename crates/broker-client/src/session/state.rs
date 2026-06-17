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

/// Write marker: replace session state with the freshly-encoded
/// (and freshly-encrypted) replay log. Payload is
/// `Exposed<&SessionState, (AuthN,)>` — caller pre-vouches AuthZ +
/// Covert at the construction site (api persister knows the inner
/// key-possession reasoning and the consumer-side decode posture).
/// Host-bridge closes AuthN via the double-AEAD seal it owns the
/// keys for.
pub struct SetState<'a> {
    pub state: Exposed<&'a SessionState, (AuthN,)>,
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
        // AuthZ + Covert pre-vouched at the construction site.
        // Host-bridge closes AuthN with the double-AEAD seal: inner
        // under applicant_session_token, outer under tee_seal_key.
        // Each layer gets its own random nonce; AAD identical so
        // cross-session copies fail at the outer layer.
        let sealed = self.state.clone().vouch::<AuthN, _, _, _, _>(
            |state| -> Result<Vec<u8>, BridgeError> {
                let plaintext = domain::encode(state)?;
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

