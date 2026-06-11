//! `STATE` session field. Encrypted replay log produced by the policy
//! engine. Double-AEAD'd: inner layer under the applicant's bearer
//! key, outer under `tee_seal_key`. AAD = session_id on both layers, so
//! cross-session copies fail at the outer check before the inner one
//! is even attempted.
//!
//! State is only present once the applicant claims the session via
//! `/connect` and the policy runs at least one round; before that the
//! field is absent (`Option::None` from the read marker).

use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::reason;
use prost::Message;

use crate::boundary;
use crate::error::BridgeError;
use crate::proto::session_store::field_selector::Kind as SelectorKind;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::write_request::op::Kind as OpKind;
use crate::proto::session_store::write_request::{BlobWrite, Op};
use crate::proto::session_store::{BlobField, FieldSelector};
use crate::proto::state::SessionState;

use super::Ctx;
use super::aead;
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
        FieldSelector {
            kind: Some(SelectorKind::Blob(BlobField::State as i32)),
        }
    }

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let Some(b) = unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None, reason!(
                "absent state blob — applicant has not connected yet \
                 or hasn't completed any policy round"
            )));
        };
        let decoded: Untrusted<SessionState, (Replay,)> = boundary::inbound::from_host(b, reason!(r#"
Raw bytes claimed-as-SessionState blob from BlobField::State slot.
Boundary entry (AuthN, AuthZ, Replay) all open: AuthN closed below
by outer-AEAD-open under tee_seal_key; AuthZ closed below by
inner-AEAD-open under applicant_session_token (key possession is
the authorisation gate). Replay left for the caller — bounded by
per-call version-CAS during the run.
            "#))
            .trust::<AuthN, _, _, _, _>(|raw| aead::open(&raw, ctx.tee_seal_key, ctx.aad()))?
            .trust::<AuthZ, _, _, _, _>(|outer| {
                let inner = aead::open(&outer, self.applicant_session_token, ctx.aad())?;
                SessionState::decode(inner.as_slice()).map_err(BridgeError::from)
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
                let plaintext = state.encode_to_vec();
                let inner = aead::seal(&plaintext, self.applicant_session_token, ctx.aad())?;
                aead::seal(&inner, ctx.tee_seal_key, ctx.aad())
            },
        )?;
        Ok(sealed.map(|value| Op {
            kind: Some(OpKind::Blob(BlobWrite {
                field: BlobField::State as i32,
                value,
            })),
        }))
    }
}

