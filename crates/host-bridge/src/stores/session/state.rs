//! `STATE` session field. Encrypted replay log produced by the policy
//! engine. Double-AEAD'd: inner layer under the applicant's bearer
//! key, outer under `TEE_key`. AAD = session_id on both layers, so
//! cross-session copies fail at the outer check before the inner one
//! is even attempted.
//!
//! State is only present once the applicant claims the session via
//! `/connect` and the policy runs at least one round; before that the
//! field is absent (`Option::None` from the read marker).

use prost::Message;

use crate::error::BridgeError;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::write_request::Op;
use crate::proto::session_store::{BlobField, FieldSelector};
use crate::proto::state::SessionState;

use super::Ctx;
use super::aead;
use super::core::{ReadField, WriteField, blob_op, blob_selector, unwrap_scalar};

/// Read marker: session state blob. Carries the applicant key for the
/// inner AEAD layer; `None` until the applicant connects and runs the
/// policy at least once.
pub struct State<'a> {
    pub applicant_key: &'a [u8],
}

/// Write marker: replace session state with the freshly-encoded
/// (and freshly-encrypted) replay log. Both AEAD layers happen
/// inside `build_op`.
pub struct SetState<'a> {
    pub state: &'a SessionState,
    pub applicant_key: &'a [u8],
}

impl ReadField for State<'_> {
    type Output = Option<SessionState>;

    fn selector(&self) -> FieldSelector {
        blob_selector(BlobField::State)
    }

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let Some(b) = unwrap_scalar(slot)? else { return Ok(None) };
        let outer = aead::open(&b, ctx.tee_key, ctx.aad())?;
        let inner = aead::open(&outer, self.applicant_key, ctx.aad())?;
        Ok(Some(SessionState::decode(inner.as_slice())?))
    }
}

impl WriteField for SetState<'_> {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Op, BridgeError> {
        // Inner under applicant_key, outer under TEE_key. Each layer
        // gets its own random nonce; AAD identical so cross-session
        // copies fail at the outer layer.
        let plaintext = self.state.encode_to_vec();
        let inner = aead::seal(&plaintext, self.applicant_key, ctx.aad())?;
        let value = aead::seal(&inner, ctx.tee_key, ctx.aad())?;
        Ok(blob_op(BlobField::State, value))
    }
}
