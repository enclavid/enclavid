//! `STATE` session field. Encrypted replay log produced by the policy
//! engine. Double-AEAD'd: inner layer under the applicant's bearer
//! key, outer under `TEE_key`. AAD = session_id on both layers, so
//! cross-session copies fail at the outer check before the inner one
//! is even attempted.
//!
//! State is only present once the applicant claims the session via
//! `/connect` and the policy runs at least one round; before that the
//! field is absent (`Option::None` from the read marker).

use enclavid_untrusted::{Exposed, Replay, Untrusted, reason};
use prost::Message;

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
/// (Replay,)>` — both AEAD layers (applicant_key + tee_key) execute
/// inside `decode`, clearing AuthN on success; AuthZ is implicitly
/// established by holding the right `applicant_key` (the inner AEAD
/// authenticates against it). Only Replay remains as a callee
/// concern. `None` until the applicant connects and runs the policy
/// at least once.
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
    type Output = Untrusted<Option<SessionState>, (Replay,)>;

    fn selector(&self) -> FieldSelector {
        FieldSelector {
            kind: Some(SelectorKind::Blob(BlobField::State as i32)),
        }
    }

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let scope_reason = reason!(r#"
Double-AEAD'd: outer under TEE_key, inner under applicant_key,
both AAD'd to session_id. Both opens succeeded ⇒ bytes are ours
(AuthN cleared) AND caller has the right applicant_key, which
itself authorizes state access (AuthZ implicit). Replay open:
host might serve an older blob from before recent /input; bound
by per-call version-CAS during the run.
        "#);
        let Some(b) = unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None, scope_reason));
        };
        let outer = aead::open(&b, ctx.tee_key, ctx.aad())?;
        let inner = aead::open(&outer, self.applicant_key, ctx.aad())?;
        Ok(Untrusted::new(
            Some(SessionState::decode(inner.as_slice())?),
            scope_reason,
        ))
    }
}

impl WriteField for SetState<'_> {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op>, BridgeError> {
        // Inner under applicant_key, outer under TEE_key. Each layer
        // gets its own random nonce; AAD identical so cross-session
        // copies fail at the outer layer.
        let plaintext = self.state.encode_to_vec();
        let inner = aead::seal(&plaintext, self.applicant_key, ctx.aad())?;
        let value = aead::seal(&inner, ctx.tee_key, ctx.aad())?;
        // Double-AEAD ciphertext: inner layer keyed to the applicant's
        // per-session bearer key (held only by the connected
        // applicant); outer layer keyed to the TEE-side per-instance
        // key. Host has neither key. Replay log content (documents,
        // biometrics, intermediate plugin outputs) never leaves the
        // TEE in plaintext.
        Ok(Exposed::expose(Op {
            kind: Some(OpKind::Blob(BlobWrite {
                field: BlobField::State as i32,
                value,
            })),
        }))
    }
}
