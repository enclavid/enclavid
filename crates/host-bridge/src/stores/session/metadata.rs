//! `METADATA` session field. Encrypted blob carrying per-session
//! configuration (tenant_id, policy ref, ephemeral pubkey, d_*,
//! client disclosure pubkey, input claims, external_ref). AEAD'd with
//! `TEE_key`; AAD = session_id binds it to the session that wrote it.

use enclavid_untrusted::{AuthZ, Exposed, Replay, Untrusted, reason};
use prost::Message;

use crate::error::BridgeError;
use crate::proto::session_store::field_selector::Kind as SelectorKind;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::write_request::op::Kind as OpKind;
use crate::proto::session_store::write_request::{BlobWrite, Op};
use crate::proto::session_store::{BlobField, FieldSelector};
use crate::proto::state::SessionMetadata;

use super::Ctx;
use super::aead;
use super::core::{ReadField, WriteField, unwrap_scalar};

/// Read marker: session metadata blob. Output is
/// `Untrusted<Option<SessionMetadata>, (AuthZ, Replay)>`. AuthN is
/// already cleared inside `decode` by the AEAD authentication step
/// — bytes are guaranteed to be ours and bound to this session_id.
/// AuthZ remains open (caller checks tenant_id); Replay remains
/// open (host may have served a stale snapshot).
pub struct Metadata;

/// Write marker: replace session metadata with a freshly-encoded
/// blob. AEAD-seal under TEE_key happens inside `build_op`.
pub struct SetMetadata<'a>(pub &'a SessionMetadata);

impl ReadField for Metadata {
    type Output = Untrusted<Option<SessionMetadata>, (AuthZ, Replay)>;

    fn selector(&self) -> FieldSelector {
        FieldSelector {
            kind: Some(SelectorKind::Blob(BlobField::Metadata as i32)),
        }
    }

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let scope_reason = reason!(r#"
AEAD-decrypt under TEE_key with session_id as AAD succeeded —
bytes are ours, bound to this session (AuthN cleared). AuthZ
open: caller must check `tenant_id` matches the authenticated
principal. Replay open: host might serve a pre-/init snapshot;
bound by version-CAS at next write.
        "#);
        let Some(b) = unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None, scope_reason));
        };
        let plaintext = aead::open(&b, ctx.tee_key, ctx.aad())?;
        Ok(Untrusted::new(
            Some(SessionMetadata::decode(plaintext.as_slice())?),
            scope_reason,
        ))
    }
}

impl WriteField for SetMetadata<'_> {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op>, BridgeError> {
        let plaintext = self.0.encode_to_vec();
        let value = aead::seal(&plaintext, ctx.tee_key, ctx.aad())?;
        // AEAD ciphertext under the TEE-side per-instance key, AAD =
        // session_id. Host cannot decrypt; cross-session copies fail
        // authentication (AAD mismatch) before any plaintext is
        // recovered.
        Ok(Exposed::expose(Op {
            kind: Some(OpKind::Blob(BlobWrite {
                field: BlobField::Metadata as i32,
                value,
            })),
        }))
    }
}
