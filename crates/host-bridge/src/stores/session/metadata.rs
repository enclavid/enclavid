//! `METADATA` session field. Encrypted blob carrying per-session
//! configuration (workspace_id, policy ref, ephemeral pubkey, d_*,
//! client disclosure pubkey, input claims, external_ref). AEAD'd with
//! `TEE_key`; AAD = session_id binds it to the session that wrote it.

use enclavid_untrusted::Exposed;
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
/// `Option<SessionMetadata>`. AEAD-decrypts under TEE_key before
/// prost-decoding.
pub struct Metadata;

/// Write marker: replace session metadata with a freshly-encoded
/// blob. AEAD-seal under TEE_key happens inside `build_op`.
pub struct SetMetadata<'a>(pub &'a SessionMetadata);

impl ReadField for Metadata {
    type Output = Option<SessionMetadata>;

    fn selector(&self) -> FieldSelector {
        FieldSelector {
            kind: Some(SelectorKind::Blob(BlobField::Metadata as i32)),
        }
    }

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let Some(b) = unwrap_scalar(slot)? else { return Ok(None) };
        let plaintext = aead::open(&b, ctx.tee_key, ctx.aad())?;
        Ok(Some(SessionMetadata::decode(plaintext.as_slice())?))
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
