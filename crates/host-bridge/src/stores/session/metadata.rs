//! `METADATA` session field. Encrypted blob carrying per-session
//! configuration (principal, policy ref, ephemeral pubkey, d_*,
//! client disclosure pubkey, input claims, client_ref). AEAD'd with
//! `tee_seal_key`; AAD = session_id binds it to the session that wrote it.

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
use crate::proto::state::SessionMetadata;

use super::Ctx;
use super::aead;
use super::core::{ReadField, WriteField, unwrap_scalar};

/// Read marker: session metadata blob. Output is
/// `Untrusted<Option<SessionMetadata>, (AuthZ, Replay)>`. Boundary
/// entry hands us `(AuthN, AuthZ, Replay)` open; AEAD-open under
/// `tee_seal_key` closes AuthN (real cryptographic work). AuthZ and
/// Replay remain open for the caller — the principal predicate and
/// CAS-bound replay reasoning live in the calling endpoint.
pub struct Metadata;

/// Write marker: replace session metadata with a freshly-encoded
/// blob. Payload is `Exposed<&SessionMetadata, (AuthN,)>` — caller
/// pre-vouches AuthZ + Covert at the construction site; host-bridge
/// closes AuthN via AEAD-seal under `tee_seal_key`.
pub struct SetMetadata<'a>(pub Exposed<&'a SessionMetadata, (AuthN,)>);

impl ReadField for Metadata {
    type Output = Untrusted<Option<SessionMetadata>, (AuthZ, Replay)>;

    fn selector(&self) -> FieldSelector {
        FieldSelector {
            kind: Some(SelectorKind::Blob(BlobField::Metadata as i32)),
        }
    }

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let Some(b) = unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None, reason!(
                "absent metadata blob — session was never created or \
                 was deleted"
            )));
        };
        let decoded: Untrusted<SessionMetadata, (AuthZ, Replay)> =
            boundary::inbound::from_host(b, reason!(r#"
Raw bytes claimed-as-SessionMetadata blob from BlobField::Metadata
slot. Boundary entry (AuthN, AuthZ, Replay) all open: AuthN closed
below by AEAD-open under tee_seal_key (real cryptographic work);
AuthZ and Replay left for the caller — the principal predicate (is
the connecting credential's identity equal to the decrypted
metadata.client?) and the CAS-bound replay reasoning live in the
calling endpoint.
            "#))
                .trust::<AuthN, _, _, _, _>(|raw| {
                    let plaintext = aead::open(&raw, ctx.tee_seal_key, ctx.aad())?;
                    SessionMetadata::decode(plaintext.as_slice()).map_err(BridgeError::from)
                })?;
        Ok(decoded.map(Some))
    }
}

impl WriteField for SetMetadata<'_> {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, BridgeError> {
        // AuthZ + Covert pre-vouched at the construction site.
        // Host-bridge closes AuthN with the cryptographic work it
        // owns the key for (tee_seal_key + session_id AAD).
        let sealed = self.0.clone().vouch::<AuthN, _, _, _, _>(
            |m| -> Result<Vec<u8>, BridgeError> {
                aead::seal(&m.encode_to_vec(), ctx.tee_seal_key, ctx.aad())
            },
        )?;
        Ok(sealed.map(|value| Op {
            kind: Some(OpKind::Blob(BlobWrite {
                field: BlobField::Metadata as i32,
                value,
            })),
        }))
    }
}
