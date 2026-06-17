//! `METADATA` session field. Encrypted blob carrying per-session
//! configuration (principal, policy ref, ephemeral pubkey, d_*,
//! client disclosure pubkey, input claims, client_ref). AEAD'd with
//! `tee_seal_key`; AAD = session_id binds it to the session that wrote it.

use broker_protocol::{BlobField, BlobWrite, FieldSelector, Op, Slot};

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::domain::{self, SessionMetadata};
use crate::error::BridgeError;

use enclavid_crypto::aead;

use super::Ctx;
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
/// pre-vouches AuthZ + Covert at the construction site; broker-client
/// closes AuthN via AEAD-seal under `tee_seal_key`.
pub struct SetMetadata<'a>(pub Exposed<&'a SessionMetadata, (AuthN,)>);

impl ReadField for Metadata {
    type Output = Untrusted<Option<SessionMetadata>, (AuthZ, Replay)>;

    fn selector(&self) -> FieldSelector {
        FieldSelector::Blob(BlobField::Metadata)
    }

    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let Some(b) = unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None));
        };
        let decoded: Untrusted<SessionMetadata, (AuthZ, Replay)> =
            boundary::inbound::from_untrusted(b)
                .trust::<AuthN, _, _, _, _>(|raw| {
                    let plaintext = aead::open(&raw, ctx.tee_seal_key, ctx.aad())?;
                    domain::decode::<SessionMetadata>(&plaintext)
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
                aead::seal(&domain::encode(m)?, ctx.tee_seal_key, ctx.aad()).map_err(Into::into)
            },
        )?;
        Ok(sealed.map(|value| {
            Op::Blob(BlobWrite {
                field: BlobField::Metadata,
                value,
            })
        }))
    }
}
