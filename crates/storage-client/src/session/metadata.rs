//! `METADATA` session field. Encrypted blob carrying per-session
//! configuration (principal, policy ref, ephemeral pubkey, d_*,
//! client disclosure pubkey, input claims, client_ref). AEAD'd with
//! `tee_seal_key`, bound (AAD) to the field and to the session that wrote it.

use session_types::SessionMetadata;
use storage_rpc::{Fields, MetadataOp, Ops, Slot};

use crate::boundary::Storage;
use crate::error::StoreError;
use enclavid_boundary::{AuthN, AuthZ, ExposedBuilder, Replay, Untrusted};

use enclavid_crypto::aead;

use super::Ctx;
use super::core::{ReadField, WriteField, scalar};

/// What a metadata seal is labelled with, apart from every other field's.
const METADATA_AAD: &[u8] = b"enclavid.metadata.v1";

/// The AAD a session's metadata is sealed under: the field, then the session.
fn aad(session_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(METADATA_AAD.len() + session_id.len());
    aad.extend_from_slice(METADATA_AAD);
    aad.extend_from_slice(session_id.as_bytes());
    aad
}

/// Read marker: session metadata blob. Output is
/// `Untrusted<Option<SessionMetadata>, (AuthZ, Replay), Storage>`. The slot
/// arrives with `(AuthN, AuthZ, Replay)` open; AEAD-open under
/// `tee_seal_key` closes AuthN (real cryptographic work). AuthZ and
/// Replay remain open for the caller — the principal predicate and
/// CAS-bound replay reasoning live in the calling endpoint.
pub struct Metadata;

/// Write marker: replace session metadata with a freshly-encoded blob. Payload
/// is a [`MetadataOp`] being built from the metadata, with `AuthN` alone open:
/// [`Storage`] answers `AuthZ` for every metadata op, the caller `Covert` for
/// its own write, and storage-client `AuthN` with the AEAD seal under
/// `tee_seal_key` that builds the op.
pub struct SetMetadata<'a>(pub ExposedBuilder<&'a SessionMetadata, MetadataOp, (AuthN,), Storage>);

impl ReadField for Metadata {
    type Output = Untrusted<Option<SessionMetadata>, (AuthZ, Replay), Storage>;

    fn select(&self, fields: &mut Fields<Storage>) {
        fields.metadata();
    }

    fn decode(
        self,
        slot: Untrusted<Slot, (AuthN, AuthZ, Replay), Storage>,
        ctx: &Ctx<'_>,
    ) -> Result<Self::Output, StoreError> {
        // An absent field is a record nobody created, or one the host removed:
        // either way there is no session to act for, and every route answers
        // as for none.
        scalar(slot)?.trust_with(AuthN::Verified, |sealed| -> Result<_, StoreError> {
            sealed
                .map(|raw| {
                    let plaintext = aead::open(&raw, ctx.tee_seal_key, &aad(ctx.session_id))?;
                    Ok(session_types::decode::<SessionMetadata>(&plaintext)?)
                })
                .transpose()
        })
    }
}

impl WriteField for SetMetadata<'_> {
    fn add_to(&self, ops: &mut Ops<Storage>, ctx: &Ctx<'_>) -> Result<(), StoreError> {
        // The seal this side owns the key for answers AuthN, and builds the op.
        let op = self
            .0
            .clone()
            .vouch_with(AuthN::Verified, |m| -> Result<_, StoreError> {
                let encoded = session_types::encode(m)?;
                let sealed = aead::seal(&encoded, ctx.tee_seal_key, &aad(ctx.session_id))?;
                Ok(MetadataOp(sealed))
            })?
            .build();
        ops.metadata(op);
        Ok(())
    }
}
