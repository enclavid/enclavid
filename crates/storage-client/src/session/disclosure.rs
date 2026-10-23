//! `DISCLOSURE` session field. An UNORDERED SET of age-encrypted
//! consent records produced by the engine during a policy run. The
//! TEE-side never decrypts — entries are forwarded to the client as
//! opaque bytes (encryption is to the client's `client_disclosure_pubkey`,
//! engine-side, before the entry is staged for commit). Order is neither
//! preserved by the store nor relied upon — the api commits to the set.

use storage_rpc::{DisclosureOp, Fields, Ops, Slot};

use crate::boundary::Storage;
use crate::error::StoreError;
use enclavid_boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};

use super::Ctx;
use super::core::{ReadField, WriteField, list};

/// Read marker: per-session disclosure set. Output is
/// `Untrusted<Vec<Vec<u8>>, (AuthN, AuthZ, Replay), Storage>` — storage-client
/// does no decryption work (items are sealed for the consumer), so
/// **no** concern gets closed at this layer. The caller is expected
/// to verify the per-session disclosure SET COMMITMENT (closes AuthN +
/// Replay) and peel AuthZ with the rationale that fits its release
/// channel (e.g. "TEE forwards opaque bytes; the consumer is the
/// content consumer, not the TEE").
pub struct Disclosure;

/// Pending append to the per-session disclosure list. Produced by the
/// engine during a policy run and merged into the next `write` call
/// so the state update + disclosure entries commit atomically.
///
/// Payload is a [`DisclosureOp`] answered in full at [`Storage`] — built in
/// `api::applicant::persister`, which holds the consumer's key. The bytes are
/// already age-sealed to the consumer's `client_disclosure_pubkey`, with field
/// order HKDF'd-shuffle'd inside the envelope; storage-client does no further
/// sealing work and only adds it to the write.
pub struct AppendDisclosure(pub Exposed<DisclosureOp, (), Storage>);

impl ReadField for Disclosure {
    type Output = Untrusted<Vec<Vec<u8>>, (AuthN, AuthZ, Replay), Storage>;

    fn select(&self, fields: &mut Fields<Storage>) {
        fields.disclosures();
    }

    fn decode(
        self,
        slot: Untrusted<Slot, (AuthN, AuthZ, Replay), Storage>,
        _ctx: &Ctx<'_>,
    ) -> Result<Self::Output, StoreError> {
        // No work-backed trust step lives here — items are age-sealed
        // for the consumer (not the TEE), so storage-client has neither
        // the key nor the structural check to close any concern.
        // Caller verifies the disclosure-hash chain (AuthN + Replay)
        // and peels AuthZ with channel-specific rationale.
        list(slot)
    }
}

impl WriteField for AppendDisclosure {
    fn add_to(&self, ops: &mut Ops<Storage>, _ctx: &Ctx<'_>) -> Result<(), StoreError> {
        // Answered in full by `api::applicant::persister` (Covert → HKDF'd
        // shuffle, AuthZ → the applicant accepted this screen, AuthN → age-seal
        // to client disclosure pubkey). Clone because `&self` forbids moving it
        // out; a padded entry is a few KiB.
        ops.disclosure(self.0.clone());
        Ok(())
    }
}
