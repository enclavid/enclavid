//! `DISCLOSURE` session field. Append-only list of age-encrypted
//! consent records produced by the engine during a policy run. The
//! TEE-side never decrypts — entries are forwarded to the client as
//! opaque bytes (encryption is to the client's `client_disclosure_pubkey`,
//! engine-side, before the entry is staged for commit).

use crate::error::BridgeError;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::write_request::Op;
use crate::proto::session_store::{FieldSelector, ListField};

use super::Ctx;
use super::core::{ReadField, WriteField, list_append_op, list_selector, unwrap_list};

/// Read marker: per-session disclosure list. Output is
/// `Vec<Vec<u8>>` — empty when the list has no entries (or has never
/// been written; the two are not distinguished).
pub struct Disclosure;

/// Pending append to the per-session disclosure list. Produced by the
/// engine during a policy run and merged into the next `write` call
/// so the state update + disclosure entries commit atomically.
///
/// Already-encrypted bytes (engine age-encrypts to client_pk before
/// pushing). The host-bridge layer doesn't add another envelope.
pub struct AppendDisclosure(pub Vec<u8>);

impl ReadField for Disclosure {
    type Output = Vec<Vec<u8>>;

    fn selector(&self) -> FieldSelector {
        list_selector(ListField::Disclosure)
    }

    fn decode(self, slot: Slot, _ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        unwrap_list(slot)
    }
}

impl WriteField for AppendDisclosure {
    fn build_op(&self, _ctx: &Ctx<'_>) -> Result<Op, BridgeError> {
        // Engine pre-encrypts to client_pk; we ship opaque bytes. We
        // clone the payload because `&self` doesn't allow moving out
        // of the marker; disclosure entries are typically small
        // (<1 KB) so the copy is negligible.
        Ok(list_append_op(ListField::Disclosure, self.0.clone()))
    }
}
