//! `DISCLOSURE` session field. Append-only list of age-encrypted
//! consent records produced by the engine during a policy run. The
//! TEE-side never decrypts — entries are forwarded to the client as
//! opaque bytes (encryption is to the client's `client_disclosure_pubkey`,
//! engine-side, before the entry is staged for commit).

use enclavid_untrusted::Exposed;

use crate::error::BridgeError;
use crate::proto::session_store::field_selector::Kind as SelectorKind;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::write_request::op::Kind as OpKind;
use crate::proto::session_store::write_request::{ListAppend, Op};
use crate::proto::session_store::{FieldSelector, ListField};

use super::Ctx;
use super::core::{ReadField, WriteField, unwrap_list};

/// Read marker: per-session disclosure list. Output is
/// `Vec<Vec<u8>>` — empty when the list has no entries (or has never
/// been written; the two are not distinguished).
pub struct Disclosure;

/// Pending append to the per-session disclosure list. Produced by the
/// engine during a policy run and merged into the next `write` call
/// so the state update + disclosure entries commit atomically.
///
/// Already-encrypted bytes (persister age-encrypts to client_pk
/// before wrapping). The host-bridge layer doesn't add another
/// envelope.
pub struct AppendDisclosure(pub Vec<u8>);

impl ReadField for Disclosure {
    type Output = Vec<Vec<u8>>;

    fn selector(&self) -> FieldSelector {
        FieldSelector {
            kind: Some(SelectorKind::List(ListField::Disclosure as i32)),
        }
    }

    fn decode(self, slot: Slot, _ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        unwrap_list(slot)
    }
}

impl WriteField for AppendDisclosure {
    fn build_op(&self, _ctx: &Ctx<'_>) -> Result<Exposed<Op>, BridgeError> {
        // Once the seal-to-`client_pk` step lands in the persister,
        // these bytes are hybrid public-key ciphertext keyed to the
        // platform consumer's disclosure recipient pubkey (provided
        // at session creation). Host cannot decrypt; only the
        // consumer's corresponding private key can open. Note: entry
        // COUNT and append timing per session ARE observable to the
        // host — confidentiality is on disclosure CONTENT, not on
        // the metadata fact "session X disclosed N items at time T".
        //
        // We clone the payload because `&self` doesn't allow moving
        // out of the marker; disclosure entries are typically small
        // (<1 KB) so the copy is negligible.
        Ok(Exposed::expose(Op {
            kind: Some(OpKind::ListAppend(ListAppend {
                field: ListField::Disclosure as i32,
                value: self.0.clone(),
            })),
        }))
    }
}
