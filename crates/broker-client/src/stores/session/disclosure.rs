//! `DISCLOSURE` session field. Append-only list of age-encrypted
//! consent records produced by the engine during a policy run. The
//! TEE-side never decrypts — entries are forwarded to the client as
//! opaque bytes (encryption is to the client's `client_disclosure_pubkey`,
//! engine-side, before the entry is staged for commit).

use broker_protocol::{FieldSelector, ListAppend, ListField, Op, Slot};

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::error::BridgeError;
use crate::reason;

use super::Ctx;
use super::core::{ReadField, WriteField, unwrap_list};

/// Read marker: per-session disclosure list. Output is
/// `Untrusted<Vec<Vec<u8>>, (AuthN, AuthZ, Replay)>` — broker-client
/// does no decryption work (items are sealed for the consumer), so
/// **no** concern gets closed at this layer. The caller is expected
/// to verify the per-session disclosure-hash chain (closes AuthN +
/// Replay) and peel AuthZ with the rationale that fits its release
/// channel (e.g. "TEE forwards opaque bytes; the consumer is the
/// content consumer, not the TEE").
pub struct Disclosure;

/// Pending append to the per-session disclosure list. Produced by the
/// engine during a policy run and merged into the next `write` call
/// so the state update + disclosure entries commit atomically.
///
/// Payload is `Exposed<Vec<u8>, ()>` — fully vouched at the api crate
/// boundary (see `api::boundary::outbound::disclosure_envelope` and
/// the vouch chain in the api persister). The bytes are already
/// age-sealed to the consumer's `client_disclosure_pubkey`, with
/// field order HKDF'd-shuffle'd inside the envelope; broker-client
/// does no further sealing work — `build_op` just rewraps as a typed
/// `ListAppend` op for the wire send.
pub struct AppendDisclosure(pub Exposed<Vec<u8>, ()>);

impl ReadField for Disclosure {
    type Output = Untrusted<Vec<Vec<u8>>, (AuthN, AuthZ, Replay)>;

    fn selector(&self) -> FieldSelector {
        FieldSelector::List(ListField::Disclosure)
    }

    fn decode(self, slot: Slot, _ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        // No work-backed trust step lives here — items are age-sealed
        // for the consumer (not the TEE), so broker-client has neither
        // the key nor the structural check to close any concern.
        // Caller verifies the disclosure-hash chain (AuthN + Replay)
        // and peels AuthZ with channel-specific rationale.
        Ok(boundary::inbound::from_host(unwrap_list(slot)?, reason!(r#"
Per-session disclosure list items from ListField::Disclosure.
Boundary entry (AuthN, AuthZ, Replay) all open: items are
age-sealed for the consumer; broker-client has no key and no
structural property to verify here, so every concern is left for
the caller — the disclosure-hash chain anchors AuthN + Replay, and
the release channel (e.g. `GET /sessions/:id/shared-data`)
contributes the AuthZ rationale.
            "#)))
    }
}

impl WriteField for AppendDisclosure {
    fn build_op(&self, _ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, BridgeError> {
        // Bytes arrived pre-vouched from `api::boundary::outbound::
        // disclosure_envelope` (Covert → HKDF'd shuffle, AuthZ →
        // consent-gate rationale, AuthN → age-seal to client
        // disclosure pubkey). Host-bridge does no further sealing
        // — just rewrap as a typed ListAppend op for the wire.
        // Clone because `&self` forbids moving the Exposed out;
        // disclosure entries are typically small (<1 KB).
        Ok(self.0.clone().map(|value| {
            Op::ListAppend(ListAppend {
                field: ListField::Disclosure,
                value,
            })
        }))
    }
}
