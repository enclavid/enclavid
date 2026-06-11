//! `STATUS` session field. Plaintext byte (host-visible — used for
//! TTL and cleanup logic). No crypto on either side; readers map the
//! single byte to `SessionStatus` enum, writers emit the byte.

use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::reason;

use crate::boundary;
use crate::error::BridgeError;
use crate::proto::session_store::field_selector::Kind as SelectorKind;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::write_request::op::Kind as OpKind;
use crate::proto::session_store::write_request::{BlobWrite, Op};
use crate::proto::session_store::{BlobField, FieldSelector};
use crate::proto::state::SessionStatus;

use super::Ctx;
use super::core::{ReadField, WriteField, unwrap_scalar};

/// Read marker: session status. Output is
/// `Untrusted<Option<SessionStatus>, (AuthN, AuthZ, Replay)>` —
/// host-bridge does **no** concern-closing work. The byte's value is
/// plaintext and host-supplied; its authenticity is unverifiable at
/// this layer (host can return any valid enum discriminant), so AuthN
/// stays open. The `SessionStatus::try_from` step inside `decode` is
/// a format-shape check (filters host garbage), not an AuthN gate.
/// Caller peels with channel-specific rationale (typical: "by-design
/// observable host hint; no security gate hangs on routing/UX
/// hint").
pub struct Status;

/// Write marker: replace session status with a fresh enum value.
/// Payload is `Exposed<SessionStatus, ()>` — fully pre-vouched at
/// the construction site (api handler emitting Running on /create,
/// persister emitting Completed on finalize). Host-bridge does no
/// concern decisions; just emits a `BlobWrite` op carrying the
/// single byte.
pub struct SetStatus(pub Exposed<SessionStatus, ()>);

impl ReadField for Status {
    type Output = Untrusted<Option<SessionStatus>, (AuthN, AuthZ, Replay)>;

    fn selector(&self) -> FieldSelector {
        FieldSelector {
            kind: Some(SelectorKind::Blob(BlobField::Status as i32)),
        }
    }

    fn decode(self, slot: Slot, _ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let Some(b) = unwrap_scalar(slot)? else {
            return Ok(Untrusted::new(None, reason!(
                "absent status byte — session record missing"
            )));
        };
        let byte = *b
            .first()
            .ok_or_else(|| BridgeError::Transport("empty status field".to_string()))?;
        // Format-shape check happens BEFORE wrapping — filters host
        // garbage (values 5..=255 are invalid discriminants) so we
        // never wrap an undefined enum value. This is NOT an AuthN
        // gate: a malicious host can still return any valid
        // discriminant; the byte's authenticity is unverifiable for
        // plaintext at this layer.
        let status = SessionStatus::try_from(byte as i32)
            .map_err(|_| BridgeError::Transport(format!("invalid status byte: {byte}")))?;
        let wrapped = boundary::inbound::from_host(status, reason!(r#"
SessionStatus byte from BlobField::Status, post-format-validation.
Boundary entry (AuthN, AuthZ, Replay) all open: host plaintext
means the value's authenticity is unverifiable here (host can lie
within the valid discriminant range); AuthZ + Replay also caller
concerns. The format-shape gate above is NOT an AuthN close.
            "#));
        Ok(wrapped.map(Some))
    }
}

impl WriteField for SetStatus {
    fn build_op(&self, _ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, BridgeError> {
        // Fully pre-vouched at the construction site. Just emit the
        // wire op.
        Ok(self.0.clone().map(|s| Op {
            kind: Some(OpKind::Blob(BlobWrite {
                field: BlobField::Status as i32,
                value: vec![s as i32 as u8],
            })),
        }))
    }
}

