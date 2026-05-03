//! `STATUS` session field. Plaintext byte (host-visible — used for
//! TTL and cleanup logic). No crypto on either side; readers map the
//! single byte to `SessionStatus` enum, writers emit the byte.

use enclavid_untrusted::Exposed;

use crate::error::BridgeError;
use crate::proto::session_store::field_selector::Kind as SelectorKind;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::write_request::op::Kind as OpKind;
use crate::proto::session_store::write_request::{BlobWrite, Op};
use crate::proto::session_store::{BlobField, FieldSelector};
use crate::proto::state::SessionStatus;

use super::Ctx;
use super::core::{ReadField, WriteField, unwrap_scalar};

/// Read marker: session status. Output is `Option<SessionStatus>` —
/// `None` when the host has no value (not yet written or expired).
pub struct Status;

/// Write marker: replace session status with a fresh enum value.
pub struct SetStatus(pub SessionStatus);

impl ReadField for Status {
    type Output = Option<SessionStatus>;

    fn selector(&self) -> FieldSelector {
        FieldSelector {
            kind: Some(SelectorKind::Blob(BlobField::Status as i32)),
        }
    }

    fn decode(self, slot: Slot, _ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError> {
        let Some(b) = unwrap_scalar(slot)? else { return Ok(None) };
        let byte = *b
            .first()
            .ok_or_else(|| BridgeError::Transport("empty status field".to_string()))?;
        let status = SessionStatus::try_from(byte as i32).map_err(|_| {
            BridgeError::Transport(format!("invalid status byte: {byte}"))
        })?;
        Ok(Some(status))
    }
}

impl WriteField for SetStatus {
    fn build_op(&self, _ctx: &Ctx<'_>) -> Result<Exposed<Op>, BridgeError> {
        // Single plaintext byte by design — the host needs it for
        // session lifecycle management (TTL, cleanup). Nothing
        // applicant-specific lands here, only the lifecycle marker
        // (PendingInit / Running / Completed / Failed / Expired).
        // Intentionally not confidential.
        Ok(Exposed::expose(Op {
            kind: Some(OpKind::Blob(BlobWrite {
                field: BlobField::Status as i32,
                value: vec![self.0 as i32 as u8],
            })),
        }))
    }
}
