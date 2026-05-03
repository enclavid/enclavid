//! `STATUS` session field. Plaintext byte (host-visible — used for
//! TTL and cleanup logic). No crypto on either side; readers map the
//! single byte to `SessionStatus` enum, writers emit the byte.

use enclavid_untrusted::Exposed;

use crate::error::BridgeError;
use crate::proto::session_store::write_request::Op;
use crate::proto::session_store::{BlobField, FieldSelector};
use crate::proto::session_store::read_response::Slot;
use crate::proto::state::SessionStatus;

use super::Ctx;
use super::core::{ReadField, WriteField, blob_op, blob_selector, unwrap_scalar};

/// Read marker: session status. Output is `Option<SessionStatus>` —
/// `None` when the host has no value (not yet written or expired).
pub struct Status;

/// Write marker: replace session status with a fresh enum value.
pub struct SetStatus(pub SessionStatus);

impl ReadField for Status {
    type Output = Option<SessionStatus>;

    fn selector(&self) -> FieldSelector {
        blob_selector(BlobField::Status)
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
        Ok(blob_op(BlobField::Status, vec![self.0 as i32 as u8]))
    }
}
