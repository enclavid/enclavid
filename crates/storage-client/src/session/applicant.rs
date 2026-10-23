//! Everything one applicant brought to a session — its state, its media, its
//! disclosures — dropped as one op, the `/reset` path. A write field like the
//! rest, so it commits under the version the caller read the session at.

use storage_rpc::{Ops, ResetOp};

use crate::boundary::Storage;
use crate::error::StoreError;

use super::Ctx;
use super::core::WriteField;

/// Write marker: drop the session's state, media and disclosures, keeping its
/// metadata and version, so the next `/connect` can claim it afresh. [`Storage`]
/// answers everything about the op it adds.
pub struct DropApplicantData;

impl WriteField for DropApplicantData {
    fn add_to(&self, ops: &mut Ops<Storage>, _ctx: &Ctx<'_>) -> Result<(), StoreError> {
        ops.reset(Storage::expose(ResetOp));
        Ok(())
    }
}
