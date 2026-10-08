//! Everything one applicant brought to a session — its state, its media, its
//! disclosures — dropped as one op, the `/reset` path. A write field like the
//! rest, so it commits under the version the caller read the session at.

use hatch_protocol::Op;

use enclavid_boundary::reason;
use enclavid_boundary::{AuthN, AuthZ, Covert, Exposed};

use crate::boundary;
use crate::error::BridgeError;

use super::Ctx;
use super::core::WriteField;

/// Write marker: drop the session's state, media and disclosures, keeping its
/// metadata and version, so the next `/connect` can claim it afresh.
pub struct DropApplicantData;

impl WriteField for DropApplicantData {
    fn build_op(&self, _ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, BridgeError> {
        Ok(boundary::outbound::to_untrusted(Op::Reset)
            .vouch_unchecked::<AuthN, _>(reason!("carries no bytes, only that the data goes"))
            .vouch_unchecked::<AuthZ, _>(reason!("drops this session's own data"))
            .vouch_unchecked::<Covert, _>(reason!("one fixed op, nothing the TEE fills in")))
    }
}
