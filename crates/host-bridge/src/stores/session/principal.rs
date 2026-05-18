//! `PRINCIPAL` session field. Plaintext string (host-visible) recording
//! which tenant created the session. The host uses it for its own
//! concerns (revocation, rate-limit, billing indexing); the TEE
//! emphatically does NOT use it for authorization — that's
//! `client_session_token`'s job (see docs/security-model.md).
//!
//! Stored plaintext because host needs to query by tenant ("list all
//! sessions for tenant X", "revoke all sessions when API key Y is
//! killed") without involving the TEE.
//!
//! Write-only from TEE's perspective: we expose `SetPrincipal` for the
//! `POST /sessions` flow to populate the plaintext field, but there's
//! no `ReadField` marker for it — TEE never reads principal back.
//! Host accesses the field directly in Redis when servicing
//! tenant-scoped admin queries.

use enclavid_untrusted::Exposed;

use crate::error::BridgeError;
use crate::proto::session_store::BlobField;
use crate::proto::session_store::write_request::op::Kind as OpKind;
use crate::proto::session_store::write_request::{BlobWrite, Op};

use super::Ctx;
use super::core::WriteField;

/// Write marker: set principal. Plaintext, no encryption — host needs
/// it queryable.
pub struct SetPrincipal<'a>(pub &'a str);

impl<'a> WriteField for SetPrincipal<'a> {
    fn build_op(&self, _ctx: &Ctx<'_>) -> Result<Exposed<Op>, BridgeError> {
        // Plaintext UTF-8 bytes. No confidentiality requirement here:
        // host needs to index by tenant. The lifecycle equivalent is
        // STATUS — both fields host-visible by design.
        Ok(Exposed::expose(Op {
            kind: Some(OpKind::Blob(BlobWrite {
                field: BlobField::Principal as i32,
                value: self.0.as_bytes().to_vec(),
            })),
        }))
    }
}
