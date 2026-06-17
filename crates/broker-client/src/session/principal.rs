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

use broker_protocol::{BlobField, BlobWrite, Op};

use crate::boundary::Exposed;
use crate::error::BridgeError;

use super::Ctx;
use super::core::WriteField;

/// Write marker: set principal. Payload is `Exposed<&str, ()>` —
/// fully pre-vouched at the construction site (api `POST /sessions`
/// handler). Host-bridge does **no** crypto work; just emits a
/// `BlobWrite` op carrying the plaintext bytes. All three outbound
/// concerns are documented at the call site with rationale tied to
/// the host-attribution use case.
pub struct SetPrincipal<'a>(pub Exposed<&'a str, ()>);

impl<'a> WriteField for SetPrincipal<'a> {
    fn build_op(&self, _ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, BridgeError> {
        // Fully pre-vouched. No sealing, no concern decisions — just
        // rewrap the plaintext bytes as a typed `Op` for the wire.
        Ok(self.0.clone().map(|s| {
            Op::Blob(BlobWrite {
                field: BlobField::Principal,
                value: s.as_bytes().to_vec(),
            })
        }))
    }
}
