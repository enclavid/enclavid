//! Client wrapper for the hatch `/authorize` endpoint.
//!
//! TEE forwards the raw HTTP `Authorization` header value plus the
//! intended operation; the hatch validates and returns the tenant
//! context. TEE never parses JWTs / certificates / etc. — the hatch is
//! the source of truth for client identity and RBAC.
//!
//! Trust model: the hatch can return arbitrary verdicts (e.g. claim a
//! token is valid when it isn't, or substitute a different principal).
//! The TEE has no independent crypto check on the verdict, so a
//! compromised hatch can mint fake sessions; bounded only by host-side
//! rate-limit + audit log. See architecture.md → Network Isolation.

use hatch_protocol::{AuthorizeRequest, AuthorizeResponse};
use hyper::StatusCode;

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};
use crate::error::BridgeError;
use crate::transport::HatchClient;

/// Principal identifier returned by the hatch. Opaque string from the
/// TEE's perspective — the hatch is authoritative on identity; the TEE
/// uses it as the per-credential key for cross-session boundary checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(pub String);

impl Principal {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Outcome of an authorization request. The whole verdict is the
/// hatch's word — substitution (Allowed→different principal) and
/// spurious denial (Allowed→Unauthenticated) are both observed-but-
/// not-trusted. A compromised hatch can mint fake sessions under any
/// principal; tracked at the rate-limit + audit-log layer. See
/// architecture.md → Network Isolation for the full analysis.
///
/// `Allowed` carries an optional principal (authenticated identity) —
/// the hatch's attribution data, opaque to TEE. None is valid: not
/// every auth scheme produces a principal. TEE forwards the optional
/// value to host-side storage if present.
#[derive(Debug)]
pub enum AuthVerdict {
    /// Hatch claims the credential is valid. Carries the authenticated
    /// principal as attribution data for host-side bookkeeping
    /// (rate-limit/audit); TEE itself doesn't act on it.
    Allowed { principal: Option<Principal> },
    /// Bad credential: missing, malformed, expired, or otherwise
    /// rejected by the hatch's identity provider (HTTP 401).
    Unauthenticated,
    /// Credential is valid but not permitted for the requested
    /// operation, or has no org binding (HTTP 403).
    PermissionDenied,
}

/// Client for the hatch `/authorize` endpoint over the shared hatch
/// connection.
#[derive(Clone)]
pub struct AuthClient {
    hatch: HatchClient,
}

impl AuthClient {
    pub fn new(hatch: HatchClient) -> Self {
        Self { hatch }
    }

    /// Authorize an HTTP request. The auth verdict (allowed / denied
    /// with reason) is the normal return value; `BridgeError` is
    /// reserved for transport-level failures (channel down, body
    /// parse, etc.) — symmetric with the rest of the bridge API.
    pub async fn authorize(
        &self,
        req: Exposed<AuthorizeRequest>,
    ) -> Result<Untrusted<AuthVerdict, (AuthN, AuthZ, Replay)>, BridgeError> {
        // The request arrives vouched by the api producer — the endpoint
        // that received the client's credential. Releasing the client's
        // own credential to its validating hatch is the producer's call,
        // not ours to self-approve; we just release it.
        let bytes = hatch_protocol::encode(&req.into_inner())?;
        let resp = self.hatch.post("/authorize", bytes).await?;

        let verdict = match resp.status {
            StatusCode::OK => {
                let r: AuthorizeResponse = hatch_protocol::decode(&resp.body)?;
                let principal = r.principal.filter(|s| !s.is_empty()).map(Principal);
                AuthVerdict::Allowed { principal }
            }
            StatusCode::UNAUTHORIZED => AuthVerdict::Unauthenticated,
            StatusCode::FORBIDDEN => AuthVerdict::PermissionDenied,
            s => return Err(BridgeError::Transport(format!("authorize: status {s}"))),
        };

        Ok(boundary::inbound::from_untrusted(verdict))
    }
}
