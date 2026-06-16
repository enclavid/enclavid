//! Client wrapper for the broker `/authorize` endpoint.
//!
//! TEE forwards the raw HTTP `Authorization` header value plus the
//! intended operation; the broker validates and returns the tenant
//! context. TEE never parses JWTs / certificates / etc. — the broker is
//! the source of truth for client identity and RBAC.
//!
//! Trust model: the broker can return arbitrary verdicts (e.g. claim a
//! token is valid when it isn't, or substitute a different principal).
//! The TEE has no independent crypto check on the verdict, so a
//! compromised broker can mint fake sessions; bounded only by host-side
//! rate-limit + audit log. See architecture.md → Network Isolation.

use broker_protocol::{AuthorizeRequest, AuthorizeResponse, ClientOperation};
use hyper::StatusCode;

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Covert, Replay, Untrusted};
use crate::error::BridgeError;
use crate::reason;
use crate::transport::BrokerClient;

/// Principal identifier returned by the broker. Opaque string from the
/// TEE's perspective — the broker is authoritative on identity; the TEE
/// uses it as the per-credential key for cross-session boundary checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(pub String);

impl Principal {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Outcome of an authorization request. The whole verdict is the
/// broker's word — substitution (Allowed→different principal) and
/// spurious denial (Allowed→Unauthenticated) are both observed-but-
/// not-trusted. A compromised broker can mint fake sessions under any
/// principal; tracked at the rate-limit + audit-log layer. See
/// architecture.md → Network Isolation for the full analysis.
///
/// `Allowed` carries an optional principal (authenticated identity) —
/// the broker's attribution data, opaque to TEE. None is valid: not
/// every auth scheme produces a principal. TEE forwards the optional
/// value to host-side storage if present.
#[derive(Debug)]
pub enum AuthVerdict {
    /// Broker claims the credential is valid. Carries the authenticated
    /// principal as attribution data for host-side bookkeeping
    /// (rate-limit/audit); TEE itself doesn't act on it.
    Allowed { principal: Option<Principal> },
    /// Bad credential: missing, malformed, expired, or otherwise
    /// rejected by the broker's identity provider (HTTP 401).
    Unauthenticated,
    /// Credential is valid but not permitted for the requested
    /// operation, or has no org binding (HTTP 403).
    PermissionDenied,
}

/// Client for the broker `/authorize` endpoint over the shared broker
/// connection.
#[derive(Clone)]
pub struct AuthClient {
    broker: BrokerClient,
}

impl AuthClient {
    pub fn new(broker: BrokerClient) -> Self {
        Self { broker }
    }

    /// Authorize an HTTP request. The auth verdict (allowed / denied
    /// with reason) is the normal return value; `BridgeError` is
    /// reserved for transport-level failures (channel down, body
    /// parse, etc.) — symmetric with the rest of the bridge API.
    pub async fn authorize(
        &self,
        authorization_header: &str,
        operation: ClientOperation,
    ) -> Result<Untrusted<AuthVerdict, (AuthN, AuthZ, Replay)>, BridgeError> {
        let req = AuthorizeRequest {
            authorization_header: authorization_header.to_string(),
            operation,
        };
        // Egress gate. The body carries the client's own credential —
        // a by-design courier release to the broker that validates it,
        // not a TEE secret. Vouch each concern with that rationale.
        let req = boundary::outbound::to_host(
            req,
            reason!("AuthorizeRequest → broker POST /authorize"),
        )
        .vouch_unchecked::<AuthN, _>(reason!(
            "authorization_header is the CLIENT's own credential, released by design \
             to the broker that validates it — not a TEE-held secret"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!(
            "forwarding the credential to its validator IS the operation; no further \
             release gate sits on top"
        ))
        .vouch_unchecked::<Covert, _>(reason!(
            "header is client-supplied and the operation is a fixed enum — no \
             policy-controlled bandwidth"
        ));
        let bytes = broker_protocol::encode(&req.into_inner())?;
        let resp = self.broker.post("/authorize", bytes).await?;

        let verdict = match resp.status {
            StatusCode::OK => {
                let r: AuthorizeResponse = broker_protocol::decode(&resp.body)?;
                let principal = r.principal.filter(|s| !s.is_empty()).map(Principal);
                AuthVerdict::Allowed { principal }
            }
            StatusCode::UNAUTHORIZED => AuthVerdict::Unauthenticated,
            StatusCode::FORBIDDEN => AuthVerdict::PermissionDenied,
            s => return Err(BridgeError::Transport(format!("authorize: status {s}"))),
        };

        Ok(boundary::inbound::from_host(verdict, reason!(r#"
AuthVerdict from broker /authorize response. Verdict comes straight
from the broker's own claim (TEE never parses tokens). No
work-backed close at this layer — caller peels with rationale (the
typical one is "verdict IS the authz answer, nothing further to
check on top").
        "#)))
    }
}
