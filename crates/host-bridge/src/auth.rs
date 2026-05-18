//! Client wrapper for the host-side `Auth` gRPC service.
//!
//! TEE forwards the raw HTTP `Authorization` header value plus the
//! intended operation, host validates and returns the tenant context.
//! TEE never parses JWTs / certificates / etc. — host is the source of
//! truth for client identity and RBAC.
//!
//! Trust model: host can return arbitrary verdicts (e.g. claim a token
//! is valid when it isn't, or substitute a different principal).
//! client_policy_key backstop in session creation prevents this from escalating
//! to applicant-data leak. See proto/auth.proto and architecture.md →
//! Network Isolation for the full analysis.

use enclavid_untrusted::{AuthN, Replay, Untrusted, reason};
use tonic::Code;
use tonic::transport::Channel;

use crate::error::BridgeError;
use crate::proto::auth::auth_client::AuthClient as ProtoAuthClient;
use crate::proto::auth::{AuthorizeClientRequest, ClientOperation};
use crate::transport::GrpcChannel;

/// Principal identifier returned by the host. Opaque string from the
/// TEE's perspective — host is authoritative on identity; the TEE
/// uses it as the per-credential key for cross-session boundary checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(pub String);

impl Principal {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Outcome of an authorization request. The whole verdict is the
/// host's word — substitution (Allowed→different principal) and
/// spurious denial (Allowed→Unauthenticated) are both observed-but-
/// not-trusted. The TEE never escalates verdict trust into a data
/// release; the client_policy_key backstop on `/init` bounds substitution
/// to at-worst denial-of-service. See architecture.md → Network
/// Isolation for the full analysis.
///
/// `Allowed` carries an optional principal (authenticated identity) —
/// host's attribution data, opaque to TEE. None is valid: not every
/// auth scheme produces a principal. TEE forwards the optional value
/// to host-side storage if present.
#[derive(Debug)]
pub enum AuthVerdict {
    /// Host claims the credential is valid. Carries the authenticated
    /// principal as attribution data for host-side bookkeeping
    /// (billing/rate-limit/audit); TEE itself doesn't act on it.
    Allowed { principal: Option<Principal> },
    /// Bad credential: missing, malformed, expired, or otherwise
    /// rejected by the host's identity provider.
    Unauthenticated,
    /// Credential is valid but not permitted for the requested
    /// operation. (RBAC failure.)
    PermissionDenied,
}

/// Client for the host-side `Auth` service exposed over the same vsock
/// channel as the rest of host-bridge.
#[derive(Clone)]
pub struct AuthClient {
    client: ProtoAuthClient<Channel>,
}

impl AuthClient {
    pub fn new(channel: GrpcChannel) -> Self {
        Self {
            client: ProtoAuthClient::new(channel),
        }
    }

    /// Authorize an HTTP request. The auth verdict (allowed / denied
    /// with reason) is the normal return value; `BridgeError` is
    /// reserved for transport-level failures (channel down, encode
    /// error, etc.) — symmetric with the rest of the host-bridge API,
    /// so callers handle infrastructure failures uniformly.
    pub async fn authorize(
        &self,
        authorization_header: &str,
        operation: ClientOperation,
    ) -> Result<Untrusted<AuthVerdict, (AuthN, Replay)>, BridgeError> {
        let request = AuthorizeClientRequest {
            authorization_header: authorization_header.to_string(),
            operation: operation as i32,
        };

        let verdict = match self.client.clone().authorize_client(request).await {
            Ok(response) => {
                let principal = response
                    .into_inner()
                    .principal
                    .filter(|s| !s.is_empty())
                    .map(Principal);
                AuthVerdict::Allowed { principal }
            }
            Err(status) => match status.code() {
                Code::Unauthenticated => AuthVerdict::Unauthenticated,
                Code::PermissionDenied => AuthVerdict::PermissionDenied,
                _ => return Err(BridgeError::from(status)),
            },
        };
        Ok(Untrusted::new(verdict, reason!(r#"
Verdict comes straight from the host's own claim. TEE can't
verify it (AuthN open), host could replay a stale answer (Replay
open). AuthZ N/A: the verdict IS the authz answer, nothing
further to check on top.
        "#)))
    }
}
