//! Client wrapper for the host-side `Auth` gRPC service.
//!
//! TEE forwards the raw HTTP `Authorization` header value plus the
//! intended operation, host validates and returns the workspace context.
//! TEE never parses JWTs / certificates / etc. — host is the source of
//! truth for client identity and RBAC.
//!
//! Trust model: host can return arbitrary verdicts (e.g. claim a token
//! is valid when it isn't, or substitute a different workspace_id).
//! K_client backstop in session creation prevents this from escalating
//! to applicant-data leak. See proto/auth.proto and architecture.md →
//! Network Isolation for the full analysis.

use enclavid_untrusted::Untrusted;
use tonic::transport::Channel;
use tonic::Code;

use crate::error::StoreError;
use crate::proto::auth::auth_client::AuthClient as ProtoAuthClient;
use crate::proto::auth::{AuthorizeClientRequest, ClientOperation};
use crate::transport::GrpcChannel;

/// Why an authorization request did NOT yield a workspace context.
/// Peer to the success type — caller maps each variant to an HTTP
/// status (401 / 403 / 500).
#[derive(Debug)]
pub enum AuthError {
    /// Bad credential: missing, malformed, expired token, or any other
    /// authentication failure surfaced by the host.
    Unauthenticated,
    /// Credential is valid but not permitted for the requested
    /// operation. (RBAC failure.)
    PermissionDenied,
    /// Transport-level failure talking to the host (channel down,
    /// timeout, etc.). Distinct from auth-decision failures so callers
    /// can pick the right HTTP status.
    Transport(StoreError),
}

impl From<StoreError> for AuthError {
    fn from(e: StoreError) -> Self {
        AuthError::Transport(e)
    }
}

/// Client for the host-side `Auth` service exposed over the same vsock
/// channel as the rest of session-store.
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

    /// Authorize an HTTP request. On success returns the workspace this
    /// credential is bound to (the only value the TEE consumes from the
    /// authorization step). On failure returns a typed `AuthError`.
    ///
    /// The success value is wrapped in `Untrusted` — host owns identity
    /// verification and we accept this delegation at the call site (see
    /// Network Isolation in architecture.md). The wrapper makes the
    /// delegation visible at every consumer rather than implicit.
    pub async fn authorize(
        &self,
        authorization_header: &str,
        operation: ClientOperation,
    ) -> Result<Untrusted<String>, AuthError> {
        let request = AuthorizeClientRequest {
            authorization_header: authorization_header.to_string(),
            operation: operation as i32,
        };

        match self.client.clone().authorize_client(request).await {
            Ok(response) => Ok(Untrusted::new(response.into_inner().workspace_id)),
            Err(status) => match status.code() {
                Code::Unauthenticated => Err(AuthError::Unauthenticated),
                Code::PermissionDenied => Err(AuthError::PermissionDenied),
                _ => Err(AuthError::Transport(StoreError::from(status))),
            },
        }
    }
}
