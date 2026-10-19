//! Client for the hatch's `authorize`.
//!
//! api hands over the request's `Authorization` header, verbatim, and the
//! operation; the hatch asks the operator's authorization hook who it is from,
//! and for a creation its limits hook what that consumer may do. api never
//! parses a credential.
//!
//! Trust model: api pins the hatch's measurement, so the hatch is our own
//! build — but what it answers is the hooks', and the hooks are the operator's
//! word. The operator decides who may use the service and how much, and could
//! answer anything, so nothing api relies on for an applicant or a consumer
//! rests on a verdict: a session is read only with its own token, which api
//! minted and the host never sees. See architecture.md → Network Isolation.

use std::sync::Arc;

use hatch_rpc::{AuthorizeRequest, HatchService, SessionTerms, Verdict};

use crate::boundary;
use crate::error::BridgeError;
use crate::link::{Link, hatch, within};
use enclavid_boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};

/// Principal identifier the hatch returned. Opaque string from the TEE's
/// perspective — the operator's hook is authoritative on identity; the TEE uses
/// it as the per-credential key for cross-session boundary checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(pub String);

impl Principal {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Outcome of an authorization request — the whole of it the hooks' word.
#[derive(Debug)]
pub enum AuthVerdict {
    /// The request may go on. `principal` is who it is from — `None` where the
    /// hatch asks no hook who callers are. `terms` are the session's, for a
    /// creation, and empty otherwise.
    Allowed {
        principal: Option<Principal>,
        terms: SessionTerms,
    },
    /// Bad credential: missing, malformed, expired, or otherwise refused.
    Unauthenticated,
    /// The credential holds, but not for the requested operation.
    PermissionDenied,
    /// The principal has created sessions as often as it may for now; it may
    /// create one again in `retry_after_secs`.
    RateLimited { retry_after_secs: u32 },
}

/// How long the hatch has to answer an authorization, unless the host says
/// otherwise (api's `authorize-deadline-secs` setting).
///
/// A creation is two questions to the hooks, each bounded by the hatch itself
/// (its `hook-deadline-secs`, 10 s by default), so this clears both plus the
/// leg. A backstop against a hatch that stops answering, not a latency budget.
pub const DEFAULT_AUTHORIZE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(25);

/// Client for the hatch's `authorize`.
#[derive(Clone)]
pub struct AuthClient {
    link: Arc<dyn Link>,
    deadline: std::time::Duration,
}

impl AuthClient {
    /// A client whose every authorization the hatch has `deadline` to answer.
    pub fn new(link: Arc<dyn Link>, deadline: std::time::Duration) -> Self {
        Self { link, deadline }
    }

    /// Authorize a request. The verdict is the normal return value;
    /// `BridgeError` is for a hatch that did not give one.
    pub async fn authorize(
        &self,
        req: Exposed<AuthorizeRequest>,
    ) -> Result<Untrusted<AuthVerdict, (AuthN, AuthZ, Replay)>, BridgeError> {
        // The request arrives vouched by the api producer — the endpoint that
        // received the client's credential. Releasing the client's own
        // credential to its validating hatch is the producer's call, not ours to
        // self-approve; we just release it.
        let hatch = hatch(self.link.as_ref())?;
        let verdict = within(self.deadline, "authorize", async {
            hatch
                .authorize(req.into_inner())
                .await
                .map_err(|e| BridgeError::Transport(e.to_string()))
        })
        .await?;
        let verdict = match verdict {
            Verdict::Allowed { principal, terms } => AuthVerdict::Allowed {
                principal: principal.filter(|s| !s.is_empty()).map(Principal),
                terms,
            },
            Verdict::Unauthenticated => AuthVerdict::Unauthenticated,
            Verdict::Denied => AuthVerdict::PermissionDenied,
            Verdict::RateLimited { retry_after_secs } => {
                AuthVerdict::RateLimited { retry_after_secs }
            }
        };
        Ok(boundary::inbound::from_untrusted(verdict))
    }
}
