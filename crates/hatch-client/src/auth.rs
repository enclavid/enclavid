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

use std::marker::PhantomData;
use std::sync::Arc;

use enclavid_boundary::{Exposed, Receives, Untrusted};
use hatch_rpc::{AuthorizeRequest, RemoteHatchCalls, SessionTerms, Verdict};

use crate::error::BridgeError;
use crate::link::{Link, hatch, within};

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

impl From<Verdict> for AuthVerdict {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allowed { principal, terms } => AuthVerdict::Allowed {
                principal: principal.filter(|s| !s.is_empty()).map(Principal),
                terms,
            },
            Verdict::Unauthenticated => AuthVerdict::Unauthenticated,
            Verdict::Denied => AuthVerdict::PermissionDenied,
            Verdict::RateLimited { retry_after_secs } => {
                AuthVerdict::RateLimited { retry_after_secs }
            }
        }
    }
}

/// How long the hatch has to answer an authorization, unless the host says
/// otherwise (api's `authorize-deadline-secs` setting).
///
/// A creation is two questions to the hooks, each bounded by the hatch itself
/// (its `hook-deadline-secs`, 10 s by default), so this clears both plus the
/// leg. A backstop against a hatch that stops answering, not a latency budget.
pub const DEFAULT_AUTHORIZE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(25);

/// Client for the hatch's `authorize`, held at end `B` of the hatch leg, whose
/// declaration says what is open on each value that crosses it.
pub struct AuthClient<B> {
    link: Arc<dyn Link<B>>,
    deadline: std::time::Duration,
    _end: PhantomData<fn() -> B>,
}

impl<B> Clone for AuthClient<B> {
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
            deadline: self.deadline,
            _end: PhantomData,
        }
    }
}

impl<B> AuthClient<B> {
    /// A client whose every authorization the hatch has `deadline` to answer.
    pub fn new(link: Arc<dyn Link<B>>, deadline: std::time::Duration) -> Self {
        Self {
            link,
            deadline,
            _end: PhantomData,
        }
    }
}

impl<B: RemoteHatchCalls + 'static> AuthClient<B> {
    /// Authorize a request. The verdict is the normal return value, open on what
    /// `B` left open on it; `BridgeError` is for a hatch that did not give one,
    /// whose error `B`'s declaration answered in full.
    ///
    /// `req` arrives answered — `Exposed<_, (), B>` is reachable only through
    /// `B`'s declaration and the answers its sender gave after it.
    pub async fn authorize(
        &self,
        req: Exposed<AuthorizeRequest, (), B>,
    ) -> Result<Untrusted<AuthVerdict, <B as Receives<Verdict>>::Open, B>, BridgeError> {
        let hatch = hatch(self.link.as_ref())?;
        let verdict = within(self.deadline, "authorize", async {
            hatch
                .authorize(req)
                .await
                .map_err(|e| BridgeError::Transport(e.to_string()))
        })
        .await?;
        Ok(verdict.map(AuthVerdict::from))
    }
}

#[cfg(test)]
mod tests {
    use hatch_rpc::{SessionTerms, Verdict};

    use super::{AuthVerdict, Principal};

    /// Each verdict keeps its case, and an empty principal is no principal.
    #[test]
    fn a_verdict_keeps_its_case() {
        let allowed = |principal: Option<&str>| Verdict::Allowed {
            principal: principal.map(str::to_string),
            terms: SessionTerms::default(),
        };
        assert!(matches!(
            AuthVerdict::from(allowed(Some("p"))),
            AuthVerdict::Allowed { principal: Some(Principal(p)), .. } if p == "p"
        ));
        for anonymous in [allowed(Some("")), allowed(None)] {
            assert!(matches!(
                AuthVerdict::from(anonymous),
                AuthVerdict::Allowed {
                    principal: None,
                    ..
                }
            ));
        }
        assert!(matches!(
            AuthVerdict::from(Verdict::Unauthenticated),
            AuthVerdict::Unauthenticated
        ));
        assert!(matches!(
            AuthVerdict::from(Verdict::Denied),
            AuthVerdict::PermissionDenied
        ));
        assert!(matches!(
            AuthVerdict::from(Verdict::RateLimited {
                retry_after_secs: 7
            }),
            AuthVerdict::RateLimited {
                retry_after_secs: 7
            }
        ));
    }
}
