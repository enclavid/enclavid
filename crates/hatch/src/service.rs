//! What the hatch serves api: [`HatchService`], over the hooks and the egress.

use fleet_stream::bin;
use hatch_rpc::{
    AuthorizeError, AuthorizeRequest, BlobRequest, ClientOperation, HatchService, KbsError,
    KbsRequest, KbsResponse, Manifest, ManifestRequest, PullError, SessionTerms, Verdict,
};

use crate::hooks::{Authorization, Hooks, Limits};
use crate::oci::Pulls;

/// One hatch, shared by every api connection it serves.
pub struct Hatch {
    pub hooks: Hooks,
    pub pulls: Pulls,
    pub kbs: reqwest::Client,
}

impl HatchService for Hatch {
    /// Who the request is from, by the authorization hook if it is on; for a
    /// creation, then, what its consumer may do, by the limits hook if that is
    /// on — the session's terms, or a refusal the hook counted its way to. A
    /// read is never asked of the limits hook: it is past the gateway and api
    /// already, and a limit here would protect nothing they had not spent.
    async fn authorize(&self, req: AuthorizeRequest) -> Result<Verdict, AuthorizeError> {
        let hook = |e: crate::hooks::HookError| AuthorizeError(e.to_string());
        let principal = match self
            .hooks
            .authorize(&req.authorization_header, req.operation)
            .await
            .map_err(hook)?
        {
            None => None,
            Some(Authorization::Principal(principal)) => Some(principal),
            Some(Authorization::Unauthenticated) => return Ok(Verdict::Unauthenticated),
            Some(Authorization::Denied) => return Ok(Verdict::Denied),
        };
        if req.operation != ClientOperation::SessionCreate {
            return Ok(Verdict::Allowed {
                principal,
                terms: SessionTerms::default(),
            });
        }
        Ok(
            match self
                .hooks
                .limits(principal.as_deref())
                .await
                .map_err(hook)?
            {
                Limits::Terms(terms) => Verdict::Allowed { principal, terms },
                Limits::RateLimited { retry_after_secs } => {
                    Verdict::RateLimited { retry_after_secs }
                }
            },
        )
    }

    async fn manifest(&self, req: ManifestRequest) -> Result<Manifest, PullError> {
        self.pulls.manifest(req).await
    }

    async fn blob(&self, req: BlobRequest) -> Result<bin::Receiver, PullError> {
        self.pulls.blob(req).await
    }

    async fn kbs(&self, req: KbsRequest) -> Result<KbsResponse, KbsError> {
        crate::kbs::relay(&self.kbs, req).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn hatch(hooks: Hooks) -> Hatch {
        Hatch {
            hooks,
            pulls: Pulls::new(1, 1),
            kbs: crate::kbs::client().unwrap(),
        }
    }

    fn ask(operation: ClientOperation) -> AuthorizeRequest {
        AuthorizeRequest {
            authorization_header: "Bearer anything".into(),
            operation,
        }
    }

    /// With no hook on, every request goes on, as one caller, and nothing is
    /// limited.
    #[tokio::test]
    async fn with_no_hook_every_request_goes_on() {
        let h = hatch(Hooks::new(None, None, Duration::from_secs(1)));
        for _ in 0..100 {
            let verdict = h
                .authorize(ask(ClientOperation::SessionCreate))
                .await
                .unwrap();
            assert!(matches!(
                verdict,
                Verdict::Allowed { principal: None, terms } if terms == SessionTerms::default()
            ));
        }
    }
}
