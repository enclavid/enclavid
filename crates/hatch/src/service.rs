//! What the hatch serves api, over the hooks and the egress: the contract as its
//! server sees it at this role's end ([`RemoteHatchAt`] at [`AnyCaller`]).

use enclavid_boundary::{Exposed, Untrusted};
use fleet_stream::bin;
use hatch_rpc::{
    AuthorizeError, AuthorizeRequest, BlobRequest, ClientOperation, KbsError, KbsRequest,
    KbsResponse, Manifest, ManifestRequest, PullError, RemoteHatchAt, SessionTerms, Verdict,
};

use crate::boundary::AnyCaller;
use crate::hooks::{Authorization, Hooks, Limits};
use crate::oci::Pulls;

/// One hatch, shared by every api connection it serves.
pub struct Hatch {
    pub hooks: Hooks,
    pub pulls: Pulls,
    pub kbs: reqwest::Client,
}

impl Hatch {
    /// Who the request is from, by the authorization hook if it is on; for a
    /// creation, then, what its consumer may do, by the limits hook if that is
    /// on — the session's terms, or a refusal the hook counted its way to. A
    /// read is never asked of the limits hook: it is past the gateway and api
    /// already, and a limit here would protect nothing they had not spent.
    async fn verdict(&self, req: AuthorizeRequest) -> Result<Verdict, AuthorizeError> {
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
}

impl RemoteHatchAt<AnyCaller> for Hatch {
    async fn authorize(
        &self,
        req: Untrusted<AuthorizeRequest, (), AnyCaller>,
    ) -> Result<Exposed<Verdict, (), AnyCaller>, AuthorizeError> {
        self.verdict(req.into_inner()).await.map(AnyCaller::expose)
    }

    async fn manifest(
        &self,
        req: Untrusted<ManifestRequest, (), AnyCaller>,
    ) -> Result<Exposed<Manifest, (), AnyCaller>, PullError> {
        self.pulls
            .manifest(req.into_inner())
            .await
            .map(AnyCaller::expose)
    }

    async fn blob(
        &self,
        req: Untrusted<BlobRequest, (), AnyCaller>,
    ) -> Result<Exposed<bin::Receiver, (), AnyCaller>, PullError> {
        self.pulls
            .blob(req.into_inner())
            .await
            .map(AnyCaller::expose)
    }

    async fn kbs(
        &self,
        req: Untrusted<KbsRequest, (), AnyCaller>,
    ) -> Result<Exposed<KbsResponse, (), AnyCaller>, KbsError> {
        crate::kbs::relay(&self.kbs, req.into_inner())
            .await
            .map(AnyCaller::expose)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use enclavid_boundary::inbound;

    use super::*;

    fn hatch(hooks: Hooks) -> Hatch {
        Hatch {
            hooks,
            pulls: Pulls::new(1, 1),
            kbs: crate::kbs::client().unwrap(),
        }
    }

    fn ask(operation: ClientOperation) -> Untrusted<AuthorizeRequest, (), AnyCaller> {
        inbound::<AnyCaller, _>(AuthorizeRequest {
            authorization_header: "Bearer anything".into(),
            operation,
        })
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
                .unwrap()
                .into_inner();
            assert!(matches!(
                verdict,
                Verdict::Allowed { principal: None, terms } if terms == SessionTerms::default()
            ));
        }
    }
}
