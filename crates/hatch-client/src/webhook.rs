//! Client for the hatch's webhooks.
//!
//! api sends a consumer's webhook through the hatch one attempt at a time: this
//! hands one over and gives back whether the endpoint took it. Building the
//! request — its body and its signature — and when to try again are api's.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use enclavid_boundary::{Exposed, Receives, Untrusted};
use hatch_rpc::{RemoteHatchCalls, WebhookAnswer, WebhookRequest};

use crate::error::BridgeError;
use crate::link::{Link, hatch, within};

/// How long the hatch has to answer one attempt: past its own deadline on the
/// endpoint, so the endpoint's silence comes back as the hatch's answer.
pub const DEFAULT_WEBHOOK_DEADLINE: Duration = Duration::from_secs(20);

/// Client for the hatch's webhooks, held at end `B` of the hatch leg, whose
/// declaration says what is open on each value that crosses it.
pub struct WebhookClient<B> {
    link: Arc<dyn Link<B>>,
    deadline: Duration,
    _end: PhantomData<fn() -> B>,
}

impl<B> Clone for WebhookClient<B> {
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
            deadline: self.deadline,
            _end: PhantomData,
        }
    }
}

impl<B> WebhookClient<B> {
    /// A client whose every attempt the hatch has `deadline` to answer.
    pub fn new(link: Arc<dyn Link<B>>, deadline: Duration) -> Self {
        Self {
            link,
            deadline,
            _end: PhantomData,
        }
    }
}

impl<B: RemoteHatchCalls + 'static> WebhookClient<B> {
    /// One attempt at the webhook `req`, answered as `B` answers what leaves;
    /// whether the endpoint took it comes back open on what `B` left open on it.
    /// No answer in time, from the hatch or the endpoint, is a `BridgeError`.
    pub async fn send(
        &self,
        req: Exposed<WebhookRequest, (), B>,
    ) -> Result<Untrusted<WebhookAnswer, <B as Receives<WebhookAnswer>>::Open, B>, BridgeError>
    {
        let hatch = hatch(self.link.as_ref())?;
        within(self.deadline, "webhook", async {
            hatch
                .webhook(req)
                .await
                .map_err(|e| BridgeError::Transport(e.to_string()))
        })
        .await
    }
}
