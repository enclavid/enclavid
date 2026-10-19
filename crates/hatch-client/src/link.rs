//! Where the typed clients find the hatch: the leg api keeps connected to the
//! hatch-CVM, as it keeps one to each of its peers.

use std::time::Duration;

use hatch_rpc::HatchClient;

use crate::error::BridgeError;

/// The hatch's client as the leg holds it — `None` while the leg is down, and
/// then a call fails rather than waits: how long to wait for the leg is the
/// host's call, and api's health port is already telling it.
pub trait Link: Send + Sync + 'static {
    fn client(&self) -> Option<HatchClient>;
}

/// The hatch's client, or the leg being down as a transport failure.
pub(crate) fn hatch(link: &dyn Link) -> Result<HatchClient, BridgeError> {
    link.client()
        .ok_or_else(|| BridgeError::Transport("the hatch leg is down".into()))
}

/// `call`, given `deadline` to come back. A remoc call has no deadline of its
/// own, and a hatch that stops answering must not park the caller.
pub(crate) async fn within<T>(
    deadline: Duration,
    what: &'static str,
    call: impl Future<Output = Result<T, BridgeError>>,
) -> Result<T, BridgeError> {
    tokio::time::timeout(deadline, call)
        .await
        .map_err(|_| BridgeError::Transport(format!("{what}: no answer in {deadline:?}")))?
}
