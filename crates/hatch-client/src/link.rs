//! Where the typed clients find the hatch: the leg api keeps connected to the
//! hatch-CVM, as it keeps one to each of its peers, held at api's end of it.

use std::sync::Arc;
use std::time::Duration;

use hatch_rpc::HatchLeg;

use crate::error::BridgeError;

/// The hatch leg as its holder keeps it, at end `B` — `None` while the leg is
/// down, and then a call fails rather than waits: how long to wait for the leg is
/// the host's call, and api's health port is already telling it.
pub trait Link<B>: Send + Sync + 'static {
    fn leg(&self) -> Option<Arc<HatchLeg<B>>>;
}

/// The hatch leg, or the leg being down as a transport failure.
pub(crate) fn hatch<B: 'static>(link: &dyn Link<B>) -> Result<Arc<HatchLeg<B>>, BridgeError> {
    link.leg()
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
