//! The child's callbacks, relayed to api.

use engine_executor::{Decision, SessionState};
use engine_rpc::{CallbackError, CallbackService, CallbackServiceClient, ChildCallbacks, Padded};
use remoc::codec::Ciborium;

/// Forwards the child's narrowed callbacks straight to api's full
/// `CallbackService` client. The upstream client method already returns the same
/// `Result<_, CallbackError>` these methods return (remoc folds transport errors
/// into `CallbackError`), so each is a one-line forward.
pub(crate) struct RelayCallbacks {
    pub(crate) upstream: CallbackServiceClient<Ciborium>,
}

impl ChildCallbacks for RelayCallbacks {
    async fn media_load(
        &self,
        hash: [u8; 32],
    ) -> Result<Option<engine_rpc::ByteBuf>, CallbackError> {
        self.upstream.media_load(hash).await
    }

    /// The child seam behind this call is a socketpair inside this CVM — no host
    /// on it — so the frames go on HERE, at the hop the host splices, and not one
    /// layer earlier where it would be a megabyte of memcpy per round against no
    /// observer. This is our own measured code performing a protocol step, not a
    /// discharge written by the party a marker distrusts: `Covert` is a property
    /// of the encoding at a hop, and this process is the one holding the bytes at
    /// it. The decision is framed on its own: whether the round finished, and
    /// how, is the policy's to choose, and its encoding's length says both.
    async fn session_change(
        &self,
        state: SessionState,
        decision: Option<Decision>,
    ) -> Result<(), CallbackError> {
        self.upstream
            .session_change(Padded::seal(&state)?, Padded::seal(&decision)?)
            .await
    }
}
