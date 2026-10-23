//! The child's callbacks, relayed to api.

use enclavid_boundary::Covert;
use engine_executor::{Decision, SessionState};
use engine_rpc::{
    CallbackError, Callbacks, Committed, MediaBytes, MediaHash, Padded, RemoteChildCallbacks,
};

use crate::boundary::AnyCaller;

/// Forwards the child's narrowed callbacks to api's, at this role's end of the
/// leg ([`AnyCaller`]): each leaves through that end's declaration, and what the
/// declaration leaves open is answered here. remoc folds a transport failure into
/// `CallbackError`, so a failed call comes back as the child's own error.
pub(crate) struct RelayCallbacks {
    pub(crate) upstream: Callbacks<AnyCaller>,
}

impl RemoteChildCallbacks for RelayCallbacks {
    async fn media_load(&self, hash: MediaHash) -> Result<Option<MediaBytes>, CallbackError> {
        let loaded = self.upstream.media_load(AnyCaller::expose(hash)).await?;
        Ok(loaded.into_inner())
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
    ) -> Result<Committed, CallbackError> {
        let state = AnyCaller::expose_builder::<Padded<SessionState>, _>(state)
            .vouch_with(Covert::Transformed, |s| Padded::seal(&s))?
            .build();
        let decision = AnyCaller::expose_builder::<Padded<Option<Decision>>, _>(decision)
            .vouch_with(Covert::Transformed, |d| Padded::seal(&d))?
            .build();
        let committed = self.upstream.session_change(state, decision).await?;
        Ok(committed.into_inner())
    }
}
