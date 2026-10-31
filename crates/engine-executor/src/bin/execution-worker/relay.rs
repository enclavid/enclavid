//! The child's callbacks: relayed to api, and its models started here, their
//! files filled first.

use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use enclavid_boundary::Covert;
use engine_executor::{Decision, SessionState};
use engine_rpc::{
    CallbackError, Callbacks, Committed, MediaBytes, MediaHash, ModelFileDigest, ModelFileStream,
    Padded, RemoteChildCallbacks,
};
use engine_supervisor::Coprocess;
use safe_logger::debug;
use tokio::time::Instant;

use crate::boundary::AnyCaller;
use crate::bundles::{Bundles, CompositionEntry};
use crate::model_files::ModelFileSlot;

#[cfg(test)]
mod tests;

/// Forwards the child's narrowed callbacks to api's, at this role's end of the
/// leg ([`AnyCaller`]): each leaves through that end's declaration, and what the
/// declaration leaves open is answered here. remoc folds a transport failure into
/// `CallbackError`, so a failed call comes back as the child's own error.
///
/// A model the child asks for is started here, in a process of its own beside
/// the child, on the socket whose other end the child was handed at spawn; its
/// files are the entry's own, filled here, once, from api, the first time any
/// round of the composition runs a model of them.
pub(crate) struct RelayCallbacks {
    pub(crate) upstream: Callbacks<AnyCaller>,
    /// The entry the round runs, whose model files its models' processes map.
    pub(crate) entry: Arc<CompositionEntry>,
    pub(crate) bundles: Arc<Bundles>,
    /// How long a fill waits for room, as a bundle's does.
    pub(crate) capacity_wait: Duration,
    /// How long a model file may take to stream in whole, and go without a
    /// new byte — a bundle's own bounds.
    pub(crate) stream_deadline: Duration,
    pub(crate) stream_idle: Duration,
    /// What starts a process beside the round's child.
    pub(crate) coprocess: Coprocess,
    /// This end of each model's socket, in the order of the entry's models,
    /// until the model's process is started on it.
    pub(crate) sockets: Mutex<Vec<Option<OwnedFd>>>,
    /// What a model's process is handed for a data file where its graph has
    /// none: a file with nothing in it.
    pub(crate) empty: Arc<File>,
}

impl RelayCallbacks {
    /// The entry's model file `index`.
    fn file(&self, index: u32) -> Result<&ModelFileSlot, CallbackError> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.entry.files.get(i))
            .ok_or(CallbackError)
    }

    /// Fill `slot`, unless a round already has: room for it reserved out of
    /// the cache's budget before the first byte, its bytes asked of api by the
    /// digest the bundle gives it, held to the bundle's length and digest,
    /// sealed, and only then charged to the entry. Rounds asking at once wait
    /// for the one fill; a fill that fails leaves the file empty for the next
    /// round to fill.
    async fn fill(&self, slot: &ModelFileSlot) -> Result<(), CallbackError> {
        let mut filled = slot.filled.lock().await;
        if *filled {
            return Ok(());
        }
        let declared = &slot.declared;
        let room = self
            .bundles
            .reserve_bytes(declared.length, Instant::now() + self.capacity_wait)
            .await
            .map_err(|_| CallbackError)?;
        let stream: ModelFileStream = self
            .upstream
            .model_file_load(AnyCaller::expose(ModelFileDigest(declared.sha256)))
            .await?
            .into_inner();
        // The stream names the file the bundle declared, or none of it is kept.
        if stream.header.length() != declared.length || stream.header.sha256() != declared.sha256 {
            debug!("model_file_load: the stream names another file");
            return Err(CallbackError);
        }
        let mut sink = slot.writer().map_err(|e| {
            debug!("model_file_load: {e}");
            CallbackError
        })?;
        stream
            .receive(&mut sink, self.stream_deadline, self.stream_idle)
            .await
            .map_err(|e| {
                debug!("model_file_load: model file stream: {e}");
                CallbackError
            })?;
        slot.seal().map_err(|e| {
            debug!("model_file_load: {e}");
            CallbackError
        })?;
        self.bundles
            .grow(&self.entry, room)
            .map_err(|_| CallbackError)?;
        *filled = true;
        Ok(())
    }
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

    /// Start model `index` of the entry: its graph and its data file filled,
    /// then a process for it beside the child, on this end of the model's
    /// socket, handed the two files opened for reading — the empty file for a
    /// graph without data. Once per model a round: its socket goes with the
    /// start.
    async fn start_model(&self, index: u32) -> Result<(), CallbackError> {
        let model = usize::try_from(index)
            .ok()
            .and_then(|i| self.entry.models.get(i))
            .ok_or(CallbackError)?;
        let socket = usize::try_from(index)
            .ok()
            .and_then(|i| {
                self.sockets
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get_mut(i)
                    .and_then(Option::take)
            })
            .ok_or_else(|| {
                debug!("start_model: a model started a second time");
                CallbackError
            })?;
        let opened = |slot: &ModelFileSlot| {
            slot.reader().map_err(|e| {
                debug!("start_model: {e}");
                CallbackError
            })
        };
        let graph = self.file(model.graph)?;
        self.fill(graph).await?;
        let graph = opened(graph)?;
        let data = match model.data {
            Some(data) => {
                let data = self.file(data)?;
                self.fill(data).await?;
                Some(opened(data)?)
            }
            None => None,
        };
        let data = data.as_ref().map_or(self.empty.as_fd(), AsFd::as_fd);
        self.coprocess
            .start(socket, &[graph.as_fd(), data], self.entry.clone())
            .map_err(|e| {
                debug!("start_model: {e}");
                CallbackError
            })
    }
}
