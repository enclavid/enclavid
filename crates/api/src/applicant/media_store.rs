//! Broker-backed host media store — the live [`MediaStore`] the engine calls
//! for `frame::from-blob-ref`. Delegates to
//! [`SessionStore::load_media`](broker_client::SessionStore::load_media)
//! (read + double-open under this session's keys). Constructed per run in the
//! applicant extractor alongside the [`SessionPersister`](super::persister);
//! replaces the Stage-1 no-op store.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use broker_client::{Replay, SessionStore, public_session_id, reason};
use enclavid_engine::{MediaStore, RunError, RunResult};

pub(super) struct BrokerMediaStore {
    pub session_store: Arc<SessionStore>,
    pub session_id: String,
    /// Applicant bearer token — the inner AEAD layer's key. A `/reset`
    /// discards it, after which all this session's media is unreadable.
    pub applicant_session_token: Vec<u8>,
}

impl MediaStore for BrokerMediaStore {
    fn load<'a>(
        &'a self,
        blob_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = RunResult<Option<Vec<u8>>>> + Send + 'a>> {
        Box::pin(async move {
            let id = public_session_id(&self.session_id);
            let bytes = self
                .session_store
                .load_media(id, blob_hash, &self.applicant_session_token)
                .await
                .map_err(|e| RunError::msg(format!("media load failed: {e}")))?
                .trust_unchecked::<Replay, _>(reason!(
                    "media blob is content-addressed by BLAKE3; a stale or reordered read \
                     can only return identical bytes"
                ))
                .into_inner();
            Ok(bytes)
        })
    }
}
