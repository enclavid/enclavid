//! The steps of a media prompt before its last: each stored as it arrives, so
//! the round its last step runs is handed every step's capture at once.
//!
//! A step's capture goes into the session's media store as a round's captures
//! do, double-sealed under the data key, and the step into its state, in one
//! write at the version the request read. No round runs: the policy is handed
//! the steps together, in the one event the last step's request builds.

use axum::http::StatusCode;

use enclavid_boundary::{Covert, Replay, reason};
use session_types::{Capture, CaptureKind, Prompt, SentStep, SessionMetadata, SessionState, Video};
use storage_client::boundary::Storage;
use storage_client::{
    DataKeys, MediaOp, MetadataOp, SessionStore, SetMedia, SetMetadata, SetState, StateBinding,
    StateOp, StoreError, encode_padded,
};

use crate::applicant::views::{SessionProgress, prompt_view};

use super::SessionRunCtx;

impl SessionRunCtx {
    /// Store the capture of one step before the last ([`store_step`]). The
    /// session stays in the wait it was in, one step further.
    pub(in crate::applicant) async fn keep_step(
        self,
        session_state: SessionState,
        capture: Capture,
    ) -> Result<SessionProgress, StatusCode> {
        let session_state = store_step(
            &self.state.session_store,
            &self.session_id,
            self.version,
            &self.metadata,
            self.new_lock.as_ref(),
            &self.data_keys,
            session_state,
            &capture,
        )
        .await?;
        let prompt = session_state
            .current_prompt
            .as_ref()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(SessionProgress::AwaitingInput {
            awaiting_seq: session_state.awaiting_seq,
            request: prompt_view(prompt, &session_state.sent, &self.locale),
        })
    }

    /// The captures of the steps already sent ([`load_sent`]).
    pub(in crate::applicant) async fn sent_captures(
        &self,
        session_state: &SessionState,
    ) -> Result<Vec<Capture>, StatusCode> {
        load_sent(
            &self.state.session_store,
            &self.session_id,
            &self.data_keys,
            session_state,
        )
        .await
    }
}

/// Store `capture`, a step's, on the session `id` as read at `version`: its
/// blob in the media store, its hash in the metadata's captured set and the
/// step in the state, in one write. Gives back the state as written.
///
/// 409 when the session moved since the read — another tab, a second tap
/// that landed first: nothing was stored, and the page's next answer is told
/// where the session stands.
#[allow(clippy::too_many_arguments)]
async fn store_step(
    store: &SessionStore,
    id: &str,
    version: u64,
    metadata: &SessionMetadata,
    new_lock: Option<&Vec<u8>>,
    data_keys: &DataKeys,
    mut session_state: SessionState,
    capture: &Capture,
) -> Result<SessionState, StatusCode> {
    let bytes = capture.bytes();
    let hash: [u8; 32] = blake3::hash(bytes).into();
    let mut metadata = metadata.clone();
    // As a round's write would: the lock of the data key with the first state
    // sealed under it.
    if metadata.data_key_lock.is_none() {
        metadata.data_key_lock = new_lock.cloned();
    }
    // The rehydrate gate's set: a hash in it is one of an applicant blob of
    // this session, which this one is.
    if !metadata.captured_media.iter().any(|h| h.as_slice() == hash) {
        metadata.captured_media.push(hash.to_vec());
    }
    session_state.sent.push(SentStep {
        hash,
        len: bytes.len() as u64,
        guides: match capture {
            Capture::Video(video) => video.guides.clone(),
            Capture::Photo(_) => Vec::new(),
        },
    });

    let key = data_keys.current();
    let set_media = SetMedia {
        blob_hash: hash,
        bytes: Storage::expose_builder::<MediaOp, _>(bytes.to_vec()).vouch(reason!(
            Covert::AlreadyHeld,
            "one capture api itself read off /input and content-addressed here: its length \
             is the applicant's upload, which the host already watched arrive encrypted, and \
             no policy-controlled quantity is in it to pad"
        )),
        data_key: key,
    };
    let set_metadata = SetMetadata(Storage::expose_builder::<MetadataOp, _>(&metadata).vouch(
        reason!(
            Covert::AlreadyHeld,
            "sealed under tee_seal_key; grows by one fixed-size hash for the capture, whatever \
             its hash — a count the host reads off the media op in this same write anyway"
        ),
    ));
    let set_state = SetState {
        state: Storage::expose_builder::<StateOp, _>(&session_state)
            .vouch_with(Covert::Transformed, encode_padded)
            .map_err(|e| {
                safe_logger::debug!("store_step: the state does not fit its frame: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?,
        data_key: key,
        binding: StateBinding::of(&metadata),
    };
    let ops = store
        .seal(id, &[&set_state, &set_metadata, &set_media])
        .map_err(|e| {
            safe_logger::debug!("store_step: sealing failed for {id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .vouch(reason!(
            Covert::Bounded,
            "a fixed three, a state, a metadata and a media op, for each step the applicant \
             sends: the count says only that a step arrived"
        ));
    match store.write(Some(version), ops).await {
        Ok(_) => Ok(session_state),
        Err(StoreError::VersionMismatch) => Err(StatusCode::CONFLICT),
        Err(e) => {
            safe_logger::debug!("store_step: the write failed for {id}: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// The captures of the steps of session `id` already sent, read back from its
/// media store in the order of the spec it awaits, each of its step's kind.
async fn load_sent(
    store: &SessionStore,
    id: &str,
    data_keys: &DataKeys,
    session_state: &SessionState,
) -> Result<Vec<Capture>, StatusCode> {
    let Some(Prompt::Media(spec)) = session_state.current_prompt.as_ref() else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut captures = Vec::with_capacity(spec.captures.len());
    for (sent, step) in session_state.sent.iter().zip(&spec.captures) {
        let bytes = store
            .load_media(id, &sent.hash, data_keys)
            .await
            .map_err(|e| {
                safe_logger::debug!("load_sent: a read failed for {id}: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .trust(reason!(
                Replay::Idempotent,
                "api writes a step's blob only under its own blake3, which is checked below, so \
                 a stale or reordered read can return only the one plaintext that hashes to \
                 this key"
            ))
            .into_inner()
            // Stored by this session's earlier requests and gone since: the
            // host dropped it.
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        if <[u8; 32]>::from(blake3::hash(&bytes)) != sent.hash {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        captures.push(match step.kind {
            CaptureKind::Photo(_) => Capture::Photo(bytes),
            CaptureKind::Video(_) => Capture::Video(Video {
                data: bytes,
                guides: sent.guides.clone(),
            }),
        });
    }
    Ok(captures)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclavid_boundary::AuthZ;
    use session_types::{
        CameraFacing, CaptureStep, FrameRange, Guide, Localized, MediaSpec, PhotoSpec, TurnSpec,
        VideoSpec,
    };
    use storage_client::{Metadata, SealedState, lock_data_keys, unlock_data_keys};

    use super::*;

    const ID: &str = "ses_steps";
    const KEY: [u8; 32] = [9; 32];

    /// A photo step, then a video step of one guide.
    fn spec() -> MediaSpec {
        let step = |kind| CaptureStep {
            icon: None,
            instructions: Localized::default(),
            label: Localized::default(),
            camera: CameraFacing::Rear,
            kind,
        };
        MediaSpec {
            label: Localized::default(),
            captures: vec![
                step(CaptureKind::Photo(PhotoSpec::default())),
                step(CaptureKind::Video(VideoSpec { guides: vec![TURN] })),
            ],
        }
    }

    const TURN: Guide = Guide::Turn(TurnSpec {
        degrees: 30,
        hold_ms: 700,
    });

    /// A session no applicant holds yet, as created.
    async fn create() -> (Arc<storage_client::memory::Disk>, Arc<SessionStore>) {
        let disk = Arc::new(storage_client::memory::Disk::default());
        let store = Arc::new(SessionStore::new(disk.connect().await, [4; 32], None));
        let metadata = SessionMetadata::default();
        let set = SetMetadata(
            Storage::expose_builder::<MetadataOp, _>(&metadata)
                .vouch(reason!(Covert::NotChosen, "test fixture")),
        );
        let ops = store
            .seal(ID, &[&set])
            .unwrap()
            .vouch(reason!(Covert::Bounded, "test fixture"));
        store.write(None, ops).await.unwrap();
        (disk, store)
    }

    /// The session as a request reads it under the applicant's key: its
    /// metadata, data keys, the lock a first write records, its state, its
    /// version.
    async fn load(
        store: &SessionStore,
    ) -> (
        SessionMetadata,
        DataKeys,
        Option<Vec<u8>>,
        Option<SessionState>,
        u64,
    ) {
        let ((metadata, sealed), version) = store.read(ID, (Metadata, SealedState)).await.unwrap();
        let metadata = metadata
            .trust(reason!(AuthZ::Matched, "test fixture"))
            .trust_accept_risk(reason!(Replay::AcceptedRisk, "test fixture"))
            .into_inner()
            .unwrap();
        let (data_keys, new_lock) = match &metadata.data_key_lock {
            Some(lock) => (unlock_data_keys(ID, lock, &KEY).unwrap(), None),
            None => {
                let data_keys = DataKeys::fresh();
                let lock = lock_data_keys(ID, &data_keys, &KEY).unwrap();
                (data_keys, Some(lock))
            }
        };
        let state = store
            .open_state(ID, sealed, &metadata, data_keys.current())
            .unwrap()
            .trust_accept_risk(reason!(Replay::AcceptedRisk, "test fixture"))
            .into_inner();
        let version = version
            .trust(reason!(Replay::Fresh, "test fixture"))
            .into_inner();
        (metadata, data_keys, new_lock, state, version)
    }

    /// Each step is stored as it arrives and read back as it was sent, in the
    /// spec's order and of each step's kind; the state that lists them opens
    /// beside the metadata the same writes left.
    #[tokio::test]
    async fn the_steps_sent_are_stored_and_read_back() {
        let (_disk, store) = create().await;
        let waiting = SessionState {
            current_prompt: Some(Prompt::Media(spec())),
            awaiting_seq: 1,
            ..Default::default()
        };
        let photo = Capture::Photo(b"front".to_vec());
        let video = Capture::Video(Video {
            data: b"turning".to_vec(),
            guides: vec![FrameRange {
                guide: TURN,
                first: 4,
                last: 9,
            }],
        });

        let (metadata, keys, lock, _, version) = load(&store).await;
        store_step(
            &store,
            ID,
            version,
            &metadata,
            lock.as_ref(),
            &keys,
            waiting,
            &photo,
        )
        .await
        .unwrap();
        let (metadata, keys, lock, state, version) = load(&store).await;
        assert_eq!(lock, None, "the first step's write locked the session");
        let state = state.expect("the state opens beside its metadata");
        assert_eq!(state.sent.len(), 1);
        store_step(&store, ID, version, &metadata, None, &keys, state, &video)
            .await
            .unwrap();

        let (metadata, keys, _, state, _) = load(&store).await;
        let state = state.unwrap();
        assert_eq!(state.awaiting_seq, 1, "a step does not move the wait");
        assert_eq!(metadata.captured_media.len(), 2);
        assert_eq!(
            load_sent(&store, ID, &keys, &state).await,
            Ok(vec![photo, video])
        );
    }

    /// A step whose read the session has moved past since stores nothing.
    #[tokio::test]
    async fn a_step_on_a_session_that_moved_is_refused() {
        let (_disk, store) = create().await;
        let waiting = SessionState {
            current_prompt: Some(Prompt::Media(spec())),
            ..Default::default()
        };
        let photo = Capture::Photo(b"front".to_vec());
        let (metadata, keys, lock, _, version) = load(&store).await;
        store_step(
            &store,
            ID,
            version,
            &metadata,
            lock.as_ref(),
            &keys,
            waiting.clone(),
            &photo,
        )
        .await
        .unwrap();
        assert_eq!(
            store_step(
                &store,
                ID,
                version,
                &metadata,
                lock.as_ref(),
                &keys,
                waiting,
                &photo
            )
            .await,
            Err(StatusCode::CONFLICT)
        );
    }
}
