//! The session store over a leg to a store in memory, the test playing the host:
//! what the volume holds is what the test reads, changes and moves.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use enclavid_boundary::reason;
use session_types::{SessionMetadata, SessionState};
use storage_rpc::{DisclosureOp, MediaOp, MetadataOp, StateOp};

use super::*;
use crate::memory::Disk;

const KEY: [u8; 32] = [7; 32];
const TOKEN: [u8; 32] = [9; 32];

async fn store_on(disk: &Arc<Disk>, key: [u8; 32]) -> SessionStore {
    SessionStore::new(disk.connect().await, key, Some(3600))
}

fn metadata(policy_ref: &str) -> SessionMetadata {
    SessionMetadata {
        policy_ref: policy_ref.into(),
        ..SessionMetadata::default()
    }
}

/// The ops `fields` make for `id`, answered for a test.
fn ops(
    store: &SessionStore,
    id: &str,
    fields: &[&dyn WriteField],
) -> Exposed<Ops<Storage>, (), Storage> {
    store
        .seal(id, fields)
        .unwrap()
        .vouch(reason!(Covert::Bounded, "test fixture"))
}

fn set_metadata(md: &SessionMetadata) -> SetMetadata<'_> {
    SetMetadata(
        Storage::expose_builder::<MetadataOp, _>(md)
            .vouch(reason!(Covert::NotChosen, "test fixture")),
    )
}

/// `state`, to be written beside the metadata `beside`.
fn set_state(state: &SessionState, beside: &SessionMetadata) -> SetState<'static> {
    SetState {
        state: Storage::expose_builder::<StateOp, _>(state)
            .vouch_with(Covert::Transformed, encode_padded)
            .unwrap(),
        applicant_session_token: &TOKEN,
        binding: StateBinding::of(beside),
    }
}

fn set_media(hash: [u8; 32], frame: &[u8]) -> SetMedia<'static> {
    SetMedia {
        blob_hash: hash,
        bytes: Storage::expose_builder::<MediaOp, _>(frame.to_vec())
            .vouch(reason!(Covert::AlreadyHeld, "test fixture")),
        applicant_session_token: &TOKEN,
    }
}

fn state_at(step: &[u8]) -> SessionState {
    SessionState {
        state: step.to_vec(),
        ..SessionState::default()
    }
}

async fn create(store: &SessionStore, id: &str, md: &SessionMetadata) -> u64 {
    let set = set_metadata(md);
    store
        .create(3600, ops(store, id, &[&set]))
        .await
        .unwrap()
        .trust(reason!(Replay::Harmless, "test fixture"))
        .into_inner()
}

/// Write `fields` to `id` at `version`; the version it leaves.
async fn write(store: &SessionStore, id: &str, version: u64, fields: &[&dyn WriteField]) -> u64 {
    store
        .write(Some(version), ops(store, id, fields))
        .await
        .unwrap()
        .trust(reason!(Replay::Harmless, "test fixture"))
        .into_inner()
}

async fn read_metadata(
    store: &SessionStore,
    id: &str,
) -> Result<Option<SessionMetadata>, StoreError> {
    let ((md,), _version) = store.read(id, (Metadata,)).await?;
    Ok(md
        .trust(reason!(AuthZ::Matched, "test fixture"))
        .trust(reason!(Replay::Harmless, "test fixture"))
        .into_inner())
}

/// The state of `id`, opened beside its metadata as api opens it.
async fn read_state(store: &SessionStore, id: &str) -> Result<Option<SessionState>, StoreError> {
    let ((md, sealed), _version) = store.read(id, (Metadata, SealedState)).await?;
    let md = md
        .trust(reason!(AuthZ::Matched, "test fixture"))
        .trust(reason!(Replay::Harmless, "test fixture"))
        .into_inner()
        .expect("the session exists");
    Ok(store
        .open_state(id, sealed, &md, &TOKEN)?
        .trust(reason!(Replay::Harmless, "test fixture"))
        .into_inner())
}

/// A record is kept under a keyed digest of its session id: the same for every
/// call of one session, another for another session, and another again under
/// another key — never the id.
#[tokio::test]
async fn a_record_is_named_by_a_keyed_digest_of_its_id() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    create(&store, "ses_a", &metadata("a")).await;

    let names: Vec<RecordName> = disk.records.lock().unwrap().keys().copied().collect();
    assert_eq!(names, [store.record("ses_a").into_inner()]);
    assert_ne!(names[0].0[..5], *b"ses_a");
    assert_ne!(store.record("ses_b").into_inner(), names[0]);
    let other_key = store_on(&disk, [8; 32]).await;
    assert_ne!(other_key.record("ses_a").into_inner(), names[0]);
}

/// Whatever a session writes — metadata, state, media, a disclosure — nothing
/// the volume holds carries its id: not a record's name, not a field, not a
/// media blob's name.
#[tokio::test]
async fn no_session_id_reaches_the_volume() {
    let id = "ses_0123456789abcdefghij";
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    let version = create(&store, id, &metadata("a")).await;

    let md = metadata("b");
    let set = set_metadata(&md);
    let state = set_state(&SessionState::default(), &md);
    let media = set_media([3; 32], b"a frame");
    let disclosure = AppendDisclosure(
        Storage::expose_builder::<DisclosureOp, _>(b"sealed to the consumer".to_vec())
            .vouch(reason!(AuthN::Indifferent, "test fixture"))
            .vouch(reason!(AuthZ::Matched, "test fixture"))
            .vouch_with(Covert::NotChosen, |bytes| Ok::<_, ()>(DisclosureOp(bytes)))
            .unwrap()
            .build(),
    );
    write(&store, id, version, &[&set, &state, &media, &disclosure]).await;

    let records = disk.records.lock().unwrap();
    let mut held: Vec<Vec<u8>> = Vec::new();
    for (name, record) in records.iter() {
        held.push(name.0.to_vec());
        held.extend(record.metadata.clone());
        held.extend(record.state.clone());
        held.extend(record.disclosures.iter().cloned());
        for (name, value) in &record.media {
            held.push(name.0.to_vec());
            held.push(value.clone());
        }
    }
    assert!(held.len() >= 6, "every field reached the volume");
    for bytes in &held {
        assert!(
            !bytes.windows(id.len()).any(|w| w == id.as_bytes()),
            "a session id on the volume"
        );
    }
}

/// What a session wrote reads back opened, field by field, at the version its
/// last write returned.
#[tokio::test]
async fn fields_round_trip_over_the_leg() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    let md = metadata("a");
    let created = create(&store, "ses_a", &md).await;

    let state = state_at(b"step 3");
    let written = write(&store, "ses_a", created, &[&set_state(&state, &md)]).await;
    assert_eq!(written, created + 1);

    assert_eq!(read_metadata(&store, "ses_a").await.unwrap(), Some(md));
    assert_eq!(read_state(&store, "ses_a").await.unwrap(), Some(state));
    let (_, version) = store.read("ses_a", (Metadata,)).await.unwrap();
    assert_eq!(
        version
            .trust(reason!(Replay::Harmless, "test fixture"))
            .into_inner(),
        written
    );

    let (_, absent) = store.read("ses_none", (Metadata,)).await.unwrap();
    assert_eq!(
        absent
            .trust(reason!(Replay::Harmless, "test fixture"))
            .into_inner(),
        0
    );
}

/// A record the host files under another session's name does not open there:
/// each is sealed to its own session.
#[tokio::test]
async fn a_record_moved_to_another_session_does_not_open() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    create(&store, "ses_a", &metadata("a")).await;
    create(&store, "ses_b", &metadata("b")).await;

    {
        let mut records = disk.records.lock().unwrap();
        let a = records[&store.record("ses_a").into_inner()].clone();
        records.insert(store.record("ses_b").into_inner(), a);
    }
    assert!(matches!(
        read_metadata(&store, "ses_b").await,
        Err(StoreError::Crypto(_))
    ));
    assert_eq!(
        read_metadata(&store, "ses_a").await.unwrap(),
        Some(metadata("a"))
    );
}

/// A state the host puts back from before a newer disclosure does not open: it
/// was sealed beside other metadata than the record's. So an applicant whose old
/// state comes back cannot carry on beside someone else's disclosures.
#[tokio::test]
async fn a_state_opens_only_beside_the_metadata_it_was_sealed_with() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    let before = metadata("a");
    let version = create(&store, "ses_a", &before).await;
    let version = write(
        &store,
        "ses_a",
        version,
        &[&set_state(&state_at(b"old"), &before)],
    )
    .await;
    let record = store.record("ses_a").into_inner();
    let old = disk.records.lock().unwrap()[&record].state.clone();

    let mut after = before.clone();
    after.disclosure_entry_hashes.push([5; 32]);
    write(
        &store,
        "ses_a",
        version,
        &[&set_metadata(&after), &set_state(&state_at(b"new"), &after)],
    )
    .await;
    assert_eq!(
        read_state(&store, "ses_a").await.unwrap(),
        Some(state_at(b"new"))
    );

    disk.records.lock().unwrap().get_mut(&record).unwrap().state = old;
    assert!(matches!(
        read_state(&store, "ses_a").await,
        Err(StoreError::Crypto(_))
    ));
}

/// A state missing beside metadata that records an applicant's data was removed
/// by whoever holds the volume, and is refused; missing beside metadata that
/// records none, the session is unclaimed.
#[tokio::test]
async fn a_missing_state_is_believed_only_beside_no_applicant_data() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    let fresh = metadata("a");
    let version = create(&store, "ses_a", &fresh).await;
    assert_eq!(read_state(&store, "ses_a").await.unwrap(), None);

    let mut captured = fresh.clone();
    captured.captured_media.push(vec![3; 32]);
    write(
        &store,
        "ses_a",
        version,
        &[
            &set_metadata(&captured),
            &set_state(&state_at(b"s"), &captured),
        ],
    )
    .await;
    let record = store.record("ses_a").into_inner();
    disk.records.lock().unwrap().get_mut(&record).unwrap().state = None;
    assert!(matches!(
        read_state(&store, "ses_a").await,
        Err(StoreError::Crypto(_))
    ));
}

/// Each field is sealed to itself: a state the host puts in the metadata's place
/// does not open as metadata.
#[tokio::test]
async fn a_state_does_not_open_as_metadata() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    let md = metadata("a");
    let version = create(&store, "ses_a", &md).await;
    write(
        &store,
        "ses_a",
        version,
        &[&set_state(&state_at(b"s"), &md)],
    )
    .await;

    {
        let mut records = disk.records.lock().unwrap();
        let record = records
            .get_mut(&store.record("ses_a").into_inner())
            .unwrap();
        record.metadata = record.state.clone();
    }
    assert!(matches!(
        read_metadata(&store, "ses_a").await,
        Err(StoreError::Crypto(_))
    ));
}

/// A reply with fewer slots than the read asked for is refused, never read.
#[tokio::test]
async fn a_reply_short_of_its_slots_is_refused() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    create(&store, "ses_a", &metadata("a")).await;

    disk.short_reads.store(true, Ordering::Relaxed);
    assert!(matches!(
        read_metadata(&store, "ses_a").await,
        Err(StoreError::Transport(_))
    ));
}

/// A write at a version the record has moved past is refused, and so is a
/// create for a session that exists; nothing either carried is kept.
#[tokio::test]
async fn a_write_at_another_version_is_refused() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    let version = create(&store, "ses_a", &metadata("a")).await;

    let md = metadata("b");
    let set = set_metadata(&md);
    assert!(matches!(
        store
            .write(Some(version + 1), ops(&store, "ses_a", &[&set]))
            .await,
        Err(StoreError::VersionMismatch)
    ));
    assert!(matches!(
        store.create(3600, ops(&store, "ses_a", &[&set])).await,
        Err(StoreError::VersionMismatch)
    ));
    assert_eq!(
        read_metadata(&store, "ses_a").await.unwrap(),
        Some(metadata("a"))
    );
}

/// A capture reads back opened by its content hash, kept under a name that is
/// not the hash; under another session's name it does not open.
#[tokio::test]
async fn media_round_trips_under_a_name_that_is_not_its_hash() {
    let disk = Arc::new(Disk::default());
    let store = store_on(&disk, KEY).await;
    let version = create(&store, "ses_a", &metadata("a")).await;

    let hash = [3; 32];
    write(&store, "ses_a", version, &[&set_media(hash, b"a frame")]).await;

    let loaded = store
        .load_media("ses_a", &hash, &TOKEN)
        .await
        .unwrap()
        .trust(reason!(Replay::Idempotent, "test fixture"))
        .into_inner();
    assert_eq!(loaded.as_deref(), Some(&b"a frame"[..]));
    let missing = store
        .load_media("ses_a", &[4; 32], &TOKEN)
        .await
        .unwrap()
        .trust(reason!(Replay::Idempotent, "test fixture"))
        .into_inner();
    assert_eq!(missing, None);

    {
        let mut records = disk.records.lock().unwrap();
        let a = records[&store.record("ses_a").into_inner()].clone();
        assert!(a.media.keys().all(|name| name.0 != hash));
        records.insert(store.record("ses_b").into_inner(), a);
    }
    let moved = store
        .load_media("ses_b", &hash, &TOKEN)
        .await
        .unwrap()
        .trust(reason!(Replay::Idempotent, "test fixture"))
        .into_inner();
    assert_eq!(moved, None, "another session names its media otherwise");
}
