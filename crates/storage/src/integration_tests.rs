//! End-to-end: serve BOTH storage services (backed by the real per-session
//! SQLite store and an object_store cache) over an in-process
//! `tokio::io::duplex`, the way the storage-CVM serves them, and drive them
//! through the leg's doors the way api does — the api ↔ storage-CVM path minus
//! RA-TLS.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use enclavid_boundary::{AuthN, Exposed};
use enclavid_boundary_macros::boundary;
use futures::StreamExt;
use futures::stream::BoxStream;
use object_store::ObjectStore;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use tokio::io::split;

use fleet_stream::{Incoming, StreamLen};
use storage_rpc::{
    BlobName, BlobStream, CacheBlob, CacheError, DisclosureOp, Dropped, Expected, Fields, Kept,
    LegSettings, MediaName, MediaOp, MetadataOp, Ops, RecordName, ResetOp, ScalarSlot,
    SessionError, Slot, StateOp, StorageLeg, Version,
};

use crate::boundary::AnyCaller;
use crate::{CacheBlobs, Caller, SessionStore, StorageSvc};

/// A blob's pieces, as the tests stream one.
type Pieces = BoxStream<'static, Result<Bytes, ()>>;

boundary! {
    /// The calling end, for the test: every concern answered.
    Api {
        calls: [storage_rpc::RemoteSessionStore, storage_rpc::RemoteCache],
        observer: Test,
    }
    out (AuthN,) {
        /// test fixture
        _: AuthN::Indifferent,
        RecordName,
        BlobName,
        MetadataOp,
        StateOp,
        MediaName,
        MediaOp,
        DisclosureOp,
        ResetOp,
        Ops<Api>,
        Expected,
        Fields<Api>,
        BlobStream,
    }
    in (AuthN,) {
        /// test fixture
        _: AuthN::Indifferent,
        Slot,
        Version,
        Option<CacheBlob>,
        Kept,
        Dropped,
        SessionError,
        CacheError,
    }
}

/// A stand-in launch digest. Any two distinct strings would do — the partition
/// derives from the bytes, not from their shape.
fn peer(tag: &str) -> String {
    tag.repeat(48)
}

const ROOMY: u64 = 64 * 1024 * 1024;
const READ_PIECE: std::num::NonZeroUsize = std::num::NonZeroUsize::new(64 * 1024).unwrap();

/// A store whose sessions are under `dir`, and whose cache is `cache`.
fn svc_in(dir: &std::path::Path, cache: Arc<dyn ObjectStore>) -> Arc<StorageSvc> {
    let sessions =
        Arc::new(SessionStore::open(dir.to_str().unwrap(), crate::DEFAULT_BUSY_TIMEOUT).unwrap());
    Arc::new(StorageSvc::new(
        sessions,
        CacheBlobs::new(cache, ROOMY, READ_PIECE),
    ))
}

fn store() -> (tempfile::TempDir, Arc<StorageSvc>) {
    let dir = tempfile::tempdir().unwrap();
    let svc = svc_in(dir.path(), Arc::new(InMemory::new()));
    (dir, svc)
}

/// Serve both services to `caller` over an in-process duplex and bring the leg
/// up as api does. Returns the leg, the handle that says it is over, and the
/// server task.
async fn connected(
    caller: Caller,
) -> (
    StorageLeg<Api>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (a, b) = tokio::io::duplex(1024 * 1024);
    let (a_r, a_w) = split(a);
    let (b_r, b_w) = split(b);
    let server = tokio::spawn(async move {
        let _ = storage_rpc::serve_storage::<AnyCaller, _, _, _>(
            a_r,
            a_w,
            caller,
            4,
            4,
            &LegSettings::default(),
        )
        .await;
    });
    let (leg, ended) = storage_rpc::connect_storage::<Api, _, _>(b_r, b_w, &LegSettings::default())
        .await
        .unwrap();
    (leg, ended, server)
}

fn record(tag: u8) -> Exposed<RecordName, (), Api> {
    Api::expose(RecordName([tag; 32]))
}

fn blob(tag: u8) -> Exposed<BlobName, (), Api> {
    Api::expose(BlobName([tag; 32]))
}

/// A write's ops to the record `tag`, as `add` adds them.
fn ops(tag: u8, add: impl FnOnce(&mut Ops<Api>)) -> Exposed<Ops<Api>, (), Api> {
    let mut ops = Ops::for_record(record(tag));
    add(&mut ops);
    Api::expose(ops)
}

fn metadata(value: &[u8]) -> Exposed<MetadataOp, (), Api> {
    Api::expose(MetadataOp(value.to_vec()))
}

/// The media name `tag` names.
fn media_name(tag: u8) -> Exposed<MediaName, (), Api> {
    Api::expose(MediaName([tag; 32]))
}

fn media(ops: &mut Ops<Api>, tag: u8, sealed: &[u8]) {
    ops.media(media_name(tag), Api::expose(MediaOp(sealed.to_vec())));
}

fn reset(tag: u8) -> Exposed<Ops<Api>, (), Api> {
    ops(tag, |o| o.reset(Api::expose(ResetOp)))
}

/// A create, expiring far in the future.
fn create() -> Expected {
    Expected::Absent {
        deadline_unix_secs: Some(9_999_999_999),
    }
}

async fn write(
    leg: &StorageLeg<Api>,
    expected: Expected,
    ops: Exposed<Ops<Api>, (), Api>,
) -> Result<u64, SessionError> {
    leg.write(Api::expose(expected), ops)
        .await
        .map(|v| v.into_inner().0)
}

/// Write `value` as the record `tag`'s metadata: a create, or an update at
/// `expected`.
async fn set_metadata(
    leg: &StorageLeg<Api>,
    tag: u8,
    value: &[u8],
    expected: Option<u64>,
) -> Result<u64, SessionError> {
    let expected = expected.map_or_else(create, Expected::Version);
    write(leg, expected, ops(tag, |o| o.metadata(metadata(value)))).await
}

/// The record `tag`'s fields `add` asks for, and its version.
async fn read(
    leg: &StorageLeg<Api>,
    tag: u8,
    add: impl FnOnce(&mut Fields<Api>),
) -> (Vec<Slot>, u64) {
    let mut fields = Fields::new();
    add(&mut fields);
    let (slots, version) = leg.read(record(tag), Api::expose(fields)).await.unwrap();
    (
        slots.into_iter().map(|s| s.into_inner()).collect(),
        version.into_inner().0,
    )
}

/// Store `bytes` under the blob `tag`, streaming them beside the call as api does.
async fn put(leg: &StorageLeg<Api>, tag: u8, bytes: &[u8]) -> Result<(), CacheError> {
    let pieces: Pieces = futures::stream::iter([Ok(Bytes::copy_from_slice(bytes))]).boxed();
    let stream = BlobStream {
        length: StreamLen::new(bytes.len() as u64).unwrap(),
        pieces,
    };
    leg.store(blob(tag), Api::expose(stream)).await.map(|kept| {
        kept.into_inner();
    })
}

/// The blob `tag`, read whole as api reads one.
async fn get(leg: &StorageLeg<Api>, tag: u8) -> Option<Vec<u8>> {
    let blob = leg.load(blob(tag)).await.unwrap().into_inner()?;
    let mut incoming = Incoming::open(blob.body, blob.length.get(), Duration::from_secs(10))
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(piece) = incoming.next().await.unwrap() {
        got.extend_from_slice(&piece);
    }
    Some(got)
}

#[tokio::test]
async fn both_services_round_trip_over_the_leg() {
    let (_dir, store) = store();
    let (leg, _ended, server) = connected(Caller::new(store, peer("ab"))).await;

    // --- session: create → read → CAS update → stale reject → reset ---
    assert_eq!(set_metadata(&leg, 1, b"m1", None).await.unwrap(), 1);
    let (slots, version) = read(&leg, 1, |f| f.metadata()).await;
    assert_eq!(version, 1);
    assert_eq!(
        slots[0],
        Slot::Scalar(ScalarSlot {
            value: Some(b"m1".to_vec())
        })
    );
    assert_eq!(set_metadata(&leg, 1, b"m2", Some(1)).await.unwrap(), 2);
    // Stale CAS → VersionMismatch surfaces across the wire.
    assert!(matches!(
        set_metadata(&leg, 1, b"x", Some(1)).await,
        Err(SessionError::VersionMismatch)
    ));
    write(&leg, Expected::Version(2), reset(1)).await.unwrap();
    // The session survives its reset.
    assert_eq!(read(&leg, 1, |_| {}).await.1, 3);

    // --- cache: miss → store → load → remove → miss ---
    assert_eq!(get(&leg, 7).await, None);
    put(&leg, 7, b"cwasm").await.unwrap();
    assert_eq!(get(&leg, 7).await, Some(b"cwasm".to_vec()));
    leg.remove(blob(7)).await.unwrap().into_inner();
    assert_eq!(get(&leg, 7).await, None);

    server.abort();
}

/// A blob past one remoc item crosses both ways, and one whose pieces fail
/// part-way is never kept: the store answers an error and the blob before it
/// stays.
#[tokio::test]
async fn cache_blobs_stream_and_an_abandoned_one_is_not_kept() {
    let (_dir, store) = store();
    let (leg, _ended, server) = connected(Caller::new(store, peer("ab"))).await;

    let big: Vec<u8> = (0..remoc::rch::DEFAULT_MAX_ITEM_SIZE + 1)
        .map(|i| (i % 251) as u8)
        .collect();
    put(&leg, 7, &big).await.unwrap();
    assert!(get(&leg, 7).await == Some(big.clone()));

    let failing: Pieces = futures::stream::iter([Ok(Bytes::from(vec![0u8; 500])), Err(())]).boxed();
    let stream = BlobStream {
        length: StreamLen::new(1000).unwrap(),
        pieces: failing,
    };
    assert!(
        leg.store(blob(7), Api::expose(stream)).await.is_err(),
        "an abandoned blob is not stored"
    );
    assert!(get(&leg, 7).await == Some(big));

    server.abort();
}

/// A write past what one call carries fails alone. remoc, handed it, would close
/// the session store's request channel for every caller on the leg; the door
/// refuses it before that, and the leg goes on.
#[tokio::test]
async fn an_oversized_write_fails_alone() {
    let (_dir, store) = store();
    let (leg, ended, server) = connected(Caller::new(store, peer("ab"))).await;

    // Just under remoc's item on its own: the call it crosses in does not fit.
    let oversized = vec![0xff; remoc::rch::DEFAULT_MAX_ITEM_SIZE - 1024];
    let oversized = ops(1, |o| media(o, 1, &oversized));
    assert!(matches!(
        write(&leg, create(), oversized).await,
        Err(SessionError::TooLarge)
    ));
    assert_eq!(set_metadata(&leg, 1, b"m1", None).await.unwrap(), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), ended)
            .await
            .is_err(),
        "the leg goes on"
    );

    server.abort();
}

/// The scenario the partition exists for: a guest the host launched connects,
/// attests as itself (which is all this node can require of it), and asks for
/// the records api is using, by the very names api uses.
#[tokio::test]
async fn one_caller_cannot_reach_another_caller() {
    let (_dir, store) = store();
    let (api, _, api_server) = connected(Caller::new(store.clone(), peer("ab"))).await;
    let (other, _, other_server) = connected(Caller::new(store, peer("cd"))).await;

    // STATE and media, not just metadata: those are what a reset drops, so a
    // record without them would let a reset that reached it go unseen.
    let first = ops(1, |o| {
        o.metadata(metadata(b"real"));
        o.state(Api::expose(StateOp(b"in-flight".to_vec())));
        media(o, 1, b"selfie");
    });
    write(&api, create(), first).await.unwrap();
    put(&api, 7, b"real").await.unwrap();

    // It cannot find out that the session is there...
    assert_eq!(read(&other, 1, |_| {}).await.1, 0);
    assert_eq!(get(&other, 7).await, None);
    // ...cannot reset it out from under the applicant, even naming its
    // version...
    assert!(matches!(
        write(&other, Expected::Version(1), reset(1)).await,
        Err(SessionError::VersionMismatch)
    ));
    // ...and its own create succeeds rather than colliding, which is the point:
    // it lands in its own partition, so api's CAS version is not touched.
    set_metadata(&other, 1, b"junk", None).await.unwrap();
    put(&other, 7, b"junk").await.unwrap();
    other.remove(blob(7)).await.unwrap().into_inner();

    let (slots, version) = read(&api, 1, |f| {
        f.metadata();
        f.state();
        f.media(media_name(1));
    })
    .await;
    assert_eq!(version, 1);
    assert_eq!(
        slots[0],
        Slot::Scalar(ScalarSlot {
            value: Some(b"real".to_vec())
        })
    );
    // The reducer state and the capture the foreign reset would have wiped.
    assert_eq!(
        slots[1],
        Slot::Scalar(ScalarSlot {
            value: Some(b"in-flight".to_vec())
        })
    );
    assert_eq!(
        slots[2],
        Slot::Scalar(ScalarSlot {
            value: Some(b"selfie".to_vec())
        })
    );
    // Neither its store nor its remove reached api's blob.
    assert_eq!(get(&api, 7).await, Some(b"real".to_vec()));

    // And the refusal above was the partition, not the version: the same call
    // from the caller that owns it resets.
    write(&api, Expected::Version(1), reset(1)).await.unwrap();
    api_server.abort();
    other_server.abort();
}

/// The TTL is not partitioned, and must not be: one sweeper, one clock, every
/// caller's expired records. Two callers holding the same name must BOTH lose
/// their record when it expires — a sweep that reached only one of them would
/// mean the other's file outlived its deadline forever.
#[tokio::test]
async fn the_sweeper_reaches_every_partition() {
    let (_dir, store) = store();
    let (api, _, api_server) = connected(Caller::new(store.clone(), peer("ab"))).await;
    let (other, _, other_server) = connected(Caller::new(store.clone(), peer("cd"))).await;

    for leg in [&api, &other] {
        let expiring = Expected::Absent {
            deadline_unix_secs: Some(100),
        };
        write(leg, expiring, ops(1, |o| o.metadata(metadata(b"m"))))
            .await
            .unwrap();
    }
    assert_eq!(store.sessions.sweep_once(1_000, 1024).unwrap(), 2);
    assert_eq!(read(&api, 1, |_| {}).await.1, 0);
    assert_eq!(read(&other, 1, |_| {}).await.1, 0);
    api_server.abort();
    other_server.abort();
}

/// Every file under `dir`, with its path relative to it.
fn files(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let name = path.strip_prefix(dir).unwrap().display().to_string();
                found.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    found
}

/// What a caller names a record or a blob by never reaches the volume — not as
/// a file name, not inside one, neither as bytes nor as hex: both are kept
/// under a digest of the caller's measurement and the name. api derives those
/// names from session ids under its own key, so no session id can reach it
/// either.
#[tokio::test]
async fn no_name_a_caller_sends_reaches_the_volume() {
    let dir = tempfile::tempdir().unwrap();
    let (sessions, cache) = (dir.path().join("sessions"), dir.path().join("cache"));
    std::fs::create_dir_all(&cache).unwrap();
    let store = svc_in(
        &sessions,
        Arc::new(LocalFileSystem::new_with_prefix(&cache).unwrap()),
    );
    let (leg, _, server) = connected(Caller::new(store, peer("ab"))).await;

    let (record_tag, blob_tag) = (0x5a, 0xa5);
    let sealed = ops(record_tag, |o| {
        o.metadata(metadata(b"sealed metadata"));
        media(o, 1, b"sealed capture");
        o.disclosure(Api::expose(DisclosureOp(b"sealed disclosure".to_vec())));
    });
    write(&leg, create(), sealed).await.unwrap();
    put(&leg, blob_tag, b"sealed cwasm").await.unwrap();

    let sent: Vec<Vec<u8>> = [record_tag, blob_tag]
        .into_iter()
        .flat_map(|tag| {
            let bytes = [tag; 32];
            [bytes.to_vec(), hex::encode(bytes).into_bytes()]
        })
        .collect();
    let kept = files(dir.path());
    assert!(!kept.is_empty(), "the volume holds the record and the blob");
    for (name, bytes) in &kept {
        for needle in &sent {
            assert!(
                !name.as_bytes().windows(needle.len()).any(|w| w == needle),
                "{name} is named by what the caller sent"
            );
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{name} holds what the caller sent as a name"
            );
        }
    }
    server.abort();
}
