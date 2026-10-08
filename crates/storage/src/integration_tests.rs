//! End-to-end remoc round-trip: serve BOTH `storage-rpc` services (backed by the
//! real per-session SQLite store + object_store cache) over an in-process
//! `tokio::io::duplex`, then drive them through the generated clients — exactly
//! the api ↔ storage-CVM path minus RA-TLS. Mirrors `engine-rpc`'s execute test.

use std::sync::Arc;

use object_store::memory::InMemory;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::io::split;

use hatch_protocol::{
    BlobField, BlobWrite, FieldSelector, MediaWrite, Op, ReadRequest, ScalarSlot, Slot,
    WriteRequest,
};
use storage_rpc::{
    ByteBuf, CacheService, CacheServiceServerShared, SessionError, SessionStoreService,
    SessionStoreServiceServerShared, StorageClients,
};

use crate::{CacheBlobs, Caller, SessionStore, StorageSvc};

/// A stand-in launch digest. Any two distinct strings would do — the partition
/// derives from the bytes, not from their shape.
fn peer(tag: &str) -> String {
    tag.repeat(48)
}

fn store() -> (tempfile::TempDir, Arc<StorageSvc>) {
    let dir = tempfile::tempdir().unwrap();
    let sessions = Arc::new(
        SessionStore::open(dir.path().to_str().unwrap(), crate::DEFAULT_BUSY_TIMEOUT).unwrap(),
    );
    let svc = Arc::new(StorageSvc::new(
        sessions,
        CacheBlobs::new(Arc::new(InMemory::new())),
    ));
    (dir, svc)
}

fn set_metadata(value: &[u8], expected: Option<u64>) -> WriteRequest {
    WriteRequest {
        ops: vec![Op::Blob(BlobWrite {
            field: BlobField::Metadata,
            value: value.to_vec(),
        })],
        expected_version: expected,
    }
}

/// Serve both services to one caller over an in-process duplex and connect to
/// them as api does. Returns the two clients and the server task.
///
/// `session_request_limit` caps the requests the session client may send. The
/// cap travels with the client, so it is set here, on the serving end.
async fn connected(
    svc: Arc<Caller>,
    session_request_limit: Option<usize>,
) -> (StorageClients, tokio::task::JoinHandle<()>) {
    use remoc::rtc::Client as _;

    let (a, b) = tokio::io::duplex(1024 * 1024);
    let (a_r, a_w) = split(a);
    let (b_r, b_w) = split(b);

    // Server end (the storage-CVM): serve both services, hand the clients over.
    let server = tokio::spawn(async move {
        let (conn, mut tx, _rx) =
            remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
                storage_rpc::connection_cfg(&storage_rpc::LegSettings::default()),
                a_r,
                a_w,
            )
            .await
            .unwrap();
        tokio::spawn(conn);
        let (s_server, mut session) =
            SessionStoreServiceServerShared::<_, Ciborium>::new(svc.clone(), 4);
        if let Some(limit) = session_request_limit {
            session.set_max_request_size(limit);
        }
        let (c_server, cache) = CacheServiceServerShared::<_, Ciborium>::new(svc.clone(), 4);
        if tx.send(StorageClients { session, cache }).await.is_err() {
            panic!("failed to send storage clients");
        }
        tokio::spawn(async move {
            let _ = s_server.serve(true).await;
        });
        c_server.serve(true).await.unwrap();
    });

    // Client end (the api orchestrator): receive both service clients.
    let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
        storage_rpc::connection_cfg(&storage_rpc::LegSettings::default()),
        b_r,
        b_w,
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    (rx.recv().await.unwrap().unwrap(), server)
}

#[tokio::test]
async fn remoc_roundtrip_both_services() {
    let (_dir, store) = store();
    let (clients, server) = connected(Arc::new(Caller::new(store, peer("ab"))), None).await;
    let session_cli = clients.session;
    let cache_cli = clients.cache;

    // --- session: create → read → CAS update → stale reject → delete → exists ---
    let id = "sess-1".to_string();
    let v1 = session_cli
        .write(id.clone(), set_metadata(b"m1", None), Some(9_999_999_999))
        .await
        .unwrap();
    assert_eq!(v1.new_version, 1);

    let got = session_cli
        .read(
            id.clone(),
            ReadRequest {
                fields: vec![FieldSelector::Blob(BlobField::Metadata)],
            },
        )
        .await
        .unwrap();
    assert_eq!(got.version, 1);
    assert_eq!(
        got.slots[0],
        Slot::Scalar(ScalarSlot {
            value: Some(b"m1".to_vec())
        })
    );

    let v2 = session_cli
        .write(id.clone(), set_metadata(b"m2", Some(1)), None)
        .await
        .unwrap();
    assert_eq!(v2.new_version, 2);

    // Stale CAS → VersionMismatch surfaces across the wire.
    let stale = session_cli
        .write(id.clone(), set_metadata(b"x", Some(1)), None)
        .await;
    assert!(matches!(stale, Err(SessionError::VersionMismatch)));

    assert!(session_cli.exists(id.clone()).await.unwrap());
    let reset = WriteRequest {
        ops: vec![Op::Reset],
        expected_version: Some(2),
    };
    session_cli.write(id.clone(), reset, None).await.unwrap();
    assert!(session_cli.exists(id.clone()).await.unwrap()); // session survives reset

    // --- cache: store → load → miss ---
    let key = "abcd".repeat(16); // 64 hex chars
    assert_eq!(cache_cli.load(key.clone()).await.unwrap(), None);
    cache_cli
        .store(key.clone(), ByteBuf::from(b"cwasm".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        cache_cli.load(key.clone()).await.unwrap(),
        Some(ByteBuf::from(b"cwasm".to_vec()))
    );

    server.abort();
}

/// What api's storage leg watches its channels for. A request past the client's
/// size limit fails before a byte of it is sent, and remoc still closes that
/// client's channel for good — that channel only: the connection stays up and
/// the other client on it goes on working. Watching the connection alone, a leg
/// in this state looked up while every session call failed. The limit is lowered
/// for the test; remoc's own is 16 MiB, and the failure is the same.
#[tokio::test]
async fn an_oversized_request_closes_its_channel_and_nothing_else() {
    use remoc::rtc::Client as _;

    const LIMIT: usize = 4096;
    let (_dir, store) = store();
    let (clients, server) = connected(Arc::new(Caller::new(store, peer("ab"))), Some(LIMIT)).await;

    let oversized = WriteRequest {
        ops: vec![Op::MediaWrite(MediaWrite {
            blob_key: vec![1u8; 32],
            value: vec![0xff; 16 * LIMIT],
        })],
        expected_version: None,
    };
    let id = "sess-1".to_string();
    assert!(
        clients
            .session
            .write(id.clone(), oversized, Some(9_999_999_999))
            .await
            .is_err()
    );

    tokio::time::timeout(std::time::Duration::from_secs(10), clients.session.closed())
        .await
        .expect("the session channel closes");
    assert!(clients.session.exists(id).await.is_err());
    assert_eq!(clients.cache.load("abcd".repeat(16)).await.unwrap(), None);

    server.abort();
}

/// The scenario the partition exists for: a guest the host launched connects,
/// attests as itself (which is all this node can require of it), and asks for
/// the records api is using. Called directly rather than over remoc — the
/// property is in who serves the call, and one connection carries one peer.
#[tokio::test]
async fn one_caller_cannot_reach_another_caller() {
    let (_dir, store) = store();
    let api = Caller::new(store.clone(), peer("ab"));
    let other = Caller::new(store, peer("cd"));

    let id = "sess-1".to_string();
    let key = "abcd".repeat(16);
    // STATE and media, not just metadata: those are what a reset drops, so a
    // record without them would let a reset that reached it go unseen.
    api.write(
        id.clone(),
        WriteRequest {
            ops: vec![
                Op::Blob(BlobWrite {
                    field: BlobField::Metadata,
                    value: b"real".to_vec(),
                }),
                Op::Blob(BlobWrite {
                    field: BlobField::State,
                    value: b"in-flight".to_vec(),
                }),
                Op::MediaWrite(MediaWrite {
                    blob_key: vec![1u8; 32],
                    value: b"selfie".to_vec(),
                }),
            ],
            expected_version: None,
        },
        Some(9_999_999_999),
    )
    .await
    .unwrap();
    api.store(key.clone(), ByteBuf::from(b"real".to_vec()))
        .await
        .unwrap();

    // It cannot find out that the session is there...
    assert!(!other.exists(id.clone()).await.unwrap());
    assert_eq!(other.load(key.clone()).await.unwrap(), None);
    // ...cannot reset it out from under the applicant, even naming its
    // version...
    let reset = || WriteRequest {
        ops: vec![Op::Reset],
        expected_version: Some(1),
    };
    assert!(matches!(
        other.write(id.clone(), reset(), None).await,
        Err(SessionError::VersionMismatch)
    ));
    // ...and its own create succeeds rather than colliding, which is the point:
    // it lands in its own partition, so api's CAS version is not touched.
    other
        .write(id.clone(), set_metadata(b"junk", None), Some(9_999_999_999))
        .await
        .unwrap();
    other
        .store(key.clone(), ByteBuf::from(b"junk".to_vec()))
        .await
        .unwrap();

    let got = api
        .read(
            id.clone(),
            ReadRequest {
                fields: vec![
                    FieldSelector::Blob(BlobField::Metadata),
                    FieldSelector::Blob(BlobField::State),
                    FieldSelector::Media(vec![1u8; 32]),
                ],
            },
        )
        .await
        .unwrap();
    assert_eq!(got.version, 1);
    assert_eq!(
        got.slots[0],
        Slot::Scalar(ScalarSlot {
            value: Some(b"real".to_vec())
        })
    );
    // The reducer state and the capture the foreign reset would have wiped.
    assert_eq!(
        got.slots[1],
        Slot::Scalar(ScalarSlot {
            value: Some(b"in-flight".to_vec())
        })
    );
    assert_eq!(
        got.slots[2],
        Slot::Scalar(ScalarSlot {
            value: Some(b"selfie".to_vec())
        })
    );
    assert_eq!(
        api.load(key).await.unwrap(),
        Some(ByteBuf::from(b"real".to_vec()))
    );

    // And the refusal above was the partition, not the version: the same call
    // from the caller that owns it resets.
    api.write(id, reset(), None).await.unwrap();
}

/// The TTL is not partitioned, and must not be: one sweeper, one clock, every
/// caller's expired records. Two callers holding the same id must BOTH lose
/// their record when it expires — a sweep that reached only one of them would
/// mean the other's file outlived its deadline forever.
#[tokio::test]
async fn the_sweeper_reaches_every_partition() {
    let (_dir, store) = store();
    let api = Caller::new(store.clone(), peer("ab"));
    let other = Caller::new(store.clone(), peer("cd"));

    let id = "sess-1".to_string();
    for c in [&api, &other] {
        c.write(id.clone(), set_metadata(b"m", None), Some(100))
            .await
            .unwrap();
    }
    assert_eq!(store.sessions.sweep_once(1_000, 1024).unwrap(), 2);
    assert!(!api.exists(id.clone()).await.unwrap());
    assert!(!other.exists(id).await.unwrap());
}
