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
    CacheService, CacheServiceServerShared, SessionError, SessionStoreService,
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
    let sessions = Arc::new(SessionStore::open(dir.path().to_str().unwrap()).unwrap());
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

#[tokio::test]
async fn remoc_roundtrip_both_services() {
    let (_dir, store) = store();
    let svc = Arc::new(Caller::new(store, peer("ab")));

    let (a, b) = tokio::io::duplex(1024 * 1024);
    let (a_r, a_w) = split(a);
    let (b_r, b_w) = split(b);

    // Server end (the storage-CVM): serve both services, hand the clients over.
    let server = tokio::spawn(async move {
        let (conn, mut tx, _rx) =
            remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
                storage_rpc::connection_cfg(),
                a_r,
                a_w,
            )
            .await
            .unwrap();
        tokio::spawn(conn);
        let (s_server, session) =
            SessionStoreServiceServerShared::<_, Ciborium>::new(svc.clone(), 4);
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
        storage_rpc::connection_cfg(),
        b_r,
        b_w,
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    let clients = rx.recv().await.unwrap().unwrap();
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
    let del = session_cli.delete(id.clone()).await.unwrap();
    assert_eq!(del.deleted, 0); // no STATE field was written, only METADATA
    assert!(session_cli.exists(id.clone()).await.unwrap()); // session survives reset

    // --- cache: store → load → miss ---
    let key = "abcd".repeat(16); // 64 hex chars
    assert_eq!(cache_cli.load(key.clone()).await.unwrap(), None);
    cache_cli
        .store(key.clone(), b"cwasm".to_vec())
        .await
        .unwrap();
    assert_eq!(
        cache_cli.load(key.clone()).await.unwrap(),
        Some(b"cwasm".to_vec())
    );

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
    // STATE and media, not just metadata: those are the two things `delete`
    // touches, so a record without them makes `deleted == 0` mean nothing.
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
    api.store(key.clone(), b"real".to_vec()).await.unwrap();

    // It cannot find out that the session is there...
    assert!(!other.exists(id.clone()).await.unwrap());
    assert_eq!(other.load(key.clone()).await.unwrap(), None);
    // ...cannot reset it out from under the applicant...
    assert_eq!(other.delete(id.clone()).await.unwrap().deleted, 0);
    // ...and its own create succeeds rather than colliding, which is the point:
    // it lands in its own partition, so api's CAS version is not touched.
    other
        .write(id.clone(), set_metadata(b"junk", None), Some(9_999_999_999))
        .await
        .unwrap();
    other.store(key.clone(), b"junk".to_vec()).await.unwrap();

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
    // The reducer state and the capture the foreign delete would have wiped.
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
    assert_eq!(api.load(key).await.unwrap(), Some(b"real".to_vec()));

    // And the 0 above was a refusal, not an empty record: the same call from the
    // caller that owns it deletes.
    assert_eq!(api.delete(id).await.unwrap().deleted, 1);
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
