//! End-to-end remoc round-trip: serve BOTH `storage-rpc` services (backed by the
//! real redb + object_store cores) over an in-process `tokio::io::duplex`, then
//! drive them through the generated clients — exactly the api ↔ storage-CVM path
//! minus RA-TLS. Mirrors `engine-rpc`'s execute duplex test.

use std::sync::Arc;

use object_store::memory::InMemory;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::io::split;

use hatch_protocol::{
    BlobField, BlobWrite, FieldSelector, Op, ReadRequest, ScalarSlot, Slot, WriteRequest,
};
use storage_rpc::{
    CacheService, CacheServiceServerShared, SessionError, SessionStoreService,
    SessionStoreServiceServerShared, StorageClients,
};

use crate::{CacheBlobs, StorageSvc, session};

fn set_metadata(value: &[u8], expected: Option<u64>) -> WriteRequest {
    WriteRequest {
        ops: vec![Op::Blob(BlobWrite { field: BlobField::Metadata, value: value.to_vec() })],
        expected_version: expected,
    }
}

#[tokio::test]
async fn remoc_roundtrip_both_services() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(session::open(dir.path().join("s.redb").to_str().unwrap()).unwrap());
    let svc = Arc::new(StorageSvc::new(db, CacheBlobs::new(Arc::new(InMemory::new()))));

    let (a, b) = tokio::io::duplex(1024 * 1024);
    let (a_r, a_w) = split(a);
    let (b_r, b_w) = split(b);

    // Server end (the storage-CVM): serve both services, hand the clients over.
    let server = tokio::spawn(async move {
        let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
            storage_rpc::connection_cfg(),
            a_r,
            a_w,
        )
        .await
        .unwrap();
        tokio::spawn(conn);
        let (s_server, session) = SessionStoreServiceServerShared::<_, Ciborium>::new(svc.clone(), 4);
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
        .read(id.clone(), ReadRequest { fields: vec![FieldSelector::Blob(BlobField::Metadata)] })
        .await
        .unwrap();
    assert_eq!(got.version, 1);
    assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: Some(b"m1".to_vec()) }));

    let v2 = session_cli
        .write(id.clone(), set_metadata(b"m2", Some(1)), None)
        .await
        .unwrap();
    assert_eq!(v2.new_version, 2);

    // Stale CAS → VersionMismatch surfaces across the wire.
    let stale = session_cli.write(id.clone(), set_metadata(b"x", Some(1)), None).await;
    assert!(matches!(stale, Err(SessionError::VersionMismatch)));

    assert!(session_cli.exists(id.clone()).await.unwrap());
    let del = session_cli.delete(id.clone()).await.unwrap();
    assert_eq!(del.deleted, 0); // no STATE field was written, only METADATA
    assert!(session_cli.exists(id.clone()).await.unwrap()); // session survives reset

    // --- cache: store → load → miss ---
    let key = "abcd".repeat(16); // 64 hex chars
    assert_eq!(cache_cli.load(key.clone()).await.unwrap(), None);
    cache_cli.store(key.clone(), b"cwasm".to_vec()).await.unwrap();
    assert_eq!(cache_cli.load(key.clone()).await.unwrap(), Some(b"cwasm".to_vec()));

    server.abort();
}
