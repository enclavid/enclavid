//! The `storage-cvm` deployable: the trusted storage node. LISTENS for the
//! orchestrator (api) over mutual RA-TLS and serves BOTH `storage-rpc` services
//! — `SessionStoreService` (one SQLite file per session) + `CacheService`
//! (object_store) — on one remoc connection. Started by INFRASTRUCTURE, exactly
//! like the hatch and the engine workers.
//!
//! **Blind.** It holds no `tee_seal_key` and no applicant token; every payload is
//! already AEAD-sealed TEE-side. RA-TLS proves the peer is the attested api and
//! hides the access pattern + key from the untrusted host; the sealed payload
//! means even a storage-CVM compromise leaks only ciphertext.
//!
//! Transport TODAY: a plain TCP listener (dev) wrapped in RA-TLS; Plan-A swaps
//! the TCP dial for the host vsock-relay rendezvous (shared fleet item, not here).

use std::sync::Arc;
use std::time::Duration;

use object_store::local::LocalFileSystem;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::net::{TcpListener, TcpStream};

use enclavid_storage::{CacheBlobs, SessionStore, StorageSvc, now_unix};
use storage_rpc::{CacheServiceServerShared, SessionStoreServiceServerShared, StorageClients};

/// How many expired sessions the sweeper purges per tick (bounds one sweep pass).
const SWEEP_BATCH: usize = 1024;
/// Concurrent in-flight calls each service handles.
const SESSION_CONCURRENCY: usize = 16;
const CACHE_CONCURRENCY: usize = 8;

#[tokio::main]
async fn main() {
    // Explicit config; fail loud if unset (minimal-defaults).
    let listen = std::env::var("ENCLAVID_STORAGE_LISTEN").expect(
        "ENCLAVID_STORAGE_LISTEN not set (listen address for the storage-CVM, e.g. 0.0.0.0:9100)",
    );
    let sessions_dir = std::env::var("ENCLAVID_STORAGE_SESSIONS_DIR").expect(
        "ENCLAVID_STORAGE_SESSIONS_DIR not set (directory for the session store: \
         per-session SQLite files under blobs/ + the deadline index meta.sqlite)",
    );
    let cache_dir = std::env::var("ENCLAVID_STORAGE_CACHE_DIR")
        .expect("ENCLAVID_STORAGE_CACHE_DIR not set (L2 cwasm cache directory)");
    let sweep_secs: u64 = std::env::var("ENCLAVID_STORAGE_SWEEP_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let sessions = Arc::new(
        SessionStore::open(&sessions_dir)
            .unwrap_or_else(|e| panic!("storage-cvm: open session store {sessions_dir}: {e}")),
    );

    std::fs::create_dir_all(&cache_dir)
        .unwrap_or_else(|e| panic!("storage-cvm: create cache dir {cache_dir}: {e}"));
    let store = Arc::new(
        LocalFileSystem::new_with_prefix(&cache_dir)
            .unwrap_or_else(|e| panic!("storage-cvm: object_store at {cache_dir}: {e}")),
    );
    let svc = Arc::new(StorageSvc::new(sessions.clone(), CacheBlobs::new(store)));

    // TTL sweeper — enforce per-session deadlines INSIDE the trust boundary (the
    // host STATUS byte is gone). Clock is host-skewable → availability-only.
    {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(sweep_secs);
            loop {
                tokio::time::sleep(interval).await;
                let sessions = sessions.clone();
                match tokio::task::spawn_blocking(move || {
                    sessions.sweep_once(now_unix(), SWEEP_BATCH)
                })
                .await
                {
                    Ok(Ok(n)) if n > 0 => eprintln!("storage-cvm: swept {n} expired session(s)"),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => eprintln!("storage-cvm: sweep error: {e}"),
                    Err(e) => eprintln!("storage-cvm: sweep join error: {e}"),
                }
            }
        });
    }

    let listener = TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| panic!("storage-cvm: bind {listen}: {e}"));
    eprintln!(
        "storage-cvm: listening on {listen}, sessions={sessions_dir}, cache={cache_dir}, sweep={sweep_secs}s"
    );

    // Mutual RA-TLS acceptor (minted once at boot): every accepted api connection
    // is an attested TLS server that also REQUIRES the api's attested cert.
    // This build attests with a software identity the whole dev fleet shares, and
    // pins that same identity: it proves the peer links this source tree, nothing
    // about where the peer runs.
    let ratls = tokio_rustls::TlsAcceptor::from(Arc::new(
        enclavid_ra_tls::server_config(
            Arc::new(enclavid_attestation::MockAttestor::dev_fleet()),
            enclavid_ra_tls::MeasurementPolicy::Pinned(vec![
                enclavid_attestation::DEV_FLEET_MEASUREMENT.to_string(),
            ]),
        )
        .unwrap_or_else(|e| panic!("storage-cvm: RA-TLS server config: {e}")),
    ));

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let svc = svc.clone();
                let ratls = ratls.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(stream, ratls, svc).await {
                        eprintln!("storage-cvm: connection from {peer} ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("storage-cvm: accept failed: {e}"),
        }
    }
}

/// RA-TLS-accept one api connection, frame it with remoc, and serve BOTH services
/// (their clients sent to the api on the base channel).
async fn serve_conn(
    stream: TcpStream,
    ratls: tokio_rustls::TlsAcceptor,
    svc: Arc<StorageSvc>,
) -> Result<(), String> {
    let tls = ratls
        .accept(stream)
        .await
        .map_err(|e| format!("RA-TLS accept: {e}"))?;
    let (read, write) = tokio::io::split(tls);
    let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
        storage_rpc::connection_cfg(),
        read,
        write,
    )
    .await
    .map_err(|e| format!("remoc connect: {e}"))?;
    tokio::spawn(conn);

    let (session_server, session) =
        SessionStoreServiceServerShared::<_, Ciborium>::new(svc.clone(), SESSION_CONCURRENCY);
    let (cache_server, cache) =
        CacheServiceServerShared::<_, Ciborium>::new(svc.clone(), CACHE_CONCURRENCY);
    tx.send(StorageClients { session, cache })
        .await
        .map_err(|e| format!("send service clients: {e}"))?;

    // Both services run for the lifetime of the connection; drive one on a task
    // and await the other.
    tokio::spawn(async move {
        let _ = session_server.serve(true).await;
    });
    cache_server
        .serve(true)
        .await
        .map_err(|e| format!("serve: {e}"))?;
    Ok(())
}
