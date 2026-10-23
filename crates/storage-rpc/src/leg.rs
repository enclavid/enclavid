//! Both ends of the storage leg, and the doors on the calling end.
//!
//! The clients and servers remoc writes from the contracts are not exported, so
//! no crate outside this one can name them. What is left to reach for is
//! [`StorageLeg`], whose doors take what an end answered and hand back what
//! arrives open on what the end left open, and [`serve_storage`], which serves
//! both contracts as their server sees them at a declared end.
//!
//! What stays with each role is WHO: both take a byte stream that is already
//! attested. The dial, the TLS and the measurement policy are the caller's.

use std::marker::PhantomData;
use std::sync::Arc;

use enclavid_boundary::{Exposed, Receives, Untrusted, inbound};
use fleet_stream::{LegSettings, bin, connection_cfg, leg_end};
use remoc::codec::Ciborium;
use remoc::rtc::{Client as _, ServerShared};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

use crate::contract::{
    RemoteCache, RemoteCacheAdapter, RemoteCacheAt, RemoteCacheClient, RemoteCacheServerShared,
    RemoteCacheServes, RemoteSessionStore, RemoteSessionStoreAdapter, RemoteSessionStoreAt,
    RemoteSessionStoreClient, RemoteSessionStoreServerShared, RemoteSessionStoreServes,
    StorageClients,
};
use crate::{
    BlobName, BlobStream, CacheBlob, CacheError, Dropped, Expected, Fields, Kept, Ops, ReadRequest,
    ReadResponse, RecordName, SessionError, Slot, Version, WriteRequest, WriteResponse,
};

/// Why the leg did not come up, or stopped being served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegError {
    /// remoc could not bring the multiplexed connection up over the stream.
    Rpc,
    /// The connection came up but the store's clients did not cross it.
    Clients,
    /// The peer closed before sending its clients.
    Closed,
    /// The server loop ended in failure.
    Serve,
}

impl std::fmt::Display for LegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self {
            LegError::Rpc => "rpc connect",
            LegError::Clients => "client exchange",
            LegError::Closed => "peer closed before sending its clients",
            LegError::Serve => "serve loop",
        };
        write!(f, "{what} failed")
    }
}
impl std::error::Error for LegError {}

/// The storage leg, held at end `B` — the only handle on it outside this crate.
///
/// What a caller must have answered before a request crosses, and what comes back
/// open, are stated by `B`'s declaration, the one place the caller says how it
/// judges this leg. A failure comes back as it is: `B`'s declaration answered the
/// store's errors in full.
///
/// Nothing else outside this crate can call the store, or serve it raw: the
/// generated clients, the generated servers and the contracts themselves are not
/// names another crate can use.
///
/// ```compile_fail
/// use storage_rpc::RemoteSessionStoreClient;
/// ```
///
/// ```compile_fail
/// use storage_rpc::RemoteCacheServerShared;
/// ```
///
/// ```compile_fail
/// use storage_rpc::RemoteSessionStore;
/// ```
///
/// What an end declares, and the contracts as their server sees them there, are:
///
/// ```
/// use storage_rpc::{RemoteCacheAt, RemoteSessionStoreCalls, RemoteSessionStoreServes};
/// ```
pub struct StorageLeg<B> {
    session: RemoteSessionStoreClient<Ciborium>,
    cache: RemoteCacheClient<Ciborium>,
    _end: PhantomData<fn() -> B>,
}

/// The session store's doors: what an end that calls it declares
/// (`RemoteSessionStoreCalls`) is what these take and hand back.
#[enclavid_boundary_macros::calls(crate::contract::RemoteSessionStore)]
impl<B> StorageLeg<B> {
    /// Read `fields` of the record `record` names, and its version. Each slot and
    /// the version come back open on what `B` left open on them: the response is
    /// taken apart here, so each part is judged on its own grounds.
    ///
    /// `record` and `fields` arrive answered — `Exposed<_, (), B>` is reachable
    /// only through `B`'s declaration and the answers its sender gave after it —
    /// and the request that crosses is built of them here.
    #[allow(clippy::type_complexity)]
    pub async fn read(
        &self,
        record: Exposed<RecordName, (), B>,
        fields: Exposed<Fields<B>, (), B>,
    ) -> Result<
        (
            Vec<Untrusted<Slot, <B as Receives<Slot>>::Open, B>>,
            Untrusted<Version, <B as Receives<Version>>::Open, B>,
        ),
        SessionError,
    > {
        let req = ReadRequest {
            fields: fields.into_inner().into_selectors(),
        };
        let ReadResponse { slots, version } = self.session.read(record.into_inner(), req).await?;
        Ok((
            slots.into_iter().map(inbound::<B, _>).collect(),
            inbound::<B, _>(Version(version)),
        ))
    }

    /// Write `ops` to the record they were made for, if it is as `expected` says;
    /// its new version comes back open on what `B` left open on it. Both arrive
    /// answered, and the request that crosses is built of them here. A request
    /// past what one call carries is refused as [`SessionError::TooLarge`]
    /// before it is sent.
    pub async fn write(
        &self,
        expected: Exposed<Expected, (), B>,
        ops: Exposed<Ops<B>, (), B>,
    ) -> Result<Untrusted<Version, <B as Receives<Version>>::Open, B>, SessionError> {
        let (expected_version, deadline_unix_secs) = match expected.into_inner() {
            Expected::Absent { deadline_unix_secs } => (None, deadline_unix_secs),
            Expected::Version(version) => (Some(version), None),
        };
        let (record, ops) = ops.into_inner().into_parts();
        let req = WriteRequest {
            ops,
            expected_version,
            deadline_unix_secs,
        };
        // remoc sends a call in the background, after handing it over has
        // already returned, so it has no way to tell this one call that it is
        // too large: it closes the request channel instead, for every caller on
        // this leg. A write that would not fit is refused here, and only it
        // fails.
        if !fits_one_call(&record, &req) {
            return Err(SessionError::TooLarge);
        }
        let WriteResponse { new_version } = self.session.write(record, req).await?;
        Ok(inbound::<B, _>(Version(new_version)))
    }
}

/// What a call wraps its arguments in on the wire, beside them: the method, the
/// reply's port, the framing.
const CALL_HEADROOM: usize = 64 * 1024;

/// Whether a write of `req` to `record` fits the one remoc item its call crosses
/// as: both encoded in the codec the leg carries them in, into a counter.
fn fits_one_call(record: &RecordName, req: &WriteRequest) -> bool {
    struct Counted(usize);
    impl std::io::Write for Counted {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counted = Counted(0);
    ciborium::into_writer(&(record, req), &mut counted).is_ok()
        && counted.0 + CALL_HEADROOM <= remoc::rch::DEFAULT_MAX_ITEM_SIZE
}

/// The cache's doors: what an end that calls it declares (`RemoteCacheCalls`) is
/// what these take and hand back.
#[enclavid_boundary_macros::calls(crate::contract::RemoteCache)]
impl<B> StorageLeg<B> {
    /// Keep the blob `stream` carries under `blob`, its pieces streamed beside
    /// the call and written while it is awaited. A source that fails abandons
    /// the blob, and the store keeps what was there.
    pub async fn store(
        &self,
        blob: Exposed<BlobName, (), B>,
        stream: Exposed<BlobStream, (), B>,
    ) -> Result<Untrusted<Kept, <B as Receives<Kept>>::Open, B>, CacheError> {
        let BlobStream { length, pieces } = stream.into_inner();
        let (tx, body) = bin::channel();
        let mut call = std::pin::pin!(
            self.cache
                .store(blob.into_inner(), CacheBlob { length, body })
        );
        // The store answers once the blob has arrived, so the pieces are written
        // while it is awaited. One that fails abandons the blob, and the store
        // answers that; a store that answers first has stopped reading.
        let reply = tokio::select! {
            reply = &mut call => reply,
            _ = fleet_stream::send_from(tx, pieces) => call.await,
        };
        reply.map(inbound::<B, _>)
    }

    /// The blob kept under `blob`, streaming beside the reply, or `None` — open
    /// on what `B` left open on it.
    pub async fn load(
        &self,
        blob: Exposed<BlobName, (), B>,
    ) -> Result<Untrusted<Option<CacheBlob>, <B as Receives<Option<CacheBlob>>>::Open, B>, CacheError>
    {
        self.cache
            .load(blob.into_inner())
            .await
            .map(inbound::<B, _>)
    }

    /// Drop the blob kept under `blob`, if there is one.
    pub async fn remove(
        &self,
        blob: Exposed<BlobName, (), B>,
    ) -> Result<Untrusted<Dropped, <B as Receives<Dropped>>::Open, B>, CacheError> {
        self.cache
            .remove(blob.into_inner())
            .await
            .map(inbound::<B, _>)
    }
}

/// Bring the leg up on an already-attested stream and take both of the store's
/// clients — api's half.
///
/// Returns the leg, and a handle that finishes when the leg is over: its
/// connection ended, or either client's request channel closed
/// (`fleet_stream::leg_end`) — the two are installed and torn down together. `B`
/// is the caller's end of the leg, and `leg` what the caller sets of its end of
/// the connection.
pub async fn connect_storage<B, R, W>(
    read: R,
    write: W,
    leg: &LegSettings,
) -> Result<(StorageLeg<B>, JoinHandle<()>), LegError>
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
        connection_cfg(leg),
        read,
        write,
    )
    .await
    .map_err(|_| LegError::Rpc)?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let StorageClients { session, cache } = rx
        .recv()
        .await
        .map_err(|_| LegError::Clients)?
        .ok_or(LegError::Closed)?;
    let (session_closed, cache_closed) = (session.closed(), cache.closed());
    let ended = leg_end(driver, async move {
        tokio::select! {
            () = session_closed => {}
            () = cache_closed => {}
        }
    });
    Ok((
        StorageLeg {
            session,
            cache,
            _end: PhantomData,
        },
        ended,
    ))
}

/// Serve both contracts on an already-attested stream until the peer goes away —
/// the storage-CVM's half.
///
/// Takes the contracts as their server sees them at end `B` — a
/// [`RemoteSessionStoreAt`] and a [`RemoteCacheAt`] — never the raw traits: the
/// raw servers are not exported, so there is no unwrapped shape to serve.
/// `service` is per connection, so a role that partitions by who is calling
/// builds one per accept. `session_buffer` / `cache_buffer` are how many calls
/// may wait to be taken on each, not how many run at once, and `leg` what the
/// role sets of its end of the connection.
pub async fn serve_storage<B, S, R, W>(
    read: R,
    write: W,
    service: S,
    session_buffer: usize,
    cache_buffer: usize,
    leg: &LegSettings,
) -> Result<(), LegError>
where
    B: RemoteSessionStoreServes + RemoteCacheServes + 'static,
    S: RemoteSessionStoreAt<B> + RemoteCacheAt<B> + Send + Sync + 'static,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
        connection_cfg(leg),
        read,
        write,
    )
    .await
    .map_err(|_| LegError::Rpc)?;
    tokio::spawn(conn);

    let service = Arc::new(service);
    let (session_server, session) = RemoteSessionStoreServerShared::<_, Ciborium>::new(
        Arc::new(RemoteSessionStoreAdapter::<_, B>::new(service.clone())),
        session_buffer,
    );
    let (cache_server, cache) = RemoteCacheServerShared::<_, Ciborium>::new(
        Arc::new(RemoteCacheAdapter::<_, B>::new(service)),
        cache_buffer,
    );
    tx.send(StorageClients { session, cache })
        .await
        .map_err(|_| LegError::Clients)?;

    // Both services run for the lifetime of the connection: one on a task, the
    // other awaited here.
    tokio::spawn(async move {
        let _ = session_server.serve(true).await;
    });
    cache_server.serve(true).await.map_err(|_| LegError::Serve)
}
