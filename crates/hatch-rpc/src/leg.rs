//! Both ends of the hatch leg, and the doors on the calling end.
//!
//! The client and server remoc writes from the contract are not exported, so no
//! crate outside this one can name either. What is left to reach for is
//! [`HatchLeg`], whose doors take what an end answered and hand back what arrives
//! open on what the end left open, and [`serve_hatch`], which serves the contract
//! as its server sees it at a declared end.
//!
//! What stays with each role is WHO: both take a byte stream that is already
//! attested. The dial, the TLS and the measurement policy are the caller's.

use std::marker::PhantomData;
use std::sync::Arc;

use enclavid_boundary::{Exposed, Receives, Untrusted, inbound};
use fleet_stream::{LegSettings, StreamLen, bin, connection_cfg, leg_end};
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

use crate::contract::{
    RemoteHatch, RemoteHatchAdapter, RemoteHatchAt, RemoteHatchCalls, RemoteHatchClient,
    RemoteHatchServerShared, RemoteHatchServes,
};
use crate::{
    AuthorizeError, AuthorizeRequest, BlobRequest, KbsError, KbsRequest, KbsResponse,
    MAX_BLOB_BYTES, Manifest, ManifestRequest, PullError, Verdict,
};

type Client = RemoteHatchClient<Ciborium>;

/// Why the leg did not come up, or stopped being served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegError {
    /// remoc could not bring the multiplexed connection up over the stream.
    Rpc,
    /// The connection came up but the hatch's client did not cross it.
    Clients,
    /// The peer closed before sending its client.
    Closed,
    /// The server loop ended in failure.
    Serve,
}

impl std::fmt::Display for LegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self {
            LegError::Rpc => "rpc connect",
            LegError::Clients => "client exchange",
            LegError::Closed => "peer closed before sending its client",
            LegError::Serve => "serve loop",
        };
        write!(f, "{what} failed")
    }
}
impl std::error::Error for LegError {}

/// The hatch leg, held at end `B` — the only handle on it outside this crate.
///
/// What a caller must have answered before a request crosses, and what comes back
/// open, are stated by `B`'s declaration, the one place the caller says how it
/// judges this leg. A failure comes back as it is: `B`'s declaration answered the
/// hatch's errors in full.
///
/// Nothing else outside this crate can call the hatch, or serve it raw: the
/// generated client, the generated server and the contract itself are not names
/// another crate can use.
///
/// ```compile_fail
/// use hatch_rpc::RemoteHatchClient;
/// ```
///
/// ```compile_fail
/// use hatch_rpc::RemoteHatchServerShared;
/// ```
///
/// ```compile_fail
/// use hatch_rpc::RemoteHatch;
/// ```
///
/// What an end declares, and the contract as its server sees it there, are:
///
/// ```
/// use hatch_rpc::{RemoteHatchAt, RemoteHatchCalls, RemoteHatchServes};
/// ```
pub struct HatchLeg<B> {
    client: Client,
    _end: PhantomData<fn() -> B>,
}

impl<B: RemoteHatchCalls> HatchLeg<B> {
    /// Who a consumer's request is from, and whether it may go on.
    ///
    /// `req` arrives answered — `Exposed<_, (), B>` is reachable only through
    /// `B`'s declaration and the answers its sender gave after it.
    pub async fn authorize(
        &self,
        req: Exposed<AuthorizeRequest, (), B>,
    ) -> Result<Untrusted<Verdict, <B as Receives<Verdict>>::Open, B>, AuthorizeError> {
        self.client
            .authorize(req.into_inner())
            .await
            .map(inbound::<B, _>)
    }

    /// The raw manifest a pinned reference names.
    pub async fn manifest(
        &self,
        req: Exposed<ManifestRequest, (), B>,
    ) -> Result<Untrusted<Manifest, <B as Receives<Manifest>>::Open, B>, PullError> {
        self.client
            .manifest(req.into_inner())
            .await
            .map(inbound::<B, _>)
    }

    /// One blob's stream, and the length its request named, which the stream is
    /// held to as it is read: one message of exactly that many bytes, or a blob
    /// that did not arrive.
    pub async fn blob(
        &self,
        req: Exposed<BlobRequest, (), B>,
    ) -> Result<
        (
            Untrusted<bin::Receiver, <B as Receives<bin::Receiver>>::Open, B>,
            StreamLen<MAX_BLOB_BYTES>,
        ),
        PullError,
    > {
        let req = req.into_inner();
        let size = req.size;
        let body = self.client.blob(req).await?;
        Ok((inbound::<B, _>(body), size))
    }

    /// One leg of a key broker's handshake.
    pub async fn kbs(
        &self,
        req: Exposed<KbsRequest, (), B>,
    ) -> Result<Untrusted<KbsResponse, <B as Receives<KbsResponse>>::Open, B>, KbsError> {
        self.client.kbs(req.into_inner()).await.map(inbound::<B, _>)
    }
}

/// Bring the leg up on an already-attested stream and take the hatch's client —
/// api's half.
///
/// Returns the leg, and a handle that finishes when the leg is over: its
/// connection ended or its request channel closed (`fleet_stream::leg_end`). `B`
/// is the caller's end of the leg, and `leg` what the caller sets of its end of
/// the connection.
pub async fn connect_hatch<B, R, W>(
    read: R,
    write: W,
    leg: &LegSettings,
) -> Result<(HatchLeg<B>, JoinHandle<()>), LegError>
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Client, Client, Ciborium>(connection_cfg(leg), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let client = rx
        .recv()
        .await
        .map_err(|_| LegError::Clients)?
        .ok_or(LegError::Closed)?;
    let ended = leg_end(driver, remoc::rtc::Client::closed(&client));
    Ok((
        HatchLeg {
            client,
            _end: PhantomData,
        },
        ended,
    ))
}

/// Serve the contract on an already-attested stream until the peer goes away —
/// the hatch's half.
///
/// Takes the contract as its server sees it at end `B`, a [`RemoteHatchAt`],
/// never the raw trait: the raw server is not exported, so there is no unwrapped
/// shape to serve. `request_buffer` is how many calls may wait to be taken, not
/// how many run at once — remoc spawns a handler for each call it takes — and
/// `leg` what the role sets of its end of the connection.
pub async fn serve_hatch<B, S, R, W>(
    read: R,
    write: W,
    service: S,
    request_buffer: usize,
    leg: &LegSettings,
) -> Result<(), LegError>
where
    B: RemoteHatchServes + 'static,
    S: RemoteHatchAt<B> + Send + Sync + 'static,
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, Client, Client, Ciborium>(connection_cfg(leg), read, write)
            .await
            .map_err(|_| LegError::Rpc)?;
    tokio::spawn(conn);
    let (server, client) = RemoteHatchServerShared::<_, Ciborium>::new(
        Arc::new(RemoteHatchAdapter::<S, B>::new(service)),
        request_buffer,
    );
    tx.send(client).await.map_err(|_| LegError::Clients)?;
    server.serve(true).await.map_err(|_| LegError::Serve)
}
