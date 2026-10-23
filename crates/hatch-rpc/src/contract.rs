//! The contract between api and the hatch, as remoc serves it.
//!
//! Nothing here is exported but what an end that serves the leg declares
//! (`RemoteHatchServes`) and the contract as its server sees it at a declared end
//! (`RemoteHatchAt`). What an end that calls it declares is read off the doors it
//! calls through, in [`crate::leg`]. The raw trait, the client and server remoc
//! writes from it, and the adapter between them are reached through `leg` alone,
//! so no crate outside this one can name them.

use fleet_stream::bin;

use crate::{
    AuthorizeError, AuthorizeRequest, BlobRequest, KbsError, KbsRequest, KbsResponse, Manifest,
    ManifestRequest, PullError, Verdict,
};

/// What api asks of the hatch. The hatch serves one of these per api
/// connection, and sends api its client on the connection's base channel.
///
/// `#[protocol]` writes what its serving end declares (`RemoteHatchServes`) and
/// how its server receives (`RemoteHatchAt`), which is the only shape
/// `serve_hatch` serves it in.
#[enclavid_boundary_macros::protocol]
#[remoc::rtc::remote]
pub trait RemoteHatch {
    /// Who a consumer's request is from, and whether it may go on — and for a
    /// creation, the terms its session is held to.
    async fn authorize(&self, req: AuthorizeRequest) -> Result<Verdict, AuthorizeError>;

    /// The raw manifest a pinned reference names.
    async fn manifest(&self, req: ManifestRequest) -> Result<Manifest, PullError>;

    /// One blob, its bytes streaming beside the reply as one message of
    /// `req.size` bytes. A stream abandoned part-way is a blob that did not
    /// arrive.
    async fn blob(&self, req: BlobRequest) -> Result<bin::Receiver, PullError>;

    /// One leg of a key broker's handshake.
    async fn kbs(&self, req: KbsRequest) -> Result<KbsResponse, KbsError>;
}
