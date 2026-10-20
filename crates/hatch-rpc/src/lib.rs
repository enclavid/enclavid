//! `hatch-rpc` — the contract between api and the **hatch-CVM**: remote trait
//! calls (remoc `rtc`) over an RA-TLS leg.
//!
//! The hatch is the fleet's one way out. It is the only CVM with a network
//! interface, and it holds no applicant data and no seal key: it fetches what
//! api names — a consumer's registry, its key broker — and asks the operator's
//! hooks who a caller is and what it may do. api pins its measurement, so what
//! crosses here in the clear — a consumer's credential, its registry bearer —
//! reaches our own build and goes no further than the party it is for: a
//! registry over TLS, which ends inside the hatch, since api pins no bearer to
//! one written `http://`. What
//! comes back is checked where it arrives, as it always was: an artifact
//! against its pinned digest, a released key against the TEE's own.
//!
//! One service, [`RemoteHatch`]:
//!
//!   * [`authorize`](RemoteHatch::authorize) — who a consumer's request is
//!     from, and for a creation the terms its session is held to;
//!   * [`manifest`](RemoteHatch::manifest) and [`blob`](RemoteHatch::blob) —
//!     an OCI pull: the raw manifest a pinned reference names, then one blob of
//!     it streaming beside the reply;
//!   * [`kbs`](RemoteHatch::kbs) — one leg of a key broker's attestation
//!     handshake, relayed.

use remoc::codec::Ciborium;
use serde::{Deserialize, Serialize};

use fleet_stream::{StreamLen, bin};

/// The longest blob the hatch streams, in bytes: 2 GiB, above the largest a
/// composition carries — its components together are held to 1.5 GiB.
pub const MAX_BLOB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The consumer API's operations, which the hatch asks its authorization hook
/// about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientOperation {
    /// POST /api/v1/sessions, and a warmup — which spends what a creation does.
    SessionCreate,
    /// GET /api/v1/sessions/:id.
    SessionRead,
    /// GET /api/v1/sessions/:id/disclosures.
    DataRead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    /// The request's `Authorization` header, verbatim. The hatch's hook reads
    /// it; api never parses it.
    pub authorization_header: String,
    pub operation: ClientOperation,
}

/// The terms a session is held to, as the operator's limits hook gives them for
/// its consumer — each `None` where the hook gives none, or there is no hook,
/// and the role's own then. api holds each to its own ceiling and seals them in
/// at the creation, so a session keeps the terms it began with whatever the hook
/// says later.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTerms {
    /// The policy and its plugins together, in bytes.
    pub components_bytes: Option<u64>,
    /// The composition compiled, in bytes.
    pub cwasm_bytes: Option<u64>,
    /// How long the session lives, in seconds.
    pub session_ttl_secs: Option<u64>,
    /// How long one pull from a registry may take, in seconds.
    pub pull_deadline_secs: Option<u64>,
}

/// The hatch's answer to an authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Verdict {
    /// The request may go on. `principal` is who it is from — `None` where the
    /// hatch asks no hook who callers are, and every caller is the same one.
    /// `terms` are the session's for a creation, and empty otherwise.
    Allowed {
        principal: Option<String>,
        terms: SessionTerms,
    },
    /// The credential is missing, malformed or refused.
    Unauthenticated,
    /// The credential holds, but not for this operation.
    Denied,
    /// The principal has created sessions as often as it may for now; it may
    /// create one again in `retry_after_secs`.
    RateLimited { retry_after_secs: u32 },
}

/// Why the hatch gave no verdict: a hook it asks did not answer, or answered
/// with something that is not one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeError(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRequest {
    /// A pinned OCI reference, `<registry>/<repo>@sha256:<hex>`.
    pub reference: String,
    /// What the hatch sends the registry as `Authorization` — empty for none.
    #[serde(with = "serde_bytes")]
    pub registry_auth: Vec<u8>,
}

/// A manifest's bytes as the registry served them. The pinned digest is over
/// exactly these, and api recomputes it before it reads one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// One blob of a pinned reference's repository, by the digest and size its
/// verified manifest gives it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRequest {
    /// The pinned reference whose repository holds the blob.
    pub reference: String,
    /// The blob's digest, `sha256:<hex>`.
    pub digest: String,
    /// The blob's length. The hatch sends no more than this, and api reads the
    /// stream as exactly this long.
    pub size: StreamLen<MAX_BLOB_BYTES>,
    /// As in [`ManifestRequest`].
    #[serde(with = "serde_bytes")]
    pub registry_auth: Vec<u8>,
}

/// Why a pull did not happen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PullError {
    /// The registry has no such manifest, blob or repository.
    NotFound,
    /// The registry refused the bearer, or the reference is not one the hatch
    /// fetches.
    Refused,
    /// The registry did not answer as one does, or not in time.
    Failed(String),
}

/// One leg of a key broker's attestation handshake (Trustee RCAR), relayed as
/// api drives it. The broker's released key is wrapped to the TEE's ephemeral
/// key, so the hatch carries it unread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsRequest {
    /// The broker's origin, as the consumer named it at the creation.
    pub endpoint: String,
    /// `GET` or `POST`.
    pub method: String,
    /// The path on the broker, e.g. `/kbs/v0/auth`.
    pub path: String,
    /// The headers to send — the handshake's session cookie among them.
    pub headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsResponse {
    /// The broker's status for this leg.
    pub status: u16,
    /// Its `Set-Cookie` headers, which carry the handshake's session.
    pub headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

/// Why a broker leg did not happen: the broker did not answer as one does, or
/// not in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsError(pub String);

macro_rules! opaque {
    ($name:ident, $what:literal) => {
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!($what, ": {}"), self.0)
            }
        }
        impl std::error::Error for $name {}
        impl From<remoc::rtc::CallError> for $name {
            fn from(err: remoc::rtc::CallError) -> Self {
                $name(format!("hatch rpc failed: {err}"))
            }
        }
    };
}
opaque!(AuthorizeError, "authorize");
opaque!(KbsError, "kbs");

impl std::fmt::Display for PullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PullError::NotFound => f.write_str("pull: not found"),
            PullError::Refused => f.write_str("pull: refused"),
            PullError::Failed(m) => write!(f, "pull: {m}"),
        }
    }
}
impl std::error::Error for PullError {}
impl From<remoc::rtc::CallError> for PullError {
    fn from(err: remoc::rtc::CallError) -> Self {
        PullError::Failed(format!("hatch rpc failed: {err}"))
    }
}

/// What api asks of the hatch. The hatch serves one of these per api
/// connection, and sends api its client on the connection's base channel.
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

/// The client api holds, as the hatch sends it.
pub type HatchClient = RemoteHatchClient<Ciborium>;

/// The remoc connection config both ends build from, and what a role sets of it
/// — the one every fleet leg is brought up with (see `fleet_stream`).
pub use fleet_stream::{LegSettings, connection_cfg};
