mod auth;
pub mod boundary;
mod error;
mod kbs;
mod link;
mod registry;

pub use auth::{AuthClient, AuthVerdict, DEFAULT_AUTHORIZE_DEADLINE, Principal};
pub use error::BridgeError;
pub use link::Link;
// The contract's own types, for the requests the typed clients take and the
// terms a verdict carries.
pub use hatch_rpc::{
    AuthorizeRequest, BlobRequest, ClientOperation, HatchClient, KbsRequest, KbsResponse,
    MAX_BLOB_BYTES, ManifestRequest, SessionTerms,
};
pub use kbs::{DEFAULT_RELAY_DEADLINE, KbsClient};
pub use registry::{BlobPieces, DEFAULT_PULL_DEADLINE, RegistryClient};
