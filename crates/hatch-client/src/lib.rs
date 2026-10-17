mod auth;
pub mod boundary;
mod error;
mod kbs;
mod kds;
mod registry;
mod transport;

pub use auth::{AuthClient, AuthVerdict, DEFAULT_AUTHORIZE_DEADLINE, Principal};
pub use error::BridgeError;
pub use transport::HatchClient;
// Wire DTO re-exports — the operation selector and the OCI pull
// response now come from the shared `hatch-protocol` crate.
pub use hatch_protocol::{AuthorizeRequest, BlobRequest, ClientOperation, ManifestRequest};
pub use hatch_protocol::{KbsRelayRequest, KbsRelayResponse};
pub use hatch_protocol::{VcekRequest, VcekResponse};
pub use kbs::{DEFAULT_RELAY_DEADLINE, KbsClient};
pub use kds::{DEFAULT_VCEK_DEADLINE, KdsClient};
pub use registry::{BlobPieces, DEFAULT_PULL_DEADLINE, RegistryClient};
