mod auth;
pub mod boundary;
mod cache;
mod error;
mod kbs;
mod registry;
mod session;
mod transport;

// Sealed session-domain types — hand-written serde structs, CBOR at
// rest. No protobuf anywhere in the project.
mod domain;

pub use auth::{AuthClient, AuthVerdict, Principal};
pub use cache::CacheStore;
// Boundary-sentinel re-exports — Untrusted/Exposed/concern markers
// live in `boundary::sentinel` after the untrusted-crate fold-in.
// The old crate-root path is preserved so external consumers don't
// need to update import paths.
pub use boundary::{AuthN, AuthZ, Covert, Exposed, Reason, Replay, Untrusted};
pub use boundary::outbound::public_session_id;
pub use error::BridgeError;
pub use transport::BrokerClient;
// Wire DTO re-exports — the operation selector and the OCI pull
// response now come from the shared `broker-protocol` crate.
pub use broker_protocol::{AuthorizeRequest, ClientOperation, PullRequest};
pub use broker_protocol::PullResponse as RegistryPullResponse;
pub use broker_protocol::{KbsRelayRequest, KbsRelayResponse};
pub use kbs::KbsClient;
pub use registry::RegistryClient;
pub use domain::{
    Action, CameraFacing, CaptureGuide, CaptureStep, Client, ClientAccess, Clip, Decision,
    DisplayField, Event, GuideNone, GuideOval, GuideRect, KbsKey, Key, Localized, MediaResult,
    MediaSpec, PluginPin, Prompt, SessionMetadata, SessionState, SessionStatus, Translation,
    capture_guide,
};
// Disclosure carried by `Prompt::ConsentDisclosure`. Re-exported under
// a qualified name so it doesn't collide with the session-store
// `session::Disclosure` wire type below.
pub use domain::Disclosure as PromptDisclosure;
pub use session::{
    AppendDisclosure, Ctx, Disclosure, Metadata, ReadField, ReadTuple, SEALED_STATE_PLAINTEXT_BYTES,
    SessionStore, SetMedia, SetMetadata, SetPrincipal, SetState, SetStatus, State, Status,
    WriteField, encode_padded,
};
