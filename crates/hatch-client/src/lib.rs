//! The typed clients api calls the hatch through: authorization, pulls, the key
//! broker's legs, webhooks. Each is held at an end of the hatch leg — api's, declared in
//! `api::boundary` — and takes what it sends answered for that end, handing back
//! what arrives open on what the end's declaration left open.

mod auth;
#[cfg(test)]
mod door_tests;
mod error;
mod kbs;
mod link;
mod registry;
mod webhook;

pub use auth::{AuthClient, AuthVerdict, DEFAULT_AUTHORIZE_DEADLINE, Principal};
pub use error::BridgeError;
pub use link::Link;
// The contract's own types, for the requests the typed clients take and the
// terms a verdict carries.
pub use hatch_rpc::{
    AuthorizeRequest, BlobRequest, ConsumerOperation, KbsRequest, KbsResponse, MAX_BLOB_BYTES,
    ManifestRequest, SessionTerms, WebhookAnswer, WebhookRequest,
};
pub use kbs::{DEFAULT_RELAY_DEADLINE, KbsClient};
pub use registry::{BlobPieces, DEFAULT_PULL_DEADLINE, RegistryClient};
pub use webhook::{DEFAULT_WEBHOOK_DEADLINE, WebhookClient};
