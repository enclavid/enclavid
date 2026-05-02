//! Concrete stores for each kind of session data.
//! Each encapsulates its own transport + encryption requirements.
//!
//! All host-bridge return values are wrapped in `Untrusted<T>` — see
//! `GrpcBlobStore` for the rationale. Even unit-typed responses from
//! writes/deletes carry the wrapper so callers must explicitly
//! acknowledge that "Ok" means "host claims success", not "TEE
//! verified the on-disk state matches expectation".

mod disclosure;
mod metadata;
mod report;
mod state;

pub use disclosure::DisclosureStore;
pub use metadata::MetadataStore;
pub use report::ReportStore;
pub use state::StateStore;
