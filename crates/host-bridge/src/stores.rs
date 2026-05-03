//! Concrete domain stores wrapping host-side gRPC services.
//!
//! - `SessionStore` — per-session typed fields (status, metadata,
//!   state) plus the disclosure list, via the `SessionStore` gRPC
//!   service. Status is host-visible plaintext; metadata, state, and
//!   disclosure entries are opaque to the host (encrypted TEE-side).
//!   `commit` atomically combines scalar field writes with accumulated
//!   list appends — used by /input and /connect handlers to publish a
//!   policy run's effects (state + disclosures) as one transaction.
//! - `ReportStore` — per-policy anonymous report log via the
//!   `ReportStore` gRPC service.
//!
//! Engine never talks to host-bridge directly. It accumulates pending
//! disclosure entries (`AppendDisclosure`) in its own `HostState`
//! buffer; the API handler harvests them after `runner.run` and merges
//! into the next `SessionStore::commit` call. This keeps engine pure
//! (compute, no host writes) and gives natural atomicity for state +
//! disclosures.
//!
//! All host-bridge return values are wrapped in `Untrusted<T>`. Even
//! unit-typed responses carry the wrapper so callers explicitly
//! acknowledge that "Ok" means "host claims success", not "TEE
//! verified the on-disk state matches expectation".

mod report;
mod session;

pub use report::ReportStore;
pub use session::{
    AppendDisclosure, Ctx, Disclosure, Metadata, ReadField, ReadTuple, SessionStore, SetMetadata,
    SetState, SetStatus, State, Status, WriteField,
};
