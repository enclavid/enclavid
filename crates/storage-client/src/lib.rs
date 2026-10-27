//! `storage-client` — api's client of the storage-CVM. Two stores, every seal
//! and open done here:
//!
//!   * [`SessionStore`] — a session's metadata, state, media and disclosures,
//!     each field sealed to its own key or recipient;
//!   * [`CacheStore`] — the L2 cache of compiled compositions, each blob sealed
//!     as a stream under a key of its own.
//!
//! Neither holds a connection. Both call through a [`Link`] — the storage leg
//! api keeps connected — at api's end of it, [`boundary::Storage`], declared
//! here beside the seals: what the storage-CVM keeps lands on a volume the host
//! reads, so the declaration judges the leg as the host's disk.

pub mod boundary;
mod cache;
mod error;
mod link;
#[cfg(any(test, feature = "memory"))]
pub mod memory;
mod session;

pub use cache::{BlobPieces, CacheStore};
pub use error::StoreError;
pub use link::Link;
pub use session::{
    AppendDisclosure, Ctx, DataKeys, Disclosure, DropApplicantData, Handoff, MAX_DATA_KEYS,
    Metadata, ReadField, ReadTuple, SealedState, SessionStore, SetMedia, SetMetadata, SetState,
    StateBinding, WriteField, encode_padded, lock_data_keys, lock_digest, unlock_data_keys,
};
// The ops a caller builds the fields of a write as.
pub use storage_rpc::{DisclosureOp, MediaOp, MetadataOp, Ops, StateOp};
