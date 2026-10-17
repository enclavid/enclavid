//! `storage-client` — api's client of the storage-CVM. Two stores, every seal
//! and open done here:
//!
//!   * [`SessionStore`] — a session's metadata, state, media and disclosures,
//!     each field sealed to its own key or recipient;
//!   * [`CacheStore`] — the L2 cache of compiled compositions, each blob sealed
//!     as a stream under a key of its own.
//!
//! Neither holds a connection. A [`SessionBackend`] / [`CacheBackend`] moves
//! what they have already sealed, and api implements both over its storage
//! leg. What the storage-CVM keeps lands on a volume the host reads, so what
//! the stores send and read back crosses the perimeter in [`boundary`].

mod backend;
pub mod boundary;
mod cache;
mod error;
mod session;

pub use backend::{BlobPieces, CacheBackend, SessionBackend};
pub use cache::CacheStore;
pub use error::StoreError;
pub use session::{
    AppendDisclosure, Ctx, Disclosure, DropApplicantData, Metadata, ReadField, ReadTuple,
    SessionStore, SetMedia, SetMetadata, SetState, State, WriteField, encode_padded,
    outbound_fields,
};
