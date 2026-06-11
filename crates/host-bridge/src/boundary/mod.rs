//! TEE ↔ host wire perimeter — one place that names every data
//! shape crossing the boundary, with its concern scope and audit
//! reason. Anywhere outside this module that needs to wrap
//! something as `Untrusted` / `Exposed` for the gRPC wire goes
//! through a function here.
//!
//! ```text
//!                  +--- boundary::outbound ---+
//!                  | one fn per data shape    |
//!  trusted code -->| typed → Exposed<T, S>    | --> SessionStore::write
//!                  | S declared per channel   |     wire send
//!                  +--------------------------+
//!
//!                  +--- boundary::inbound ----+
//!                  | one fn per data shape    |
//!  wire bytes ---->| raw → Untrusted<T, S>    | --> typed reader logic
//!                  | S declared per channel   |     decrypt / decode
//!                  +--------------------------+
//! ```
//!
//! Reviewer grep guide:
//!
//!   * `boundary::outbound::` — every TEE → wire crossing.
//!   * `boundary::inbound::`  — every wire → TEE crossing.
//!   * `trust::<X,` / `trust_unchecked::<X,` — how each inbound
//!     concern actually gets cleared by the caller (cryptographic
//!     check, application predicate, blanket-trust with reason).
//!   * `vouch::<X,` / `vouch_unchecked::<X,` — how each outbound
//!     concern gets closed (seal, sanitise, blanket-vouch).
//!
//! Two perimeters, by design:
//!
//!   * `host_bridge::boundary` — the gRPC-wire perimeter. Owns the
//!     data shapes host-bridge knows about (state/metadata/status/
//!     principal/version/disclosure list). Migration target for
//!     readers/writers in `stores/session/*.rs`.
//!   * `api::boundary` (separate crate) — engine-emitted data that
//!     first becomes wire-bound inside the api persister. Carries
//!     `ConsentDisclosure` and other types the host-bridge layer
//!     never sees in typed form, sealing them through the api side
//!     before handing pre-vouched bytes down to host-bridge's
//!     writers. Once api crate's boundary lands, host-bridge's
//!     writer markers consume `Exposed<_, ()>` instead of raw
//!     bytes.
//!
//! Combined, the two layers cover every byte that leaves the TEE.

pub mod inbound;
pub mod outbound;
pub mod sentinel;

pub use sentinel::{
    AuthN, AuthZ, Covert, Exposed, Reason, Remove, Replay, Untrusted,
};
pub use inbound::{FromHost, from_host};
pub use outbound::{ToHost, to_host};
// `reason!` is a macro_export'd top-level macro — re-export the
// stable path so callers can write `host_bridge::reason!(...)` if
// they prefer the boundary-scoped name. The crate-root alias
// (`enclavid_host_bridge::reason!`) keeps working via macro_export.
