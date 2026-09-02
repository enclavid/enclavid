//! TEE ↔ host wire perimeter — one place that names every data
//! shape crossing the boundary, with its concern scope and audit
//! reason. Anywhere outside this module that needs to wrap
//! something as `Untrusted` / `Exposed` for the wire goes
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
//!   * `hatch_client::boundary` — the wire perimeter. Owns the
//!     data shapes hatch-client knows about (state/metadata/status/
//!     principal/version/disclosure list). Migration target for
//!     readers/writers in `stores/session/*.rs`.
//!   * `api::boundary` (separate crate) — engine-emitted data that
//!     first becomes wire-bound inside the api persister. Carries
//!     `ConsentDisclosure` and other types the hatch-client layer
//!     never sees in typed form, sealing them through the api side
//!     before handing pre-vouched bytes down to hatch-client's
//!     writers. Once api crate's boundary lands, hatch-client's
//!     writer markers consume `Exposed<_, ()>` instead of raw
//!     bytes.
//!
//! Combined, the two layers cover every byte that leaves the TEE on
//! the wire. They are not every byte that leaves it: a role also
//! speaks on the serial port, and that crossing is `safe-logger`,
//! which uses the same vocabulary from the same crate. Its release
//! point is `safe_logger::line` and its grep term is `log!`.
//!
//! The vocabulary itself — `Untrusted`, `Exposed`, the concern
//! markers, `reason!` — lives in `enclavid-boundary`, below both
//! channels. Re-exported here so this stays the path callers use.

pub mod inbound;
pub mod outbound;

pub use enclavid_boundary as sentinel;
pub use enclavid_boundary::{
    AuthN, AuthZ, Covert, Exposed, Reason, Remove, Replay, Untrusted, reason,
};
pub use inbound::{FromUntrusted, from_untrusted};
pub use outbound::{ToUntrusted, to_untrusted};
