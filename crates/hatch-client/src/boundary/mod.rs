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
//! This module is ONE perimeter, not the only one. It owns the
//! hatch wire — the data shapes hatch-client knows about (state /
//! metadata / status / principal / version / disclosure list) — and
//! it owns the concerns that crossing raises, which is why the
//! markers it clears are re-exported here.
//!
//! A role that speaks on other channels declares those itself,
//! against the same vocabulary taken from `enclavid-boundary`
//! directly: api judges its execution-worker leg `Asserted` in
//! `api::applicant::callbacks`, and the serial port is `safe-logger`
//! (release point `safe_logger::line`, grep term `log!`). A scope is
//! a property of the CHANNEL, not of the bytes, so each perimeter
//! names its own and none of them belong in this one's surface.
//!
//! The vocabulary itself — `Untrusted`, `Exposed`, the concern markers, `reason!`
//! — lives in `enclavid-boundary`, below both channels, and is NOT re-exported
//! from here. One name, one path: a word that means the same thing on every
//! channel should not arrive through whichever crate a caller happened to be
//! holding, and a second path is how a marker for one leg ends up looking like it
//! belongs to another. What this module owns is the hatch's own facades —
//! `from_untrusted` / `to_untrusted` / `outbound_session_id` — and the answers
//! that crossing raises.

pub mod inbound;
pub mod outbound;

pub use inbound::{FromUntrusted, from_untrusted};
pub use outbound::{ToUntrusted, to_untrusted};
