//! TEE ↔ hatch wire perimeter — one place that names every data
//! shape crossing to the hatch and back, with its concern scope and
//! audit reason. Anywhere outside this module that needs to wrap
//! something as `Untrusted` / `Exposed` for the hatch wire goes
//! through a function here.
//!
//! ```text
//!                  +--- boundary::outbound ---+
//!                  | one fn per data shape    |
//!  trusted code -->| typed → Exposed<T, S>    | --> wire send
//!                  | S declared per channel   |
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
//!   * `trust(` / `trust_with(` / `trust_accept_risk(` — how each inbound
//!     concern is answered by the caller: an argued kind, work (a
//!     cryptographic check, an application predicate), or an accepted risk.
//!   * `vouch(` / `vouch_with(` / `vouch_accept_risk(` — how each outbound
//!     concern is answered (seal, sanitise, argued kind, accepted risk).
//!
//! This module is ONE perimeter, not the only one. It owns the hatch's
//! requests and replies, and the concerns that crossing raises.
//!
//! A role that speaks on other channels declares those itself,
//! against the same vocabulary taken from `enclavid-boundary`
//! directly: what the storage-CVM keeps is `storage_client::boundary`,
//! api's end of the execution-worker leg is declared with `boundary!`
//! in `api::boundary`, its compile leg opens with `to_compiler`, and
//! the serial port is `safe-logger`
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
//! `from_untrusted` / `to_untrusted` — and the answers that crossing raises.

pub mod inbound;
pub mod outbound;

pub use inbound::{FromUntrusted, from_untrusted};
pub use outbound::{ToUntrusted, to_untrusted};
