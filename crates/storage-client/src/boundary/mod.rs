//! The host perimeter as the storage-CVM's volume draws it. What a store
//! sends is kept where the host reads it, and what it reads back was kept
//! where the host could have changed it or put an older copy back. The leg
//! to the storage-CVM is attested and pinned, and that answers for the hop
//! — the record id, the version and the deadline cross on its answers (see
//! `SessionStore`). For what is kept, the volume is the host's, so the scopes
//! here are the host's: every concern open, answered at the use site.
//!
//! A facade of its own because a scope is a property of the CHANNEL: this
//! volume is the host's, while the hatch leg reaches a CVM api pins, which hands
//! each request on to the operator's hooks, a registry or a broker. Each names
//! its own scope — the hatch leg in the `boundary!` declarations of its two ends
//! (`api::boundary`, `enclavid_hatch::boundary`).
//!
//! Reviewer grep guide:
//!
//!   * `boundary::outbound::` — every value sent to be kept.
//!   * `boundary::inbound::`  — every value read back.
//!   * `trust(` / `trust_with(` / `trust_accept_risk(` and `vouch(` /
//!     `vouch_with(` / `vouch_accept_risk(` — how each concern gets answered.

pub mod inbound;
pub mod outbound;

pub use inbound::{FromUntrusted, from_untrusted};
pub use outbound::{ToUntrusted, to_untrusted};
