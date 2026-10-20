//! The host perimeter as the storage-CVM's volume draws it. What a store
//! sends is kept where the host reads it, and what it reads back was kept
//! where the host could have changed it or put an older copy back. The leg
//! to the storage-CVM is attested and pinned, and that answers for the hop
//! — the record id, the version and the deadline cross on its answers (see
//! `SessionStore`). For what is kept, the volume is the host's, so the scopes
//! here are the host's: every concern open, answered at the use site.
//!
//! The same shape as `hatch_client::boundary`, and a facade of its own
//! because a scope is a property of the CHANNEL: the hatch's requests and
//! this volume are two channels to one untrusted party, and each perimeter
//! names its own.
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
