//! Wire → TEE crossings. A single generic entry function
//! [`from_untrusted`] wraps any host-supplied value with the
//! **maximally-open inbound scope** `(AuthN, AuthZ, Replay)`. The
//! caller (use site) then answers each concern: with work
//! ([`trust_with`](Untrusted::trust_with)), with an argued kind
//! ([`trust`](Untrusted::trust)), or as an accepted risk
//! ([`trust_accept_risk`](Untrusted::trust_accept_risk)).
//!
//! The boundary layer doesn't carry per-channel scope decisions —
//! it just names "data crossed here", and pins the maximal scope so
//! every consumer is forced to make every concern decision **at the
//! use site** with a reason that explains the specific context of
//! that call.
//!
//! Audit grep:
//!
//!   * `boundary::inbound::from_untrusted(` — every wire → TEE crossing.
//!   * `trust(` / `trust_with(` / `trust_accept_risk(` — where each
//!     concern gets answered downstream, locally documented.
//!
//! Why a single fn (not per-channel `state_blob` / `version` / ...):
//! a per-channel fn either returns its own narrowed scope (the
//! boundary fn embeds scope decisions, hiding semantic reasoning
//! inside its body) or returns the same maximal scope (just a
//! label). The explicit-peel-at-use-site path makes every "AuthZ
//! N/A" / "AuthN closed by AEAD-open" call out in code with the
//! rationale right where the data is consumed.

use enclavid_boundary::{AuthN, AuthZ, Replay, Untrusted};

/// Maximally-open inbound scope: host-supplied data has all three
/// inbound concerns open until the use site addresses each.
///
/// `(AuthN, AuthZ, Replay)`:
///   * `AuthN` — bytes could be fabricated by the host;
///   * `AuthZ` — caller may not be authorised to receive this;
///   * `Replay` — bytes could be a stale snapshot.
pub type FromUntrusted<T> = Untrusted<T, (AuthN, AuthZ, Replay)>;

/// Wrap a host-supplied value as a [`FromUntrusted<T>`]. The
/// `channel_reason` names the channel (wire field, response slot,
/// counter, ...) — it is the audit-grep anchor for the perimeter.
/// Caller must address each of `(AuthN, AuthZ, Replay)` at the use
/// site before reaching the inner value via `into_inner`.
pub fn from_untrusted<T>(value: T) -> FromUntrusted<T> {
    Untrusted::new(value)
}
