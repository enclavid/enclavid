//! Wire → TEE crossings. A single generic entry function
//! [`from_host`] wraps any host-supplied value with the
//! **maximally-open inbound scope** `(AuthN, AuthZ, Replay)`. The
//! caller (use site) then addresses each concern via a transforming
//! peel ([`trust::<X>(work)`](Untrusted::trust)) or a blanket-
//! accept ([`trust_unchecked::<X>(reason)`](
//! Untrusted::trust_unchecked)).
//!
//! The boundary layer doesn't carry per-channel scope decisions —
//! it just names "data crossed here" via the [`Reason`] token, and
//! pins the maximal scope so every consumer is forced to make every
//! concern decision **at the use site** with a reason that explains
//! the specific context of that call.
//!
//! Audit grep:
//!
//!   * `boundary::inbound::from_host(` — every wire → TEE crossing,
//!     each carrying a per-call `reason!` naming the channel.
//!   * `trust::<X,` / `trust_unchecked::<X,` — where each concern
//!     gets closed downstream, locally documented.
//!
//! Why a single fn (not per-channel `state_blob` / `version` / ...):
//! a per-channel fn either returns its own narrowed scope (the
//! boundary fn embeds scope decisions, hiding semantic reasoning
//! inside its body) or returns the same maximal scope (just a
//! label). The explicit-peel-at-use-site path makes every "AuthZ
//! N/A" / "AuthN closed by AEAD-open" call out in code with the
//! rationale right where the data is consumed.

use crate::boundary::{AuthN, AuthZ, Reason, Replay, Untrusted};

/// Maximally-open inbound scope: host-supplied data has all three
/// inbound concerns open until the use site addresses each.
///
/// `(AuthN, AuthZ, Replay)`:
///   * `AuthN` — bytes could be fabricated by the host;
///   * `AuthZ` — caller may not be authorised to receive this;
///   * `Replay` — bytes could be a stale snapshot.
pub type FromHost<T> = Untrusted<T, (AuthN, AuthZ, Replay)>;

/// Wrap a host-supplied value as a [`FromHost<T>`]. The
/// `channel_reason` names the channel (wire field, response slot,
/// counter, ...) — it is the audit-grep anchor for the perimeter.
/// Caller must address each of `(AuthN, AuthZ, Replay)` at the use
/// site before reaching the inner value via `into_inner`.
pub fn from_host<T>(value: T, channel_reason: Reason) -> FromHost<T> {
    Untrusted::new(value, channel_reason)
}
