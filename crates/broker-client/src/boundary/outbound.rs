//! TEE → wire crossings. A single generic entry function [`to_host`]
//! wraps any TEE-produced value with the **maximally-open outbound
//! scope** `(AuthN, AuthZ, Covert)`. The caller (use site) then
//! addresses each concern via a transforming peel
//! ([`vouch::<X>(work)`](Exposed::vouch)) or a blanket-vouch
//! ([`vouch_unchecked::<X>(reason)`](Exposed::vouch_unchecked)).
//!
//! The boundary layer doesn't carry per-channel scope decisions —
//! it just names "data crossed here" via the [`Reason`] token and
//! pins the maximal scope so every producer is forced to make every
//! concern decision **at the use site** with a reason that explains
//! the specific context of that release.
//!
//! Audit grep:
//!
//!   * `boundary::outbound::to_host(` — every TEE → wire crossing,
//!     each carrying a per-call `reason!` naming the channel.
//!   * `vouch::<X,` / `vouch_unchecked::<X,` — where each concern
//!     gets closed downstream, locally documented.
//!
//! Why a single fn (not per-channel `state_plaintext` / `principal`
//! / ...): a per-channel fn either returns its own narrowed scope
//! (the boundary fn embeds scope decisions, hiding semantic
//! reasoning inside its body) or returns the same maximal scope
//! (just a label). The explicit-peel-at-use-site path makes every
//! "AuthN closed by AEAD-seal" / "Covert bounded by enum
//! cardinality" call out in code with the rationale right where the
//! data is released.

use crate::boundary::{AuthN, AuthZ, Covert, Exposed, Reason};

/// Maximally-open outbound scope: every TEE → wire release has all
/// three outbound concerns open until the use site addresses each.
///
/// `(AuthN, AuthZ, Covert)`:
///   * `AuthN` — confidentiality (host may read the bytes);
///   * `AuthZ` — release authorisation (which party may receive);
///   * `Covert` — hidden bandwidth in the encoded shape.
pub type ToHost<T> = Exposed<T, (AuthN, AuthZ, Covert)>;

/// Wrap a TEE-produced value as a [`ToHost<T>`]. The
/// `channel_reason` names the channel (wire field, response slot,
/// blob slot, ...) — it is the audit-grep anchor for the perimeter.
/// Caller must address each of `(AuthN, AuthZ, Covert)` at the use
/// site before the value reaches the wire via `into_inner`.
pub fn to_host<T>(value: T, channel_reason: Reason) -> ToHost<T> {
    Exposed::new(value, channel_reason)
}
