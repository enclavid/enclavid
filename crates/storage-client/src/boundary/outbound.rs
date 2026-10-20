//! Store → volume crossings: values the storage-CVM keeps where the host
//! reads them. [`to_untrusted`] opens all three outbound concerns
//! `(AuthN, AuthZ, Covert)`, and the use site answers each: with the work
//! ([`vouch_with`](Exposed::vouch_with)) — a seal, a pad, a shuffle — with an
//! argued kind and its reason ([`vouch`](Exposed::vouch)), or as an accepted
//! risk ([`vouch_accept_risk`](Exposed::vouch_accept_risk)). It answers
//! none of them itself: against a reader of every byte, what keeps a value is
//! its own seal, and each is sealed to its own key or recipient. Where a whole
//! kind of value is answered alike every time, the answer is given once, in a
//! mint named for that kind (`outbound_fields`, for the op set of a write).

use enclavid_boundary::{AuthN, AuthZ, Covert, Exposed};

/// Maximally-open outbound scope: every value sent to be kept has all
/// three outbound concerns open until the use site addresses each.
///
/// `(AuthN, AuthZ, Covert)`:
///   * `AuthN` — confidentiality (host may read the bytes);
///   * `AuthZ` — release authorisation (which party may receive);
///   * `Covert` — hidden bandwidth in the encoded shape.
pub type ToUntrusted<T> = Exposed<T, (AuthN, AuthZ, Covert)>;

/// Wrap a TEE-produced value the storage-CVM will keep as a
/// [`ToUntrusted<T>`]. The caller addresses each of `(AuthN, AuthZ, Covert)`
/// at the use site before the value reaches the wire via `into_inner`.
pub fn to_untrusted<T>(value: T) -> ToUntrusted<T> {
    Exposed::new(value)
}
