//! TEE → hatch crossings: the requests api sends the hatch, which hands them
//! on to the operator's hooks, the consumer's registry and the KBS.
//! [`to_untrusted`] opens all three outbound concerns `(AuthN, AuthZ, Covert)`,
//! and the use site answers each: with work ([`vouch_with`](Exposed::vouch_with)),
//! with an argued kind ([`vouch`](Exposed::vouch)), or as an accepted risk
//! ([`vouch_accept_risk`](Exposed::vouch_accept_risk)). It answers none of them
//! itself, because each request is answered on its own terms.
//!
//! The host is reached two other ways, and neither is this crossing. What the
//! storage-CVM keeps lands on a volume the host reads, which is
//! `storage_client::boundary`. And a leg to a pinned peer that writes nothing
//! where the host reads has the hop answer `AuthN` once: in the `boundary!`
//! declaration of api's execution-worker end, and in `to_compiler`.
//!
//! Audit grep:
//!
//!   * `boundary::outbound::to_untrusted(` — every value the host will read.
//!   * `vouch(` / `vouch_with(` / `vouch_accept_risk(` — where each concern is
//!     answered.

use enclavid_boundary::{AuthN, AuthZ, Covert, Exposed};

/// Maximally-open outbound scope: every request to the hatch has all
/// three outbound concerns open until the use site addresses each.
///
/// `(AuthN, AuthZ, Covert)`:
///   * `AuthN` — confidentiality (host may read the bytes);
///   * `AuthZ` — release authorisation (which party may receive);
///   * `Covert` — hidden bandwidth in the encoded shape.
pub type ToUntrusted<T> = Exposed<T, (AuthN, AuthZ, Covert)>;

/// Wrap a TEE-produced value the hatch will read as a [`ToUntrusted<T>`].
/// The caller addresses each of `(AuthN, AuthZ, Covert)` at the use site
/// before the value reaches the wire via `into_inner`.
pub fn to_untrusted<T>(value: T) -> ToUntrusted<T> {
    Exposed::new(value)
}
