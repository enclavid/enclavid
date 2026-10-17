//! TEE → hatch crossings: the requests api sends a host process that reads
//! every byte. [`to_untrusted`] opens all three outbound concerns
//! `(AuthN, AuthZ, Covert)`, and the use site answers each: a peel that does
//! the work ([`vouch::<X>(work)`](Exposed::vouch)) or a vouch with its reason
//! ([`vouch_unchecked::<X>(reason)`](Exposed::vouch_unchecked)). It answers
//! none of them itself, because each request is answered on its own terms.
//!
//! The host is reached two other ways, and neither is this crossing. What the
//! storage-CVM keeps lands on a volume the host reads, which is
//! `storage_client::boundary`. And a leg to a pinned peer that writes nothing
//! where the host reads has the hop answer `AuthN` once, which is `to_worker`
//! and `to_compiler` in api.
//!
//! Audit grep:
//!
//!   * `boundary::outbound::to_untrusted(` — every value the host will read.
//!   * `vouch::<X,` / `vouch_unchecked::<X,` — where each concern is closed.

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
