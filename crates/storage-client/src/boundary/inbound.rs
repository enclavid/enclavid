//! Volume → store crossings: values read back from where the host could have
//! changed them or put an older copy back. [`from_untrusted`] opens all three
//! inbound concerns `(AuthN, AuthZ, Replay)`, and the use site answers each: with
//! work ([`trust_with`](Untrusted::trust_with)) — an AEAD open, a decode — with
//! an argued kind and its reason ([`trust`](Untrusted::trust)), or as an
//! accepted risk ([`trust_accept_risk`](Untrusted::trust_accept_risk)).

use enclavid_boundary::{AuthN, AuthZ, Replay, Untrusted};

/// Maximally-open inbound scope: a value read back has all three inbound
/// concerns open until the use site addresses each.
///
/// `(AuthN, AuthZ, Replay)`:
///   * `AuthN` — bytes could be fabricated by the host;
///   * `AuthZ` — caller may not be authorised to receive this;
///   * `Replay` — bytes could be a stale snapshot.
pub type FromUntrusted<T> = Untrusted<T, (AuthN, AuthZ, Replay)>;

/// Wrap a value the store read back as a [`FromUntrusted<T>`]. The caller
/// addresses each of `(AuthN, AuthZ, Replay)` at the use site before
/// reaching the inner value via `into_inner`.
pub fn from_untrusted<T>(value: T) -> FromUntrusted<T> {
    Untrusted::new(value)
}
