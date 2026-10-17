//! Volume → store crossings: values read back from where the host could have
//! changed them or put an older copy back. [`from_untrusted`] opens all three
//! inbound concerns `(AuthN, AuthZ, Replay)`, and the use site answers each: a
//! peel that does the work ([`trust::<X>(work)`](Untrusted::trust)) — an AEAD
//! open, a decode — or an accept with its reason
//! ([`trust_unchecked::<X>(reason)`](Untrusted::trust_unchecked)).

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
