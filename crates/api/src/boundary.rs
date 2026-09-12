//! The ENGINE-leg crossings: values arriving from the compile-worker and the
//! execution-worker.
//!
//! api types its other two CVM boundaries and left this one bare. The hatch is
//! typed in `hatch-client`; the storage CVM is typed transitively, because
//! `crate::storage` implements hatch-client's backend seams and everything
//! surfaces through the typed `SessionStore` / `CacheStore`. The worker legs had
//! nothing — and they are the ones reaching the process that executes
//! adversary-authored wasm.
//!
//! What that cost: four separate defects found by review turned out to be one
//! defect four times, all here. api sealed a disclosure the worker asserted;
//! consent derives from a `current_prompt` the worker authored; media blob hashes
//! are never checked against their bytes; the consent caps and the
//! invisible-character whitelist run only worker-side. On a typed leg that class
//! does not accumulate, because the value cannot be reached without naming a
//! reason — the compiler asks what a reviewer otherwise has to.
//!
//! ## Why one new marker rather than the hatch's four
//!
//! [`Asserted`] is the only inbound concern this leg has, and none of the
//! existing markers is it.
//!
//!   * `AuthN` asks who produced the bytes. Mutual RA-TLS against a pinned
//!     measurement already answers that, and answers it more strongly than a
//!     per-value check could. Nobody substituted these bytes — that is the
//!     problem. Discharging `AuthN` here would be easy, true, cryptographic, and
//!     would say nothing about whether a prompt's fields are the ones the
//!     applicant approved.
//!   * `AuthZ` asks whether a principal may reach a resource. The worker is
//!     obviously allowed to write a prompt into the session it is running, and
//!     there is no principal on the return path at all.
//!   * `Replay` asks whether this is a stale snapshot. A remoc call over a TLS
//!     stream has no versions and no store to be stale from.
//!   * `Covert` is outbound-only by construction.
//!
//! The question none of them asks — *is this value a function of something we or
//! the applicant established, or did the peer pick it* — is the one all four
//! defects turned on. See [`Asserted`] for the four kinds of discharge, and for
//! why "the peer is attested" is not one of them.
//!
//! Audit grep: `boundary::from_worker(` for every crossing, `trust::<Asserted` /
//! `trust_unchecked::<Asserted` for where each one is answered.
//!
//! One entry function, not one per channel or per direction. The concern does
//! not change with either, so a second function returning the same scope would
//! be a label rather than a decision — the argument `hatch-client`'s
//! `boundary::inbound` already makes for its own single entry.
//!
//! ## Why the wrapping is here and not on the remoc trait
//!
//! Because the scope is `PhantomData`. It has no wire representation: exactly
//! `T` would cross either way, and the receiving side would deserialize into
//! whatever `S` it declared, so a wrapper in the RPC signature would enforce
//! nothing the receiver could not simply assert. It would also make the WORKER
//! name `Untrusted` — the party the marker distrusts, declaring its own output
//! doubtful, which is theatre if honest and absent if not.
//!
//! `Asserted` is a judgement the RECEIVER makes, not a property of the bytes.
//! The same blob from a worker and from the applicant has different provenance
//! with identical contents. That is also why provenance cannot simply ride along
//! inside a domain type: a value re-entering api from the sealed store is the
//! same bytes with the same origin, and has to be judged again where it lands.

use hatch_client::{Asserted, Untrusted};

/// A value a worker produced — returned from a call api made, or pushed into a
/// callback api is serving. Both are the worker's own word; nothing about that
/// turns on which way the call went.
pub(crate) type FromWorker<T> = Untrusted<T, (Asserted,)>;

/// Wrap a value a worker produced. The caller answers [`Asserted`] at the use
/// site, where the context that makes an answer possible actually lives.
pub(crate) fn from_worker<T>(value: T) -> FromWorker<T> {
    Untrusted::new(value)
}
