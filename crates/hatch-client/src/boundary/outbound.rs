//! TEE → wire crossings. A single generic entry function [`to_untrusted`]
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
//!   * `boundary::outbound::to_untrusted(` — every TEE → wire crossing,
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

use crate::boundary::{AuthN, AuthZ, Covert, Exposed};
use crate::reason;

/// Maximally-open outbound scope: every TEE → wire release has all
/// three outbound concerns open until the use site addresses each.
///
/// `(AuthN, AuthZ, Covert)`:
///   * `AuthN` — confidentiality (host may read the bytes);
///   * `AuthZ` — release authorisation (which party may receive);
///   * `Covert` — hidden bandwidth in the encoded shape.
pub type ToUntrusted<T> = Exposed<T, (AuthN, AuthZ, Covert)>;

/// Wrap a TEE-produced value as a [`ToUntrusted<T>`]. The
/// `channel_reason` names the channel (wire field, response slot,
/// blob slot, ...) — it is the audit-grep anchor for the perimeter.
/// Caller must address each of `(AuthN, AuthZ, Covert)` at the use
/// site before the value reaches the wire via `into_inner`.
pub fn to_untrusted<T>(value: T) -> ToUntrusted<T> {
    Exposed::new(value)
}

/// Mint the session id as a fully-vouched outbound value — the record address
/// the store indexes by. Used by the lone-id store calls (`read` / `delete` /
/// `exists`); `write` bundles its id into the `(id, version)` tuple instead.
/// NOT a generic "anything goes" mint — it is specific to the session id so the
/// audited reason lives in one place (grep `outbound_session_id(`).
///
/// **The justification deliberately does not name the peer.** Whoever holds the
/// record must index by this value, so no arrangement exists in which it could
/// be hidden from them. That held when the store was host Redis, holds now that
/// it is the attested storage-CVM behind RA-TLS, and will hold through the next
/// move. The previous rationale reasoned from who was on the other end instead,
/// and went stale the moment the storage tier moved — hence the rename from
/// `public_session_id`.
///
/// Distribution is a separate fact, kept in this doc rather than in the name
/// because it tracks deployment rather than the value's role: the id is **not**
/// host-known. It is generated in the TEE
/// (`api::client::create::generate_session_id`), never crosses the wire in
/// cleartext (client TLS terminates in the TEE), is not sent to the hatch
/// (`AuthorizeRequest` carries only the verbatim header and an operation enum),
/// and reaches the storage-CVM inside RA-TLS. It IS handed to the applicant and
/// the consumer, so it is not "private" either — see `api::applicant::reset`,
/// where knowledge of it is the documented trust gate.
pub fn outbound_session_id(id: &str) -> Exposed<&str, ()> {
    to_untrusted(id)
        .vouch_unchecked::<AuthN, _>(reason!(
            "nothing to conceal from a peer that must index by it"
        ))
        .vouch_unchecked::<AuthZ, _>(reason!("names a record; no release decision hangs on it"))
        .vouch_unchecked::<Covert, _>(reason!(
            "fixed-shape random id minted in the TEE, not policy-controlled"
        ))
}
