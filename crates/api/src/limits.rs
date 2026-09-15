//! API-side resource and validation limits — every numeric cap the
//! HTTP / multipart / external-input boundary enforces lives here.
//!
//! **These are compile-time constants by design.** Together with
//! [`engine_types::limits`] they form the enclave's full trust
//! contract: a consumer attesting the enclave hash is implicitly
//! attesting these values too. Routing them through env / config /
//! runtime input would let an untrusted host:
//!
//!   * Tune body limits per session to enable selective DoS or to
//!     reject specific user classes (see the host_state-side `limits`
//!     module for the same threat applied to fuel/memory).
//!   * Stretch the entropy of `session_id` down to brute-forceable.
//!   * Inflate `client_ref` so it becomes a covert data sink.
//!
//! Changing a value here changes the trust contract. Bump the
//! image, re-attest, communicate to consumers.

// ----- HTTP / multipart body caps -----

/// Body-limit applied to `/session/:id/input/:slot_id` (multipart).
/// Headroom for the largest legitimate payload: ~12 JPEG frames at
/// ~200 KB plus multipart overhead. Enforced via axum's
/// `DefaultBodyLimit::max(...)` at the route layer so handler logic
/// stays free of byte arithmetic.
pub const APPLICANT_INPUT_BODY_LIMIT: usize = 16 * 1024 * 1024;

// ----- Service-provided input -----

/// Hard cap on the JSON byte payload accepted via Match-Mode
/// service input (the `input` field of session metadata, parsed
/// into typed `eval-args`). Tight enough to prevent a malicious
/// service from smuggling a database of names in and extracting
/// match results — the architecture's bulk-matching defence.
pub const MAX_MATCH_INPUT_SIZE: usize = 1024;

// ----- Session identifier shape -----

/// Random bytes drawn for a fresh `session_id`. 32 bytes = 256-bit
/// entropy. Architecture doc requires ≥ 128 bits to make session
/// guessing infeasible; this is comfortable headroom.
pub const SESSION_ID_RANDOM_BYTES: usize = 32;

/// Random bytes drawn for the `client_session_token` (per-session
/// bearer the client presents in `X-Session-Token` on read endpoints).
/// 32 bytes = 256-bit entropy — unguessable, and matches the
/// applicant_session_token width for symmetry.
pub const CLIENT_SESSION_TOKEN_BYTES: usize = 32;

/// Maximum length of the consumer-supplied `client_ref` field
/// (their per-session reconciliation tag, opaque to the TEE).
/// Bounds host storage growth and keeps wire frames small; UUIDs
/// and typical client identifiers fit comfortably.
pub const MAX_CLIENT_REF_LEN: usize = 128;

/// Maximum byte length of the `Authorization` header value the TEE
/// is willing to forward as `registry_auth`. Typical Logto-issued
/// JWT access tokens land around 1–2 KB; 8 KB is comfortably above
/// realistic bearer sizes while still bounding session-metadata
/// growth in case a malicious consumer supplies a giant string.
/// Enforced at session-create time, before any persistence.
pub const MAX_REGISTRY_AUTH_LEN: usize = 8 * 1024;

// ----- The derivations the worker's own bounds rest on -----
//
// The execution-worker enforces its own bounds on what arrives, because it
// accepts any attested guest and cannot assume its caller ran this crate. Those
// bounds were DERIVED from the caps above, and a derivation nobody checks drifts.
// This is where the check belongs: the only place both numbers are visible.
//
// The direction matters. The worker's bound must be the LOOSER one — if this side
// ever admits more than the worker will, the overrun stops being a 4xx the
// applicant can act on and becomes a failed round.
//
// Written as const assertions rather than tests: a trust-contract derivation that
// stopped holding should not compile, and both sides of every comparison are
// constants, so there is nothing to run.

/// Bytes the smallest possible JSON entry costs. What turns the config's byte cap
/// into an entry count.
///
/// The MARGINAL cost of an entry is six (`,"k":0`); five is that minus the comma
/// the last entry does not pay, so dividing by five can only over-count entries —
/// which is the safe direction for a bound the worker's cap must cover.
const MIN_JSON_BYTES_PER_ENTRY: usize = 5;

const _: () = assert!(
    MAX_MATCH_INPUT_SIZE / MIN_JSON_BYTES_PER_ENTRY <= engine_types::limits::MAX_PROPS,
    "the config cap can yield more props entries than the worker will accept"
);
const _: () = assert!(
    MAX_MATCH_INPUT_SIZE <= engine_types::limits::MAX_PROPS_BYTES,
    "the config cap can yield more props bytes than the worker will accept"
);
const _: () = assert!(
    APPLICANT_INPUT_BODY_LIMIT <= hatch_client::MAX_CLIP_BYTES,
    "a legal applicant body can exceed the clip budget the worker will accept"
);
// The frame COUNT has no derivation to check, which is the gap it exists to close:
// an empty multipart part costs only its framing, so a legal body admits frames by
// the hundred thousand. This asserts the opposite direction from the three above —
// that the cap still BINDS, i.e. is well below what a legal body could carry at
// some tens of bytes a part. A count raised past that would be decoration.
const _: () = assert!(
    hatch_client::MAX_CLIP_FRAMES > 0
        && hatch_client::MAX_CLIP_FRAMES * 32 < APPLICANT_INPUT_BODY_LIMIT,
    "the frame count cap no longer binds — a legal body cannot reach it"
);
