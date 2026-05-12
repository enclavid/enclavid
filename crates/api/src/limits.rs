//! API-side resource and validation limits — every numeric cap the
//! HTTP / multipart / external-input boundary enforces lives here.
//!
//! **These are compile-time constants by design.** Together with
//! [`enclavid_engine::limits`] they form the enclave's full trust
//! contract: a consumer attesting the enclave hash is implicitly
//! attesting these values too. Routing them through env / config /
//! runtime input would let an untrusted host:
//!
//!   * Tune body limits per session to enable selective DoS or to
//!     reject specific user classes (see the host_state-side `limits`
//!     module for the same threat applied to fuel/memory).
//!   * Stretch the entropy of `session_id` down to brute-forceable.
//!   * Inflate `external_ref` so it becomes a covert data sink.
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

/// Maximum length of the consumer-supplied `external_ref` field
/// (their per-session reconciliation tag, opaque to the TEE).
/// Bounds host storage growth and keeps wire frames small; UUIDs
/// and typical client identifiers fit comfortably.
pub const MAX_EXTERNAL_REF_LEN: usize = 128;
