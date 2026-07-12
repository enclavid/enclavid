//! Engine-side resource and validation limits — every numeric cap
//! the policy execution layer enforces lives here.
//!
//! **These are compile-time constants by design.** Together they
//! form the engine's slice of the TEE trust contract: a consumer
//! attesting an enclave hash is implicitly attesting these values
//! too. Loading any of them from env / config / runtime input
//! would let an untrusted host:
//!
//!   * Open covert host→policy channels (policy self-measures its
//!     fuel/memory budget; runtime-variable budget = side-channel
//!     bandwidth).
//!   * Selectively DoS user classes by tuning caps per-session
//!     based on out-of-band signals (IP, headers, ...).
//!   * Break the "PCR = behavior" attestation contract — the
//!     measured code says one thing, the running instance does
//!     another.
//!
//! Changing a value here changes the trust contract. Bump the
//! image, re-attest, communicate to consumers.
//!
//! For HTTP / multipart / external-input size caps see the api
//! crate's `limits` module — same review discipline applies, but
//! those live at the IO boundary and are reviewed alongside the
//! HTTP routes that enforce them.

// ----- Wasmtime resource caps -----

/// Maximum linear memory the policy component is allowed to grow
/// to. Enforced via `Store::limiter` on every `memory.grow`. Bounds
/// the worst-case memory pressure inside the TEE from a malicious
/// or buggy policy; tight enough to keep the enclave responsive,
/// generous enough that ML-bearing policies (decoded JPEG frames,
/// ONNX intermediates) don't trip on legitimate work.
///
/// Tighten once plugin separation lands and heavy lifting moves
/// out into attested plugins (which get their own stores + caps).
pub const POLICY_MAX_MEMORY: usize = 128 * 1024 * 1024;

/// Fuel budget for one `Runner::run` / `Runner::extract_texts`
/// call. Each WASM instruction consumes ~1 unit; out-of-fuel
/// traps. Pairs with `POLICY_MAX_MEMORY` as the second leg of the
/// "policy can't hang the enclave" guarantee — memory cap blocks
/// allocation bombs, fuel cap blocks compute bombs / infinite
/// loops. Generous for MVP since the policy currently carries
/// plugin work inline; tighten with plugin separation.
pub const POLICY_FUEL_BUDGET: u64 = 10_000_000_000;

/// Hard cap on the policy's opaque `state` blob, enforced in
/// [`Runner::run`](crate::Runner::run) immediately after each `handle`
/// round — a larger blob traps the round.
///
/// The engine's data-minimization ceiling. The reducer model already lets a
/// well-behaved policy keep only derived results in `state`: raw captures live
/// in the host blob store, so a policy rehydrates a frame by its `blob-ref`
/// (`frame::from-blob-ref`) each round it needs it and keeps only the 32-byte
/// ref — never the pixels — in `state`. This cap is the backstop for the
/// malicious/buggy case, sized to still allow one legitimate heavy use the blob
/// store does NOT cover: caching a large policy-DERIVED artifact across rounds
/// (a policy-produced value, not an ingest capture — e.g. a stitched or
/// re-encoded image the policy computed), which can run to about a megabyte. It
/// still blocks bulk media accumulation (a stack of raw frames stuffed into the
/// blob), which is tens of megabytes and up. Lighter state — step bookkeeping,
/// blob-refs, MRZ text, face embeddings, screening verdicts — is a rounding
/// error against it.
///
/// The host-observable ciphertext-size covert channel this blob would otherwise
/// feed is NOT bounded here; it is CLOSED downstream by the seal-boundary
/// constant-size padding (`broker_client::SEALED_STATE_PLAINTEXT_BYTES`), which
/// pads every sealed `SessionState` to a fixed size. This cap is therefore the
/// data-min ceiling only — and because the padding frame must cover a max-cap
/// state, raising this cap raises that frame (and hence the constant per-write
/// seal cost) in lockstep.
pub const POLICY_MAX_STATE_BYTES: usize = 1024 * 1024;

// ----- text-ref validation -----

/// Per-prompt cap on consented fields. Trapping over this is
/// pre-emptive defence against a policy that tries to make the
/// consent screen visually overwhelming (user fatigue → reflexive
/// Allow). 20 lines on a phone is already a lot to read.
pub const MAX_CONSENT_FIELDS: usize = 20;

/// Per-field cap on `display-field.value` byte length. Generous
/// enough for legitimate free-form data — multi-segment international
/// addresses, long legal-entity names, multi-line composite IDs —
/// across all UTF-8 scripts (4096 bytes ≈ 4000 ASCII chars / ~2000
/// Cyrillic / ~1300 CJK). The consent UI handles values past its
/// own visible-region threshold by collapsing with an explicit
/// "Show full" toggle, so the user can always inspect the entire
/// value before consenting. Anything beyond this byte cap is still
/// a policy bug or covert-channel attempt — the cap is the hard
/// outer ceiling, the UI is the in-band UX boundary.
pub const MAX_VALUE_LENGTH: usize = 4096;

/// Soft cap on a sanitised `translation.value` (in characters,
/// not bytes — UTF-8 safe). Labels are well under, consent reasons
/// usually fit. Values longer than this get truncated rather than
/// rejected; [`MAX_TEXT_VALUE_HARD_BYTES`] is the rejection threshold.
pub const MAX_TEXT_VALUE_SOFT_CHARS: usize = 1000;

// ----- Schema-level caps re-exported from `enclavid-embedded` -----
//
// These are the wire-format limits that bound what a single source
// file can declare. They're owned by the schema crate and engine
// re-exports them here so callers inside engine continue using
// `crate::limits::*` without reaching across crate paths. Single
// source of truth — bumps land in `enclavid-embedded::lib.rs`.
//
// Naming kept verbatim to avoid touching call sites; semantic
// meanings preserved from when they lived here directly:
//
//   * `MAX_LANGUAGE_LENGTH` — BCP-47-shaped `translation.language`
//     tag length cap (longest realistic tag is ~12 bytes,
//     `zh-Hant-HK`). Anything longer is a policy bug or covert
//     channel.
//   * `MAX_KEY_LENGTH` — `text-ref` identifier length cap. Blocks
//     unicode shenanigans on the registry cache index and bounds
//     per-entry memory.
//   * `MAX_TEXT_VALUE_HARD_BYTES` — hard cap on the raw byte length
//     of a `translation.value` before sanitisation. Refuses the
//     whole policy load if any single entry exceeds this. Second-
//     line guard behind `POLICY_MAX_MEMORY` — wasmtime caps total
//     linear memory, this caps per-entry size so a million 1-byte
//     entries can't slip under the memory wire by spreading the
//     payload.
//   * `MAX_DECLARED_DISCLOSURE_FIELDS` / `MAX_DECLARED_LOCALIZED` /
//     `MAX_DECLARED_ICONS` — per-kind cardinality caps on a single
//     component's embedded declarations. Split per kind because the
//     covert-channel surfaces aren't symmetric — see
//     `enclavid-embedded::lib.rs` for the per-kind rationale. The
//     compile-time bound is the system-wide trust contract; runtime
//     transparency UI in api views surfaces the actual declared
//     counts to the user as a second-line defence.
pub use enclavid_embedded::{
    MAX_DECLARED_DISCLOSURE_FIELDS, MAX_DECLARED_ICONS, MAX_DECLARED_LOCALIZED,
    MAX_KEY_LENGTH, MAX_LANGUAGE_LENGTH, MAX_TEXT_VALUE_HARD_BYTES,
};
