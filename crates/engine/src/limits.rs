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

// ----- text-ref validation -----

/// Per-prompt cap on consented fields. Trapping over this is
/// pre-emptive defence against a policy that tries to make the
/// consent screen visually overwhelming (user fatigue → reflexive
/// Allow). 20 lines on a phone is already a lot to read.
pub const MAX_EXPOSE_FIELDS: usize = 20;

/// Per-field cap on `display-field.value` byte length. Bounds the
/// most a single consented field can carry. Larger payloads are a
/// policy bug or a covert channel — the consumer wants stable data
/// shapes, not free-form blobs.
pub const MAX_VALUE_LENGTH: usize = 200;

/// BCP-47-shaped `translation.language` tag length cap (longest
/// realistic tag is ~12 bytes, `zh-Hant-HK`). Anything longer is a
/// policy bug or covert channel.
pub const MAX_LANGUAGE_LENGTH: usize = 16;

/// `text-ref` identifier length cap. Blocks unicode shenanigans on
/// the registry cache index and bounds per-entry memory.
pub const MAX_KEY_LENGTH: usize = 128;

/// Soft cap on a sanitised `translation.value` (in characters,
/// not bytes — UTF-8 safe). Labels are well under, consent reasons
/// usually fit. Values longer than this get truncated rather than
/// rejected; the hard cap below is the rejection threshold.
pub const MAX_TEXT_VALUE_SOFT_CHARS: usize = 1000;

/// Hard cap on the **raw** byte length of a `translation.value`
/// before sanitisation. Refuses the whole policy load if any
/// single entry exceeds this. Second-line guard behind
/// `POLICY_MAX_MEMORY` — wasmtime caps total linear memory, this
/// caps per-entry size so a million 1-byte entries can't slip
/// under the memory wire by spreading the payload.
pub const MAX_TEXT_VALUE_HARD_BYTES: usize = 16 * 1024;

/// Total cap on declarations returned from `prepare-text-refs`.
/// Bounds how much memory the per-session text registry can
/// occupy and the audit cardinality of "what strings can this
/// policy show". Second-line guard behind `POLICY_MAX_MEMORY`.
pub const MAX_TEXT_ENTRIES: usize = 4096;
