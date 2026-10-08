//! Engine-side resource and validation limits — the numeric caps of
//! the policy execution layer that are terms of the trust contract.
//!
//! **These are compile-time constants by design.** Together they
//! form the engine's slice of the TEE trust contract: a consumer
//! attesting an enclave hash is implicitly attesting these values
//! too. Loading any of them from env / config / runtime input
//! would let an untrusted host:
//!
//!   * Open covert host→policy channels (a policy can measure a cap
//!     it runs against; one the host varies is side-channel
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
//! The round's memory max and its fuel are not here. They are settings
//! the host gives the execution worker at launch
//! (`engine_executor::admission`, `engine_executor::DEFAULT_ROUND_FUEL`),
//! outside the measurement: how much the service gives a round.
//!
//! What that leaves the host is a threshold of its own choosing. It can
//! run workers of one image with different values and pick which one a
//! session reaches, so it learns whether a round — an honest policy's
//! too — needs more than it chose: one bit per round, and only when the
//! round fails. A threshold in the build would leave that bit too, only
//! at a value the host did not pick. Accepted: the host already times
//! every round it carries, the bit bounds how much a round did rather
//! than what it was about, and a round it makes fail is availability,
//! which the host has anyway.
//!
//! For HTTP / multipart / external-input size caps see the api
//! crate's `limits` module — same review discipline applies, but
//! those live at the IO boundary and are reviewed alongside the
//! HTTP routes that enforce them.

// ----- Round resource caps -----

/// Hard cap on the policy's opaque `state` blob, enforced in
/// `Executor::run` (in `engine-executor`) immediately after each `handle`
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
/// The host-observable size covert channel this blob would otherwise feed is NOT
/// bounded here; it is CLOSED by constant-size padding to
/// `hatch_client::SEALED_STATE_PLAINTEXT_BYTES` at BOTH places the host can count
/// bytes — the seal boundary, where every sealed `SessionState` is a fixed-size
/// ciphertext, and the api↔execution-worker hop, where `engine_rpc::Padded` frames
/// the same value in both directions. This cap is therefore the data-min ceiling
/// only — and because the frame must cover a max-cap state, raising this cap
/// raises it (and hence the constant per-write seal cost and per-round wire cost)
/// in lockstep.
pub const POLICY_MAX_STATE_BYTES: usize = 1024 * 1024;

// ----- The consumer's static config, as it arrives on the execute hop -----
//
// `props` is a pure function of the consumer's JSON config, which api already
// caps at `enclavid_api::limits::MAX_MATCH_INPUT_SIZE` — 1 KiB, the
// bulk-matching defence. These two are the SAME bound restated where the
// execution-worker can enforce it, and they exist because the worker cannot see
// api's constant and must not assume its caller is api. The worker accepts any
// attested guest, so "api already capped it" is a statement about a peer it
// cannot identify.
//
// Derived rather than picked. In a JSON object of N bytes every entry costs at
// least six (`"k":0,`) and every byte of a key or a string value costs at least
// one, so 1 KiB of config cannot yield more than ~170 entries or more than 1 KiB
// of key-and-value bytes. Both numbers below sit above that with room, so no
// legitimate config is near them — deliberately looser, so a legitimate round is
// never refused worker-side. A `const` assertion in the api crate pins them to
// that origin, which is the only place both constants are visible at once, so a
// derivation that stopped holding fails to compile.

/// Maximum entries in one round's `props` list.
pub const MAX_PROPS: usize = 256;

/// Maximum total bytes across every `props` key and every string `props` value.
/// Non-string values are fixed-width scalars and are bounded by [`MAX_PROPS`]
/// alone.
pub const MAX_PROPS_BYTES: usize = 4 * 1024;

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

// ----- The consumer's embedded catalogs, as a whole -----

/// The most embedded-section bytes one composition may carry: every
/// `enclavid:embedded.*.v1` section — disclosure-fields, i18n, icons — of the
/// policy and of every plugin it pins, at every nesting depth, summed as raw
/// bytes. Past it the compile is refused before any section is parsed, and no
/// bundle exists to be cached or installed.
///
/// The per-kind caps below bound what ONE component declares; the plugin set is
/// the consumer's to pin, so they bound no composition. This does, and what
/// holds a composition's catalogs downstream is sized from it: the metadata the
/// execute hop accepts (`engine_rpc::MAX_BUNDLE_META_BYTES`) and, through that,
/// what an execution-worker reserves for one install.
///
/// Here rather than in `enclavid-embedded`, which owns the per-component schema
/// and is shared with the CLI: a composition exists only in the fleet, and this
/// leaf is what both the compiler that holds the cap and the execute contract
/// that derives from it link.
///
/// 2 MiB: the largest catalog shipped today is under 3 KB, so this is hundreds
/// of times what a composition needs, while a decoded catalog of tiny keys —
/// tens of bytes each in a hash table — stays in the tens of MiB.
pub const MAX_EMBEDDED_SECTION_BYTES: u64 = 2 * 1024 * 1024;

// ----- Schema-level caps re-exported from `enclavid-embedded` -----
//
// These are the wire-format limits that bound what a single source
// file can declare. They're owned by the schema crate and this leaf
// re-exports them here so callers continue using `limits::*` without
// reaching across crate paths. Single source of truth — bumps land in
// `enclavid-embedded::lib.rs`.
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
//     line guard behind the round's memory max, which bounds everything
//     the round's process holds; this caps per-entry size so a million
//     1-byte entries can't slip under the memory wire by spreading
//     the payload.
//   * `MAX_DECLARED_DISCLOSURE_FIELDS` / `MAX_DECLARED_LOCALIZED` /
//     `MAX_DECLARED_ICONS` — per-kind cardinality caps on a single
//     component's embedded declarations. Split per kind because the
//     covert-channel surfaces aren't symmetric — see
//     `enclavid-embedded::lib.rs` for the per-kind rationale. The
//     compile-time bound is the system-wide trust contract; runtime
//     transparency UI in api views surfaces the actual declared
//     counts to the user as a second-line defence.
pub use enclavid_embedded::{
    MAX_DECLARED_DISCLOSURE_FIELDS, MAX_DECLARED_ICONS, MAX_DECLARED_LOCALIZED, MAX_KEY_LENGTH,
    MAX_LANGUAGE_LENGTH, MAX_TEXT_VALUE_HARD_BYTES,
};
