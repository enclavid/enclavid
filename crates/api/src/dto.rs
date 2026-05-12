//! Public JSON wire types for the api crate. Single source of truth
//! for everything that crosses an HTTP boundary or sits inside a
//! disclosure envelope sealed for the platform consumer.
//!
//! Why these mirror WIT / proto by hand instead of deriving Serialize
//! on those:
//!
//!   * **Firewall.** Auto-derived serde would publish every internal
//!     variant the moment it lands in WIT or proto. A new
//!     policy-internal field (debug variant, future-only flag, ...)
//!     would silently appear in the public API. The dto module is
//!     where we explicitly opt fields IN to the wire contract.
//!   * **Shape control.** Aliasing through serde-remote (e.g.
//!     `SessionStatusDef`) keeps wire shapes stable independently of
//!     foreign type evolution.
//!
//! Used by:
//!   * `applicant::persister` — wraps engine's structured
//!     `ConsentDisclosure` records into `DisclosureEnvelope`, JSON-
//!     encodes, age-seals to the consumer recipient.
//!   * `applicant::views` — converts proto `Suspended::Consent` into
//!     `RequestView::Consent` for the applicant frontend.

use serde::Serialize;

use enclavid_host_bridge::{DisplayField as ProtoDisplayField, SessionStatus};

use crate::text_registry::TextRegistry;

/// Serde "remote" definition for the proto-generated `SessionStatus`
/// enum. Variants must mirror the foreign enum exactly; serde uses
/// this shadow type only as a description of how to serialize the
/// real `SessionStatus` (declared in host-bridge). Lets the JSON
/// wire shape live in the api crate without an orphan-rule wrapper
/// or a transport-layer serde-aware build.rs.
///
/// Used by both client/session.rs and applicant/status.rs via
/// `#[serde(with = "dto::SessionStatusDef")]` on a `SessionStatus`
/// field — same wire string ("running", "completed", ...) for both
/// audiences.
#[derive(Serialize)]
#[serde(remote = "SessionStatus", rename_all = "snake_case")]
pub enum SessionStatusDef {
    Unspecified,
    Running,
    Completed,
    Failed,
    Expired,
}

/// Disclosure envelope schema version. Bumped only when the wire
/// shape (envelope or any inner field shape) changes incompatibly.
/// SDKs read `version` and pick the right deserializer.
pub const ENVELOPE_VERSION: u32 = 1;

/// Public contract carried inside the age-encrypted disclosure entry.
/// Self-describing: SDKs only need age + a JSON parser, no proto.
///
/// `reason` from `prompt-disclosure` is intentionally **not** here —
/// the consumer authored the policy and already knows what each
/// disclosure means; including a policy-controlled string would be a
/// covert channel for arbitrary outbound data.
///
/// `session_id` is embedded as defense-in-depth: the per-session
/// `metadata.disclosure_hash` chain already binds the list to its
/// session, but a redundant in-envelope copy lets a consumer
/// receiving a disclosure out-of-band (future webhook payloads)
/// also verify the binding without round-tripping to the TEE.
#[derive(Serialize)]
pub struct DisclosureEnvelope {
    pub version: u32,
    pub session_id: String,
    pub fields: Vec<DisplayField>,
}

/// Wire shape for the **sealed envelope to the consumer**. Just the
/// policy-declared `key` text-ref and the data; no label.
///
/// Rationale: the consumer authored the policy and dispatches by the
/// literal `key` string (`"passport-number"`, `"first-name"`, ...).
/// Translations live in the per-session text registry inside the
/// TEE — sending them in the envelope would otherwise leak non-user-
/// locale variants the applicant never saw on consent.
#[derive(Serialize)]
pub struct DisplayField {
    pub key: String,
    pub value: String,
}

/// Wire shape for the **applicant consent screen**. Adds the host-
/// resolved `label` translations so the frontend can render a
/// human-readable name without round-tripping. The raw `key`
/// text-ref is still surfaced — the consent UI shows it for any
/// non-canonical key as a visible flag against categorical encoding
/// via key choice.
#[derive(Serialize)]
pub struct ConsentFieldView {
    pub key: String,
    pub label: Translations,
    pub value: String,
}

/// One translation row: the human-readable `text` in a specific
/// `language`. The applicant frontend picks the row matching the
/// user's locale (with fallback).
#[derive(Serialize, Clone, Default)]
pub struct LocalizedString {
    pub language: String,
    pub text: String,
}

/// Full translation set for one `text-ref`. Serializes as a JSON
/// array of `{language, text}` rows — frontend / SDK do locale
/// selection. (Named to reflect what it actually contains; not
/// "LocalizedText" because that's already the WIT-level concept
/// `{key + translations}`.)
pub type Translations = Vec<LocalizedString>;

// --- proto → dto conversion ---

/// Envelope-shape conversion: copies `key` + `value`. No registry
/// dependency. Used by the persister when sealing disclosures for
/// the consumer.
pub fn display_field_from_proto(f: &ProtoDisplayField) -> DisplayField {
    DisplayField {
        key: f.key.clone(),
        value: f.value.clone(),
    }
}

/// Consent-screen conversion: resolves the `label` text-ref through
/// the policy's per-session text registry into the full set of
/// translations. Used by the api view layer when building
/// `RequestView::Consent` for the applicant frontend.
pub fn consent_field_view_from_proto(
    f: &ProtoDisplayField,
    registry: &TextRegistry,
) -> ConsentFieldView {
    ConsentFieldView {
        key: f.key.clone(),
        label: registry.resolve(&f.label),
        value: f.value.clone(),
    }
}
