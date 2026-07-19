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
//!   * `applicant::views` — converts a `Prompt::ConsentDisclosure` into
//!     `RequestView::Consent` for the applicant frontend.

use serde::Serialize;

use broker_client::{DisplayField as ProtoDisplayField, Localized, SessionStatus};

use crate::locale::Locale;

/// The pinned policy of a session, echoed to the consumer: the full OCI
/// reference plus its `sha256:<hex>` digest substring (the same value the
/// attestation quote binds in `ReportData.policy_digest`). Shared by the
/// create response (`CreateSessionResponse`) and the read view
/// (`SessionView`).
#[derive(Serialize)]
pub struct ResolvedPolicyView {
    /// Full pinned OCI reference from session metadata / request.
    pub reference: String,
    /// Convenience: the `sha256:<hex>` digest substring extracted from
    /// `reference`.
    pub digest: String,
}

/// Serde "remote" definition for the proto-generated `SessionStatus`
/// enum. Variants must mirror the foreign enum exactly; serde uses
/// this shadow type only as a description of how to serialize the
/// real `SessionStatus` (declared in broker-client). Lets the JSON
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
/// literal `key` string (`"passport_number"`, `"first_name"`, ...).
/// Translations live in the per-session text registry inside the
/// TEE — sending them in the envelope would otherwise leak non-user-
/// locale variants the applicant never saw on consent.
#[derive(Serialize)]
pub struct DisplayField {
    pub key: String,
    pub value: String,
}

/// Wire shape for the **applicant consent screen**. `label` is
/// pre-resolved to the applicant's locale by the server — frontend
/// renders the string verbatim, no client-side i18n. The raw `key`
/// text-ref is surfaced alongside and the consent UI always shows
/// it — user is the sole auditor on this screen, so the full
/// (key, label, value) triple is rendered with nothing suppressed.
#[derive(Serialize)]
pub struct ConsentFieldView {
    pub key: String,
    pub label: String,
    pub value: String,
}

// --- domain → dto conversion ---
//
// The engine already resolved every ref at the action boundary, so the
// domain [`ProtoDisplayField`] carries the machine `key` and the full
// `label` translation set directly. Rendering here is registry-free —
// just a locale pick — which is what lets a read render without the
// policy component (self-contained sealed prompt).

/// Envelope-shape conversion: `f.key` is already the machine identifier
/// the consumer SDK dispatches on. Used by the persister when sealing
/// disclosures for the consumer.
pub fn display_field_from_proto(f: &ProtoDisplayField) -> DisplayField {
    DisplayField {
        key: f.key.clone(),
        value: f.value.clone(),
    }
}

/// Consent-screen conversion. `f.key` is the machine identifier;
/// `f.label` is the resolved translation set, locale-picked and
/// sanitised. The value is policy free-text, displayed verbatim.
pub fn consent_field_view_from_proto(f: &ProtoDisplayField, locale: &Locale) -> ConsentFieldView {
    ConsentFieldView {
        key: f.key.clone(),
        label: pick_localized(&f.label, locale),
        value: f.value.clone(),
    }
}

/// Shared helper: a resolved [`Localized`] set → applicant-facing string
/// for the request locale (`en` fallback), sanitised. Empty when the set
/// carries no translation rows.
pub fn pick_localized(localized: &Localized, locale: &Locale) -> String {
    match locale.pick(&localized.translations) {
        Some(picked) => engine_executor::sanitize_text_value(picked),
        None => String::new(),
    }
}
