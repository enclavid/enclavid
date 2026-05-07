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
//!   * **Shape control.** WIT-generated tuple-variants (`Custom(loc)`)
//!     are incompatible with serde's `tag = "..."` flat form. dto
//!     uses struct-variants so the JSON is a discriminated union
//!     keyed on `key` with payload alongside (`{"key":"custom",
//!     "language":"en","text":"..."}`).
//!
//! Used by:
//!   * `applicant::persister` — wraps engine's structured
//!     `ConsentDisclosure` records into `DisclosureEnvelope`, JSON-
//!     encodes, age-seals to the consumer recipient.
//!   * `applicant::views` — converts proto `Suspended::Consent` into
//!     `RequestView::Consent` for the applicant frontend.
//!
//! Both consumers see the same field/key shape — a single change
//! here updates both surfaces.

use serde::Serialize;

use enclavid_host_bridge::{
    DisplayField as ProtoDisplayField, DocumentField as ProtoDocumentField, DocumentFieldKind,
    DocumentRole as ProtoDocumentRole, FieldKey as ProtoFieldKey,
    LocalizedText as ProtoLocalizedText, SessionStatus, WellKnownFieldKey, field_key,
};

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

/// One consented field. `key` is flattened into the same JSON object
/// as `value` — see `FieldKey` for the discriminator shape.
#[derive(Serialize)]
pub struct DisplayField {
    #[serde(flatten)]
    pub key: FieldKey,
    pub value: String,
}

/// Identifier for a `DisplayField`. Serialized as a discriminated
/// union with `key` as the tag:
///
///   * Simple well-known: `{"key": "first-name"}`
///   * Document-* keys carry the document role alongside:
///     `{"key": "document-number", "document": "passport"}`
///   * Custom escape hatch carries language + label text:
///     `{"key": "custom", "language": "en", "text": "Tax ID"}`
///   * Unknown — fallback for proto values we didn't expect (host
///     garbage or version skew). Defensive; a well-behaved engine
///     never emits this.
#[derive(Serialize)]
#[serde(tag = "key", rename_all = "kebab-case")]
pub enum FieldKey {
    FirstName,
    LastName,
    MiddleName,
    DateOfBirth,
    PlaceOfBirth,
    Nationality,
    Sex,
    DocumentNumber { document: DocumentRole },
    DocumentIssuingCountry { document: DocumentRole },
    DocumentIssueDate { document: DocumentRole },
    DocumentExpiryDate { document: DocumentRole },
    CountryOfResidence,
    Custom { language: String, text: String },
    Unknown,
}

/// Which physical document a `document-*` field belongs to.
#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum DocumentRole {
    Passport,
    IdCard,
    DriversLicense,
    /// Defensive fallback — see `FieldKey::Unknown`.
    Unknown,
}

/// BCP-47 language tag + human-readable text. Shared shape for the
/// `Custom` field key payload and any other localized prose
/// surfaced to applicants (e.g. consent `reason`).
#[derive(Serialize, Default)]
pub struct LocalizedText {
    pub language: String,
    pub text: String,
}

// --- proto → dto conversions ---

impl From<&ProtoDisplayField> for DisplayField {
    fn from(f: &ProtoDisplayField) -> Self {
        Self {
            key: f.key.as_ref().map(FieldKey::from).unwrap_or(FieldKey::Unknown),
            value: f.value.clone(),
        }
    }
}

impl From<&ProtoFieldKey> for FieldKey {
    fn from(fk: &ProtoFieldKey) -> Self {
        match fk.kind.as_ref() {
            Some(field_key::Kind::WellKnown(wk)) => well_known_to_dto(*wk),
            Some(field_key::Kind::DocumentField(df)) => document_field_to_dto(df),
            Some(field_key::Kind::Custom(c)) => FieldKey::Custom {
                language: c.language.clone(),
                text: c.text.clone(),
            },
            None => FieldKey::Unknown,
        }
    }
}

impl From<&ProtoLocalizedText> for LocalizedText {
    fn from(loc: &ProtoLocalizedText) -> Self {
        Self {
            language: loc.language.clone(),
            text: loc.text.clone(),
        }
    }
}

fn well_known_to_dto(wk: i32) -> FieldKey {
    match WellKnownFieldKey::try_from(wk).unwrap_or(WellKnownFieldKey::Unspecified) {
        WellKnownFieldKey::FirstName => FieldKey::FirstName,
        WellKnownFieldKey::LastName => FieldKey::LastName,
        WellKnownFieldKey::MiddleName => FieldKey::MiddleName,
        WellKnownFieldKey::DateOfBirth => FieldKey::DateOfBirth,
        WellKnownFieldKey::PlaceOfBirth => FieldKey::PlaceOfBirth,
        WellKnownFieldKey::Nationality => FieldKey::Nationality,
        WellKnownFieldKey::Sex => FieldKey::Sex,
        WellKnownFieldKey::CountryOfResidence => FieldKey::CountryOfResidence,
        WellKnownFieldKey::Unspecified => FieldKey::Unknown,
    }
}

fn document_field_to_dto(df: &ProtoDocumentField) -> FieldKey {
    let document = document_role_to_dto(df.role);
    match DocumentFieldKind::try_from(df.kind).unwrap_or(DocumentFieldKind::Unspecified) {
        DocumentFieldKind::Number => FieldKey::DocumentNumber { document },
        DocumentFieldKind::IssuingCountry => FieldKey::DocumentIssuingCountry { document },
        DocumentFieldKind::IssueDate => FieldKey::DocumentIssueDate { document },
        DocumentFieldKind::ExpiryDate => FieldKey::DocumentExpiryDate { document },
        DocumentFieldKind::Unspecified => FieldKey::Unknown,
    }
}

fn document_role_to_dto(role: i32) -> DocumentRole {
    match ProtoDocumentRole::try_from(role).unwrap_or(ProtoDocumentRole::Unspecified) {
        ProtoDocumentRole::Passport => DocumentRole::Passport,
        ProtoDocumentRole::IdCard => DocumentRole::IdCard,
        ProtoDocumentRole::DriversLicense => DocumentRole::DriversLicense,
        ProtoDocumentRole::Unspecified => DocumentRole::Unknown,
    }
}
