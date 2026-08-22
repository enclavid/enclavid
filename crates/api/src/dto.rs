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
use sha2::{Digest, Sha256};

use hatch_client::{DisplayField as ProtoDisplayField, Localized, PromptDisclosure, SessionStatus};

use crate::locale::Locale;

/// The pinned policy of a session, echoed to the consumer: the full OCI
/// reference plus its `sha256:<hex>` digest substring (the same value the
/// attestation quote binds in `ReportData.policy_digest`), and every plugin
/// fused alongside it. Shared by the create response (`CreateSessionResponse`)
/// and the read view (`SessionView`). All refs are digest-pinned — the TEE
/// only ever runs digest-pinned artifacts.
#[derive(Serialize)]
pub struct ResolvedPolicyView {
    /// Full pinned OCI reference from session metadata / request.
    pub reference: String,
    /// Convenience: the `sha256:<hex>` digest substring extracted from
    /// `reference`.
    pub digest: String,
    /// Every plugin fused into the session's composition, in pin order —
    /// the complete set of artifact digests (with the policy above) that
    /// build the cwasm the TEE runs.
    pub plugins: Vec<PluginView>,
}

/// One plugin pinned into a session's composition, echoed to the consumer.
#[derive(Serialize)]
pub struct PluginView {
    /// The WIT package the plugin satisfies (e.g. `enclavid:well-known`).
    pub package: String,
    /// Full pinned OCI reference of the plugin artifact.
    pub reference: String,
    /// `sha256:<hex>` digest substring extracted from `reference`.
    pub digest: String,
}

impl PluginView {
    /// Build a view from a sealed plugin pin, extracting the digest from its
    /// pinned ref.
    pub fn from_pin(pin: &hatch_client::PluginPin) -> Self {
        Self {
            package: pin.package.clone(),
            reference: pin.impl_ref.clone(),
            digest: crate::policy_pull::split_pinned_ref(&pin.impl_ref)
                .map(|(_, d)| d.to_string())
                .unwrap_or_default(),
        }
    }
}

/// Serde "remote" definition for the proto-generated `SessionStatus`
/// enum. Variants must mirror the foreign enum exactly; serde uses
/// this shadow type only as a description of how to serialize the
/// real `SessionStatus` (declared in hatch-client). Lets the JSON
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
/// metadata set commitment already binds the list to its session,
/// but a redundant in-envelope copy lets a consumer receiving a
/// disclosure out-of-band (future webhook payloads) also verify the
/// binding without round-tripping to the TEE.
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
        Some(picked) => engine_types::sanitize::sanitize_text_value(picked),
        None => String::new(),
    }
}

/// Content digest of a consent-disclosure prompt — the binding between the
/// screen the applicant AUDITED and the disclosure the runtime SEALS on accept.
///
/// The `/input` consent submit echoes this (host-minted) hex digest; the input
/// handler recomputes it over the session's current `current_prompt` and refuses
/// an ACCEPT whose digest doesn't match (409). That closes the show==seal TOCTOU:
/// if `current_prompt` advanced between render and accept (a stale second tab, a
/// concurrent round), the echoed digest is stale and the accept is rejected —
/// rather than sealing a disclosure the applicant never saw.
///
/// Covers everything the applicant audits on the screen — the disclosed
/// `(key, label, value)` fields in order, the reason, the requester, and the
/// declared-vocabulary count — so any change to what would be sealed, or to whom
/// / why, changes the digest. Locale-independent: the whole translation set is
/// hashed, not the locale-picked string.
pub fn consent_disclosure_digest(d: &PromptDisclosure) -> String {
    // Just SHA-256 over the prompt's JSON. Deterministic because `Disclosure` is
    // map/float-free (only Vec/String/usize), so equal values always serialize to
    // identical bytes — and both call sites hash the SAME `current_prompt` value,
    // so exact byte-canonicality isn't required, only that serialization is a pure
    // function of the value. JSON's own delimiters keep field boundaries
    // unambiguous. (If a `HashMap` field is ever added to this type, switch to an
    // order-independent encoding.)
    let json = serde_json::to_vec(d).expect("PromptDisclosure is always serializable");
    hex::encode(Sha256::digest(json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_client::{PromptDisclosure, Translation};

    fn loc(text: &str) -> Localized {
        Localized {
            translations: vec![Translation {
                language: "en".into(),
                text: text.into(),
            }],
        }
    }

    fn field(key: &str, value: &str) -> ProtoDisplayField {
        ProtoDisplayField {
            key: key.into(),
            label: loc(&format!("{key} label")),
            value: value.into(),
        }
    }

    fn disclosure() -> PromptDisclosure {
        PromptDisclosure {
            fields: vec![field("first_name", "Alice"), field("dob", "1990-01-01")],
            reason: loc("To open an account"),
            requester: loc("Acme Trading"),
            total_declared: 12,
        }
    }

    #[test]
    fn digest_is_deterministic_and_64_hex() {
        let a = consent_disclosure_digest(&disclosure());
        assert_eq!(a, consent_disclosure_digest(&disclosure()));
        assert_eq!(a.len(), 64, "sha256 → 64 hex chars");
    }

    #[test]
    fn digest_changes_with_sealed_content_or_recipient() {
        let base = consent_disclosure_digest(&disclosure());

        // A changed field VALUE (the data that leaks) — the core show==seal bind.
        let mut d = disclosure();
        d.fields[0].value = "Bob".into();
        assert_ne!(
            base,
            consent_disclosure_digest(&d),
            "value change must move the digest"
        );

        // A changed field KEY.
        let mut d = disclosure();
        d.fields[1].key = "nationality".into();
        assert_ne!(
            base,
            consent_disclosure_digest(&d),
            "key change must move the digest"
        );

        // An ADDED field (D1 ⊂ D2) — the classic "seal more than was shown".
        let mut d = disclosure();
        d.fields.push(field("passport_number", "X123"));
        assert_ne!(
            base,
            consent_disclosure_digest(&d),
            "added field must move the digest"
        );

        // A changed requester (WHO it is disclosed to).
        let mut d = disclosure();
        d.requester = loc("Evil Corp");
        assert_ne!(
            base,
            consent_disclosure_digest(&d),
            "requester change must move the digest"
        );
    }

    #[test]
    fn field_order_is_significant() {
        let a = consent_disclosure_digest(&disclosure());
        let mut d = disclosure();
        d.fields.swap(0, 1);
        assert_ne!(
            a,
            consent_disclosure_digest(&d),
            "reordered fields are a different screen"
        );
    }

    #[test]
    fn field_boundaries_do_not_collide() {
        // With identical labels, ("ab", "") and ("a", "b") must not collide —
        // JSON's own delimiters keep the key/value boundary unambiguous.
        let lbl = loc("L");
        let a = PromptDisclosure {
            fields: vec![ProtoDisplayField {
                key: "ab".into(),
                label: lbl.clone(),
                value: String::new(),
            }],
            ..Default::default()
        };
        let b = PromptDisclosure {
            fields: vec![ProtoDisplayField {
                key: "a".into(),
                label: lbl,
                value: "b".into(),
            }],
            ..Default::default()
        };
        assert_ne!(consent_disclosure_digest(&a), consent_disclosure_digest(&b));
    }
}
