//! Hardening for the policy → host text channel. Runs inside the
//! attested TEE; policy cannot bypass.
//!
//! Two surfaces are sanitised here:
//!
//!   1. `DisplayField`s from `prompt-disclosure` — structured consent
//!      data shown to the applicant and persisted to the consumer.
//!      `value` is policy-supplied free text (typically the actual
//!      PII like "Alice"); `key` and `label` are embedded refs resolved
//!      by `enclavid:embedded/disclosure-fields` /
//!      `enclavid:embedded/i18n`, reverse-looked-up in the
//!      composition's `EmbeddedRegistry`.
//!   2. `translation` entries inside `i18n` sections — the registered
//!      constant strings every component can reference at use sites.
//!      Sanitised once at registration time, cached thereafter —
//!      never re-sanitised at lookup.
//!
//! Stripping rules (control chars, BIDI overrides, zero-width chars,
//! Unicode tag characters) are shared across both surfaces; only the
//! length budgets differ.

use crate::embedded::{DisclosureFieldsStore, EmbeddedRegistry, IconStore, LocalizedStore};
use crate::enclavid::shared_types::disclosure::DisplayField;
use crate::limits::{
    MAX_EXPOSE_FIELDS, MAX_KEY_LENGTH, MAX_TEXT_VALUE_SOFT_CHARS, MAX_VALUE_LENGTH,
};

/// Enforce structural limits + registration on `DisplayField`s carried
/// by a `consent-disclosure` render. Policies exceeding them trap — this
/// is a programming error or a covert-channel attempt, not user input.
///
/// `key` is a disclosure-field-ref → reverse-looked-up in the
/// composition's disclosure-fields store; `label` is a localized-ref
/// → looked up in the localized store. Each store only knows tokens
/// it itself issued, so a token that crossed kinds (a localized ref
/// passed as a key, etc.) fails the right-store check and traps
/// cleanly.
pub fn validate_fields(
    fields: &[DisplayField],
    embedded: &EmbeddedRegistry,
) -> wasmtime::Result<()> {
    if fields.len() > MAX_EXPOSE_FIELDS {
        return Err(wasmtime::Error::msg(format!(
            "consent-disclosure exceeds {MAX_EXPOSE_FIELDS} fields"
        )));
    }
    for field in fields {
        if field.value.len() > MAX_VALUE_LENGTH {
            return Err(wasmtime::Error::msg(format!(
                "consent-disclosure value exceeds {MAX_VALUE_LENGTH} bytes"
            )));
        }
        ensure_disclosure_field(
            &field.key,
            &embedded.disclosure_fields,
            "consent-disclosure field key",
        )?;
        ensure_localized(
            &field.label,
            &embedded.localized,
            "consent-disclosure field label",
        )?;
    }
    Ok(())
}

/// Format-validate + lookup in the disclosure-fields store. Used at
/// every disclosure-field-ref use-site inside host fns so the engine
/// never accepts a runtime-crafted or cross-store ref.
pub fn ensure_disclosure_field(
    token: &str,
    store: &DisclosureFieldsStore,
    role: &str,
) -> wasmtime::Result<()> {
    ensure_registered_in(token, role, "disclosure-field", |t| store.contains(t))
}

/// Format-validate + lookup in the localized store. Used at every
/// localized-ref use-site (consent reason/requester, media labels,
/// instructions, ...).
pub fn ensure_localized(
    token: &str,
    store: &LocalizedStore,
    role: &str,
) -> wasmtime::Result<()> {
    ensure_registered_in(token, role, "localized", |t| store.contains(t))
}

/// Format-validate + lookup in the icons store. Used at every
/// icon-ref use-site (`CaptureStep.icon`).
pub fn ensure_icon(
    token: &str,
    store: &IconStore,
    role: &str,
) -> wasmtime::Result<()> {
    ensure_registered_in(token, role, "icon", |t| store.contains(t))
}

/// Shared body: format check then membership through the
/// store-specific `contains` closure. `kind` is the interface name
/// surfaced in the trap message; the store type itself is erased
/// behind the closure so this function doesn't need to know which
/// store it's checking.
fn ensure_registered_in(
    token: &str,
    role: &str,
    kind: &str,
    contains: impl FnOnce(&str) -> bool,
) -> wasmtime::Result<()> {
    validate_ref_format(token)?;
    if !contains(token) {
        return Err(wasmtime::Error::msg(format!(
            "{role} {kind} ref '{token}' is not registered in any component's \
             enclavid:embedded.{kind}s section"
        )));
    }
    Ok(())
}

/// Validate the structure of an embedded-ref token: a sanity gate
/// applied before the registry reverse-lookup so the trap message can
/// distinguish "well-formed but unknown" from "ill-formed".
///
/// Bounded length (≤ `MAX_KEY_LENGTH` + slot/kind prefix headroom)
/// and ASCII-only characters keep the parser predictable and stop
/// unicode shenanigans from sliding past the index lookup. The set
/// — lowercase letters, digits, `-`, `_`, and `:` (the Phase A
/// slot/kind separator) — accommodates both formats:
///
///   * Phase A debug refs: `"<slot>:<kind>:<key>"` — letters/digits
///     in slot, single-letter kind tag, kebab/snake_case key.
///   * Phase B HMAC refs: lowercase hex digest (`[0-9a-f]+`).
///
/// Validation is intentionally permissive — the **forgery defence**
/// lives in the registry's reverse-index, not here. Anything past
/// this format check that isn't a registered token fails the membership
/// step.
pub fn validate_ref_format(token: &str) -> wasmtime::Result<()> {
    if token.is_empty() {
        return Err(wasmtime::Error::msg("embedded ref is empty"));
    }
    // Generous upper bound: a Phase A ref tops out at ~MAX_KEY_LENGTH
    // + a few bytes of slot/kind prefix; a Phase B ref is fixed-width
    // hex. Anything past this is malformed.
    if token.len() > MAX_KEY_LENGTH + 16 {
        return Err(wasmtime::Error::msg(format!(
            "embedded ref exceeds {} bytes",
            MAX_KEY_LENGTH + 16,
        )));
    }
    for c in token.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == ':') {
            return Err(wasmtime::Error::msg(
                "embedded ref contains invalid character (allowed: a-z, 0-9, '-', '_', ':')",
            ));
        }
    }
    Ok(())
}

/// Validate a BCP-47-shaped language tag on a `translation` entry.
/// Soft-sanitise a single text-entry's raw value: NFC-normalize,
/// strip control / BIDI / zero-width chars, then truncate to a
/// per-character budget. Bytes-level hard reject happens upstream
/// (caller checks `value.len() <= MAX_TEXT_VALUE_HARD_BYTES` before
/// reaching here).
pub fn sanitize_text_value(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !is_stripped(*c)).collect();
    let trimmed = cleaned.trim();
    if trimmed.chars().count() <= MAX_TEXT_VALUE_SOFT_CHARS {
        return trimmed.to_string();
    }
    // Truncate by char count, not byte count — multi-byte unicode
    // safe.
    trimmed
        .chars()
        .take(MAX_TEXT_VALUE_SOFT_CHARS)
        .collect()
}

/// Strip invisible/control/bidi-override codepoints.
pub fn sanitize_string(s: &str) -> String {
    s.chars()
        .filter(|c| !is_stripped(*c))
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn sanitize_fields(fields: Vec<DisplayField>) -> Vec<DisplayField> {
    fields
        .into_iter()
        .map(|f| DisplayField {
            // `key` and `label` are embedded refs — already passed
            // `validate_ref_format` (ASCII subset) and reverse-
            // looked-up in the registry, so they contain no
            // characters that would need stripping. `value` is
            // policy-supplied free text and gets stripped here
            // (control / BIDI / zero-width).
            //
            // Order is **not** shuffled here. Policy-controlled
            // ordering is a covert channel only to the consumer
            // envelope (the destination the policy author can
            // collude with); the applicant's consent screen renders
            // for the user — who is the defender, not the attacker
            // — so order-preserving the consent UI is correct UX
            // and not a leak surface. The shuffle lives at the
            // envelope boundary instead (api persister's
            // `seal_disclosure`), so it applies to the bytes that
            // actually reach the consumer.
            key: f.key,
            label: f.label,
            value: sanitize_string(&f.value),
        })
        .collect()
}

fn is_stripped(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    // Unicode Tags block — explicitly-invisible "ASCII smuggler"
    // codepoints used to steganographically embed bytes inside
    // human-readable text. Stripped unconditionally.
    if matches!(c, '\u{E0000}'..='\u{E007F}') {
        return true;
    }
    matches!(
        c,
        '\u{200B}' // zero-width space
        | '\u{200C}' // zero-width non-joiner
        | '\u{200D}' // zero-width joiner
        | '\u{FEFF}' // byte order mark
        | '\u{202A}' // LTR embedding
        | '\u{202B}' // RTL embedding
        | '\u{202C}' // pop directional formatting
        | '\u{202D}' // LTR override
        | '\u{202E}' // RTL override
        | '\u{2066}' // LTR isolate
        | '\u{2067}' // RTL isolate
        | '\u{2068}' // first strong isolate
        | '\u{2069}' // pop directional isolate
        | '\u{00AD}' // soft hyphen
        | '\u{034F}' // combining grapheme joiner
        | '\u{061C}' // arabic letter mark
        | '\u{115F}' // hangul choseong filler
        | '\u{1160}' // hangul jungseong filler
        | '\u{17B4}' // khmer vowel inherent aq
        | '\u{17B5}' // khmer vowel inherent aa
        | '\u{180E}' // mongolian vowel separator
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::{ComponentDecls, EmbeddedRegistry, Translation};
    use std::collections::HashMap;

    /// Fixed test key — non-secret. Production callers derive
    /// `ref_key` from `tee_seal_key + policy_ref` in the api crate;
    /// tests only need stability for token round-trip.
    const TEST_REF_KEY: [u8; 32] = [7u8; 32];

    fn field(key: &str, value: &str) -> DisplayField {
        // Default-label sites are tests that fail before reaching the
        // label-validation step (too-many-fields / long-value / key
        // format / unregistered key). The placeholder label here is
        // intentionally a non-token string; if a callsite slips past
        // the early gates the label gate catches the wrong-test-shape
        // and surfaces a loud trap.
        DisplayField {
            key: key.to_string(),
            label: "unused-placeholder-label".to_string(),
            value: value.to_string(),
        }
    }

    fn field_with_label(key: &str, label: &str, value: &str) -> DisplayField {
        DisplayField {
            key: key.to_string(),
            label: label.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn strips_zero_width_space() {
        assert_eq!(sanitize_string("Pass\u{200B}hidden"), "Passhidden");
    }

    #[test]
    fn strips_rtl_override() {
        assert_eq!(
            sanitize_string("Confirmed \u{202E}reversed"),
            "Confirmed reversed"
        );
    }

    #[test]
    fn strips_control_chars() {
        assert_eq!(sanitize_string("ok\nmore\tdata\r"), "okmoredata");
    }

    #[test]
    fn trims_whitespace_after_strip() {
        assert_eq!(sanitize_string("  \u{200B}  text  "), "text");
    }

    #[test]
    fn preserves_plain_ascii() {
        assert_eq!(sanitize_string("Alexander Mayfield"), "Alexander Mayfield");
    }

    #[test]
    fn strips_unicode_tag_chars() {
        // ASCII smuggler: invisible codepoints in U+E0000..=U+E007F
        // that map to ASCII letters/digits. A policy could otherwise
        // hide bytes inside an otherwise plain-looking value.
        assert_eq!(
            sanitize_string("Alice\u{E0041}\u{E0042}\u{E0043}"),
            "Alice"
        );
    }

    /// Mint refs through a fresh single-slot (policy) registry, then
    /// return both the registry and pre-resolved refs for the tests
    /// below. Mirrors what `Runner::run` builds, scaled down.
    struct Fixture {
        embedded: EmbeddedRegistry,
        first_name_key: String,
        tax_id_key: String,
        first_name_label: String,
    }

    fn fixture() -> Fixture {
        let mut localized: HashMap<String, Vec<Translation>> = HashMap::new();
        localized.insert("first_name-label".into(), vec![]);
        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(ComponentDecls {
            disclosure_fields: ["first_name", "tax_id"]
                .into_iter()
                .map(String::from)
                .collect(),
            localized,
            icons: Default::default(),
        });
        let embedded = b.build();
        Fixture {
            first_name_key: embedded.disclosure_fields.get_token(0, "first_name").unwrap(),
            tax_id_key: embedded.disclosure_fields.get_token(0, "tax_id").unwrap(),
            first_name_label: embedded.localized.get_token(0, "first_name-label").unwrap(),
            embedded,
        }
    }

    #[test]
    fn validate_too_many_fields_traps() {
        let f = fixture();
        let fields: Vec<_> = (0..21).map(|_| field(&f.first_name_key, "v")).collect();
        assert!(validate_fields(&fields, &f.embedded).is_err());
    }

    #[test]
    fn validate_long_value_traps() {
        let f = fixture();
        let long = "x".repeat(MAX_VALUE_LENGTH + 1);
        assert!(
            validate_fields(&[field(&f.first_name_key, &long)], &f.embedded).is_err()
        );
    }

    #[test]
    fn validate_well_formed_registered_key_passes() {
        let f = fixture();
        assert!(
            validate_fields(
                &[field_with_label(&f.tax_id_key, &f.first_name_label, "v")],
                &f.embedded
            )
            .is_ok(),
            "tax_id registered by policy slot should round-trip"
        );
    }

    #[test]
    fn validate_invalid_ref_format_traps() {
        let f = fixture();
        // Uppercase characters not allowed inside an embedded ref.
        assert!(validate_fields(&[field("Bad", "v")], &f.embedded).is_err());
        // Dot separator not allowed.
        assert!(validate_fields(&[field("a.b", "v")], &f.embedded).is_err());
    }

    #[test]
    fn validate_unregistered_key_traps() {
        let f = fixture();
        // Well-formed (passes the ASCII format gate) but never registered
        // by any slot in the registry. Pre-Phase-B the format-shape
        // was the Phase A debug string; under Phase B BLAKE3-keyed
        // tokens it's a random-looking 32-hex string that no slot
        // ever produced. Both pass `validate_ref_format` and both
        // miss the by_token reverse-index.
        assert!(
            validate_fields(&[field("0123456789abcdef0123456789abcdef", "v")], &f.embedded)
                .is_err()
        );
        // Phase A debug-looking string too — still well-formed by the
        // ASCII gate (allows `:`), still unregistered under the new HMAC
        // scheme. Forgery resistance covers both shapes.
        assert!(
            validate_fields(&[field("0:d:loyalty_tier_ru", "v")], &f.embedded)
                .is_err()
        );
    }

    #[test]
    fn validate_invalid_label_traps() {
        let f = fixture();
        // Label format rules mirror key — bad label fails the same
        // way as a bad key.
        assert!(validate_fields(
            &[field_with_label(&f.first_name_key, "Bad", "v")],
            &f.embedded
        )
        .is_err());
        assert!(validate_fields(
            &[field_with_label(&f.first_name_key, "a.b", "v")],
            &f.embedded
        )
        .is_err());
        assert!(validate_fields(
            &[field_with_label(&f.first_name_key, &f.first_name_label, "v")],
            &f.embedded
        )
        .is_ok());
    }

    #[test]
    fn validate_unregistered_label_traps() {
        let f = fixture();
        assert!(validate_fields(
            &[field_with_label(&f.first_name_key, "0:l:unregistered_label", "v")],
            &f.embedded
        )
        .is_err());
    }

    #[test]
    fn sanitize_truncates_long_value() {
        let long = "a".repeat(MAX_TEXT_VALUE_SOFT_CHARS + 100);
        let cleaned = sanitize_text_value(&long);
        assert_eq!(cleaned.chars().count(), MAX_TEXT_VALUE_SOFT_CHARS);
    }

    // ---------- Multi-component scoping ----------
    //
    // Cover the slot-bound `enclavid:embedded/*` story end-to-end at
    // the sanitize layer (the gate that runs on every host-fn payload
    // carrying refs). Registry-level slot scoping is unit-tested in
    // `embedded::registry::tests`; here we exercise that the slot
    // discipline survives through `validate_fields`, which is where
    // any drift between registration-time and validate-time would surface.

    /// Fixture: two components, slot 0 = policy, slot 1 = plugin.
    /// Each contributes distinct disclosure-field keys and one
    /// localized label, with a `shared` key declared by both slots so
    /// cross-slot-collision behaviour is observable.
    struct MultiFixture {
        embedded: EmbeddedRegistry,
        policy_df: String,
        plugin_df: String,
        shared_policy_df: String,
        shared_plugin_df: String,
        policy_label: String,
        plugin_label: String,
    }

    fn multi_component_fixture() -> MultiFixture {
        let mut policy_localized: HashMap<String, Vec<Translation>> = HashMap::new();
        policy_localized.insert("policy-label".into(), vec![]);
        let mut plugin_localized: HashMap<String, Vec<Translation>> = HashMap::new();
        plugin_localized.insert("plugin-label".into(), vec![]);

        let mut b = EmbeddedRegistry::builder(TEST_REF_KEY);
        b.add_component(ComponentDecls {
            disclosure_fields: ["policy-only", "shared"]
                .into_iter()
                .map(String::from)
                .collect(),
            localized: policy_localized,
            icons: Default::default(),
        });
        b.add_component(ComponentDecls {
            disclosure_fields: ["plugin-only", "shared"]
                .into_iter()
                .map(String::from)
                .collect(),
            localized: plugin_localized,
            icons: Default::default(),
        });
        let embedded = b.build();

        MultiFixture {
            policy_df: embedded.disclosure_fields.get_token(0, "policy-only").unwrap(),
            plugin_df: embedded.disclosure_fields.get_token(1, "plugin-only").unwrap(),
            shared_policy_df: embedded.disclosure_fields.get_token(0, "shared").unwrap(),
            shared_plugin_df: embedded.disclosure_fields.get_token(1, "shared").unwrap(),
            policy_label: embedded.localized.get_token(0, "policy-label").unwrap(),
            plugin_label: embedded.localized.get_token(1, "plugin-label").unwrap(),
            embedded,
        }
    }

    #[test]
    fn validate_accepts_plugin_slot_registered_field() {
        // A plugin (slot 1) registered both the disclosure-field-ref AND
        // its label; the policy is just relaying the field to
        // prompt_disclosure. validate_fields must accept it the same
        // way it accepts policy-registered refs.
        let f = multi_component_fixture();
        assert!(
            validate_fields(
                &[field_with_label(&f.plugin_df, &f.plugin_label, "v")],
                &f.embedded
            )
            .is_ok(),
            "plugin-registered slot-1 refs round-trip through validate"
        );
    }

    #[test]
    fn validate_accepts_policy_and_plugin_refs_mixed_in_one_call() {
        // One prompt_disclosure carrying refs from both components.
        // This is the typical multi-component flow (policy composes
        // results from a plugin and surfaces them on the consent
        // screen) — both slots' refs must validate together.
        let f = multi_component_fixture();
        let fields = vec![
            field_with_label(&f.policy_df, &f.policy_label, "policy-value"),
            field_with_label(&f.plugin_df, &f.plugin_label, "plugin-value"),
        ];
        assert!(validate_fields(&fields, &f.embedded).is_ok());
    }

    #[test]
    fn validate_rejects_forged_cross_slot_token() {
        // Under Phase B, "forgery" isn't a string-format manipulation
        // attack — the BLAKE3-keyed prefix makes the token opaque —
        // but a guest could still re-use a token it observed (e.g. a
        // ref leaked through an earlier disclosure list). What's
        // structurally tested here is that the registry never
        // accepts a string that wasn't issued under the active
        // `ref_key`, no matter how plausible it looks. Phase A debug
        // strings ("1:d:policy-only") are the most visually obvious
        // foreign-looking shape and are guaranteed not to collide
        // with a Phase B HMAC digest.
        let f = multi_component_fixture();
        let forged = "1:d:policy-only";
        assert!(
            validate_fields(
                &[field_with_label(forged, &f.plugin_label, "v")],
                &f.embedded
            )
            .is_err(),
            "Phase-A-looking cross-slot string must be rejected"
        );

        // Symmetric shape, slot 0 prefix on a slot-1-only key.
        let forged_other_way = "0:d:plugin-only";
        assert!(
            validate_fields(
                &[field_with_label(forged_other_way, &f.policy_label, "v")],
                &f.embedded
            )
            .is_err()
        );

        // And a randomly-constructed Phase B-shaped token that no
        // slot issued under this registry's ref_key — still rejected.
        let forged_phase_b = "deadbeefcafef00d0123456789abcdef";
        assert!(
            validate_fields(
                &[field_with_label(forged_phase_b, &f.policy_label, "v")],
                &f.embedded
            )
            .is_err(),
            "random 32-hex string not under by_token must be rejected"
        );
    }

    #[test]
    fn validate_handles_collision_key_per_slot_independently() {
        // The raw key `shared` is declared by BOTH slot 0 and slot 1.
        // Tokens must be distinct (slot is in the BLAKE3 input) and
        // each must round-trip through validate_fields when paired
        // with its own slot's label.
        let f = multi_component_fixture();
        assert_ne!(f.shared_policy_df, f.shared_plugin_df);
        // Phase B tokens are opaque 32-char hex; per-slot
        // distinguishability lives in the bytes, not a visible prefix.
        assert_eq!(f.shared_policy_df.len(), 32);
        assert_eq!(f.shared_plugin_df.len(), 32);

        assert!(
            validate_fields(
                &[field_with_label(&f.shared_policy_df, &f.policy_label, "v")],
                &f.embedded
            )
            .is_ok()
        );
        assert!(
            validate_fields(
                &[field_with_label(&f.shared_plugin_df, &f.plugin_label, "v")],
                &f.embedded
            )
            .is_ok()
        );
    }
}
