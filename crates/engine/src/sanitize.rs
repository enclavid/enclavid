//! Hardening for the policy → host text channel. Runs inside the
//! attested TEE; policy cannot bypass.
//!
//! Two surfaces are sanitised here:
//!
//!   1. `DisplayField`s from `prompt-disclosure` — structured consent
//!      data shown to the applicant and persisted to the consumer.
//!      `value` is policy-supplied free text (typically the actual
//!      PII like "Alice"); `key` and `label` are embedded refs minted
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

use crate::embedded::{DisclosureFieldsStore, EmbeddedRegistry, LocalizedStore};
use crate::enclavid::disclosure::types::DisplayField;
use crate::limits::{
    MAX_EXPOSE_FIELDS, MAX_KEY_LENGTH, MAX_TEXT_VALUE_SOFT_CHARS, MAX_VALUE_LENGTH,
};

/// Enforce structural limits + registration on `DisplayField`s from
/// `prompt-disclosure`. Policies exceeding them trap — this is a
/// programming error or a covert-channel attempt, not user input.
///
/// `key` is a disclosure-field-ref → reverse-looked-up in the
/// composition's disclosure-fields store; `label` is a localized-ref
/// → looked up in the localized store. Each store only knows tokens
/// it itself minted, so a token that crossed kinds (a localized ref
/// passed as a key, etc.) fails the right-store check and traps
/// cleanly.
pub fn validate_fields(
    fields: &[DisplayField],
    embedded: &EmbeddedRegistry,
) -> wasmtime::Result<()> {
    if fields.len() > MAX_EXPOSE_FIELDS {
        return Err(wasmtime::Error::msg(format!(
            "prompt_disclosure exceeds {MAX_EXPOSE_FIELDS} fields"
        )));
    }
    for field in fields {
        if field.value.len() > MAX_VALUE_LENGTH {
            return Err(wasmtime::Error::msg(format!(
                "prompt_disclosure value exceeds {MAX_VALUE_LENGTH} bytes"
            )));
        }
        ensure_disclosure_field(
            &field.key,
            &embedded.disclosure_fields,
            "prompt_disclosure field key",
        )?;
        ensure_localized(
            &field.label,
            &embedded.localized,
            "prompt_disclosure field label",
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
/// this format check that isn't a minted token fails the membership
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

    fn field(key: &str, value: &str) -> DisplayField {
        DisplayField {
            key: key.to_string(),
            label: "0:l:first_name-label".to_string(),
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
    /// return both the registry and pre-minted refs for the tests
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
        let mut b = EmbeddedRegistry::builder();
        b.add_component(ComponentDecls {
            disclosure_fields: ["first_name", "tax_id"]
                .into_iter()
                .map(String::from)
                .collect(),
            localized,
        });
        let embedded = b.finish();
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
    fn validate_well_formed_minted_key_passes() {
        let f = fixture();
        assert!(
            validate_fields(&[field(&f.tax_id_key, "v")], &f.embedded).is_ok(),
            "tax_id minted by policy slot should round-trip"
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
    fn validate_unminted_key_traps() {
        let f = fixture();
        // Well-formed but never minted by any slot in the registry —
        // the timing-based + cross-component defence: a component
        // can't synthesise a foreign ref at evaluate time.
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
    fn validate_unminted_label_traps() {
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
}
