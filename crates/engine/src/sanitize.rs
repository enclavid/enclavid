//! Hardening for the policy → host text channel. Runs inside the
//! attested TEE; policy cannot bypass.
//!
//! Two surfaces are sanitised here:
//!
//!   1. `DisplayField`s from `prompt-disclosure` — structured consent
//!      data shown to the applicant and persisted to the consumer.
//!      `value` is policy-supplied free text (typically the actual
//!      PII like "Alice"); `key` and `label` are text-refs into the
//!      policy's registry (membership-checked + format-validated).
//!   2. `translation` entries inside `localized-text` declarations
//!      from `prepare-text-refs` — the registered constant strings
//!      policy can reference at use sites. Sanitised once at
//!      registration time, cached thereafter — never re-sanitised
//!      at lookup.
//!
//! Stripping rules (control chars, BIDI overrides, zero-width chars,
//! Unicode tag characters) are shared across both surfaces; only the
//! length budgets differ.

use std::collections::HashSet;

use crate::enclavid::disclosure::disclosure::DisplayField;
use crate::limits::{
    MAX_EXPOSE_FIELDS, MAX_KEY_LENGTH, MAX_LANGUAGE_LENGTH, MAX_TEXT_VALUE_SOFT_CHARS,
    MAX_VALUE_LENGTH,
};

/// Enforce structural limits + registration on `DisplayField`s from
/// `prompt-disclosure`. Policies exceeding them trap — this is a
/// programming error or a covert-channel attempt, not user input.
///
/// Both `key` and `label` are checked against `registered` (the set
/// of text-refs the policy declared via `prepare-localized-texts`).
/// Membership matters because that declaration runs before the
/// policy ever sees per-session args — refusing unregistered refs
/// at this point blocks any "craft a text-ref string from user
/// attribute bits at evaluate time" pattern. Unregistered = trap.
pub fn validate_fields(
    fields: &[DisplayField],
    registered: &HashSet<String>,
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
        ensure_registered(&field.key, registered, "prompt_disclosure field key")?;
        ensure_registered(&field.label, registered, "prompt_disclosure field label")?;
    }
    Ok(())
}

/// Format-validate + check membership in the policy's pre-declared
/// text-ref set. Used at every text-ref use-site inside host fns so
/// the engine never accepts a runtime-crafted ref. `role` is the
/// human-readable site name (e.g. "prompt_disclosure reason",
/// "prompt_media spec label") embedded in the error message; helps
/// audit a trap back to the host fn that fired it.
pub fn ensure_registered(
    text_ref: &str,
    registered: &HashSet<String>,
    role: &str,
) -> wasmtime::Result<()> {
    validate_key_format(text_ref)?;
    if !registered.contains(text_ref) {
        return Err(wasmtime::Error::msg(format!(
            "{role} text-ref '{text_ref}' is not registered in prepare-localized-texts"
        )));
    }
    Ok(())
}

/// Validate the structure of a `text-ref` key — applied at
/// registration time (every key emitted from `prepare-text-refs`)
/// and at use-site time (consent field key/label, media labels,
/// consent reason). ASCII letters/digits/`-`/`_`, max 128 chars,
/// must start with a lowercase letter. Allowing `_` alongside `-`
/// lets policy authors keep their language-idiomatic identifier
/// convention; either form parses cleanly and renders harmlessly
/// on the consent screen.
pub fn validate_key_format(key: &str) -> wasmtime::Result<()> {
    if key.is_empty() {
        return Err(wasmtime::Error::msg("text-ref key is empty"));
    }
    if key.len() > MAX_KEY_LENGTH {
        return Err(wasmtime::Error::msg(format!(
            "text-ref key exceeds {MAX_KEY_LENGTH} bytes"
        )));
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(wasmtime::Error::msg(
            "text-ref key must start with lowercase ASCII letter",
        ));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
            return Err(wasmtime::Error::msg(
                "text-ref key contains invalid character (allowed: a-z, 0-9, '-', '_')",
            ));
        }
    }
    Ok(())
}

/// Validate a BCP-47-shaped language tag on a `translation` entry.
/// Cheap defensive check: letters/digits/`-`, ≤16 chars, starts with
/// a letter. Doesn't enforce real BCP-47 grammar — that's a lot of
/// rules for marginal benefit. Goal here is bounding cardinality
/// and rejecting obvious garbage (multi-KB strings, embedded NULs)
/// that policy might try to smuggle through the language field.
pub fn validate_language(lang: &str) -> wasmtime::Result<()> {
    if lang.is_empty() {
        return Err(wasmtime::Error::msg("translation language is empty"));
    }
    if lang.len() > MAX_LANGUAGE_LENGTH {
        return Err(wasmtime::Error::msg(format!(
            "translation language exceeds {MAX_LANGUAGE_LENGTH} bytes"
        )));
    }
    let mut chars = lang.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() {
        return Err(wasmtime::Error::msg(
            "translation language must start with ASCII letter",
        ));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '-') {
            return Err(wasmtime::Error::msg(
                "translation language contains invalid character (allowed: A-Za-z0-9, '-')",
            ));
        }
    }
    Ok(())
}

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
            // `key` and `label` are `text-ref`s — already passed
            // `validate_key_format` (ASCII kebab-case), so they
            // contain no characters that would need stripping.
            // `value` is policy-supplied free text and gets stripped
            // here (control / BIDI / zero-width).
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

    fn field(key: &str, value: &str) -> DisplayField {
        DisplayField {
            key: key.to_string(),
            label: "first-name-label".to_string(),
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

    #[test]
    fn validate_language_accepts_bcp47_shapes() {
        assert!(validate_language("en").is_ok());
        assert!(validate_language("en-US").is_ok());
        assert!(validate_language("zh-Hant-HK").is_ok());
    }

    #[test]
    fn validate_language_rejects_garbage() {
        assert!(validate_language("").is_err()); // empty
        assert!(validate_language("a".repeat(MAX_LANGUAGE_LENGTH + 1).as_str()).is_err());
        assert!(validate_language("1-bad").is_err()); // digit start
        assert!(validate_language("en US").is_err()); // space
        assert!(validate_language("en_US").is_err()); // underscore not BCP-47
        assert!(validate_language("en\u{0}").is_err()); // embedded NUL
    }

    fn registered() -> HashSet<String> {
        ["first-name", "tax-id", "first-name-label"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    #[test]
    fn validate_too_many_fields_traps() {
        let fields: Vec<_> = (0..21).map(|_| field("first-name", "v")).collect();
        assert!(validate_fields(&fields, &registered()).is_err());
    }

    #[test]
    fn validate_long_value_traps() {
        let long = "x".repeat(MAX_VALUE_LENGTH + 1);
        assert!(validate_fields(&[field("first-name", &long)], &registered()).is_err());
    }

    #[test]
    fn validate_invalid_key_traps() {
        // Bad: starts with digit
        assert!(validate_fields(&[field("1bad", "v")], &registered()).is_err());
        // Bad: uppercase
        assert!(validate_fields(&[field("Bad", "v")], &registered()).is_err());
        // Bad: dot separator
        assert!(validate_fields(&[field("a.b", "v")], &registered()).is_err());
        // OK: kebab-case ASCII + registered
        assert!(validate_fields(&[field("tax-id", "v")], &registered()).is_ok());
    }

    #[test]
    fn validate_unregistered_key_traps() {
        // Well-formed but NOT in `prepare-localized-texts` — the
        // timing-based defence: policy can't craft a fresh text-ref
        // at evaluate time based on user attributes.
        assert!(
            validate_fields(&[field("loyalty-tier-ru", "v")], &registered()).is_err()
        );
    }

    #[test]
    fn validate_invalid_label_traps() {
        // Label format rules mirror key — bad label fails the same
        // way as a bad key.
        assert!(validate_fields(
            &[field_with_label("first-name", "Bad", "v")],
            &registered()
        )
        .is_err());
        assert!(validate_fields(
            &[field_with_label("first-name", "a.b", "v")],
            &registered()
        )
        .is_err());
        assert!(validate_fields(
            &[field_with_label("first-name", "first-name-label", "v")],
            &registered()
        )
        .is_ok());
    }

    #[test]
    fn validate_unregistered_label_traps() {
        assert!(validate_fields(
            &[field_with_label("first-name", "unregistered-label", "v")],
            &registered()
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
