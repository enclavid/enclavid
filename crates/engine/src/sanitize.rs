//! Hardening for the policy → host text channel. Runs inside the
//! attested TEE; policy cannot bypass.
//!
//! Since embedded refs became unforgeable resource handles the host
//! mints from DECLARED keys, there is nothing to validate at the ref
//! boundary — a component can't fabricate a `key` / `label` / `icon`.
//! What remains is stripping of the free-text surfaces:
//!
//!   1. `DisplayField.value` — policy-supplied free text (typically the
//!      actual PII like "Alice") on a `consent-disclosure` render.
//!   2. `translation` entries inside `i18n` sections — the registered
//!      constant strings, sanitised once at registration time.
//!
//! Stripping rules (control chars, BIDI overrides, zero-width chars,
//! Unicode tag characters) are shared; only the length budgets differ.
//! Length / field-count limits on a disclosure are enforced at the
//! action boundary (`runner::convert`), where the fields are built.

use crate::limits::MAX_TEXT_VALUE_SOFT_CHARS;

/// Soft-sanitise a single text-entry's raw value: strip control / BIDI /
/// zero-width / Unicode-tag chars, then truncate to a per-character
/// budget. Used on `i18n` translation values at registration time
/// (re-exported for the api crate, which applies the same stripping to
/// manifest translation values).
pub fn sanitize_text_value(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !is_stripped(*c)).collect();
    let trimmed = cleaned.trim();
    if trimmed.chars().count() <= MAX_TEXT_VALUE_SOFT_CHARS {
        return trimmed.to_string();
    }
    // Truncate by char count, not byte count — multi-byte unicode safe.
    trimmed.chars().take(MAX_TEXT_VALUE_SOFT_CHARS).collect()
}

/// Strip invisible/control/bidi-override codepoints and trim. Applied to
/// `DisplayField.value` at the disclosure boundary.
pub fn sanitize_string(s: &str) -> String {
    s.chars()
        .filter(|c| !is_stripped(*c))
        .collect::<String>()
        .trim()
        .to_string()
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

    #[test]
    fn strips_zero_width_space() {
        assert_eq!(sanitize_string("Pass\u{200B}hidden"), "Passhidden");
    }

    #[test]
    fn strips_rtl_override() {
        assert_eq!(sanitize_string("Confirmed \u{202E}reversed"), "Confirmed reversed");
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
        // ASCII smuggler: invisible codepoints in U+E0000..=U+E007F that
        // map to ASCII letters/digits.
        assert_eq!(sanitize_string("Alice\u{E0041}\u{E0042}\u{E0043}"), "Alice");
    }

    #[test]
    fn sanitize_truncates_long_value() {
        let long = "a".repeat(MAX_TEXT_VALUE_SOFT_CHARS + 100);
        assert_eq!(sanitize_text_value(&long).chars().count(), MAX_TEXT_VALUE_SOFT_CHARS);
    }
}
