//! Hardening for the policy → host text channel. Runs inside the
//! attested TEE; policy cannot bypass.
//!
//! Since embedded refs became unforgeable resource handles the host
//! mints from DECLARED keys, there is nothing to validate at the ref
//! boundary — a component can't fabricate a `key` / `label` / `icon`.
//! What remains is sanitising the free-text surfaces:
//!
//!   1. `DisplayField.value` — policy-supplied free text (typically the
//!      actual PII like "Alice") on a `consent-disclosure` render.
//!   2. `translation` entries inside `i18n` sections — the registered
//!      constant strings, sanitised once at registration time.
//!
//! These strings are BOTH shown to the applicant (the sole auditor) AND
//! sealed to the consumer, so any INVISIBLE character is a covert channel:
//! it carries data the applicant never sees. We defend with a WHITELIST
//! (default-deny), not a blacklist of known-bad codepoints — a blacklist
//! inevitably has gaps (a new zero-width / variation-selector / tag char
//! slips through, which is exactly how this surface regressed before),
//! whereas a whitelist fails CLOSED on anything it doesn't recognise. See
//! [`is_allowed`]: only VISIBLE-content general categories pass
//! (letters / marks / numbers / punctuation / symbols / space — by
//! CATEGORY, so it is script-agnostic and every country's names survive),
//! minus the handful of invisible Default_Ignorable codepoints that
//! masquerade as marks / letters. Length / field-count limits on a
//! disclosure are enforced at the action boundary (`runner::convert`).

use unicode_general_category::{GeneralCategory, get_general_category};

use crate::limits::MAX_TEXT_VALUE_SOFT_CHARS;

/// Soft-sanitise a single text-entry's raw value: keep only whitelisted
/// (visible-content) characters, then truncate to a per-character budget.
/// Used on `i18n` translation values at registration time (re-exported
/// for the api crate, which applies the same whitelist to manifest
/// translation values).
pub fn sanitize_text_value(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| is_allowed(*c)).collect();
    let trimmed = cleaned.trim();
    if trimmed.chars().count() <= MAX_TEXT_VALUE_SOFT_CHARS {
        return trimmed.to_string();
    }
    // Truncate by char count, not byte count — multi-byte unicode safe.
    trimmed.chars().take(MAX_TEXT_VALUE_SOFT_CHARS).collect()
}

/// Keep only whitelisted (visible-content) characters and trim. Applied to
/// `DisplayField.value` at the disclosure boundary.
pub fn sanitize_string(s: &str) -> String {
    s.chars()
        .filter(|c| is_allowed(*c))
        .collect::<String>()
        .trim()
        .to_string()
}

/// Whitelist predicate: is `c` a VISIBLE content character safe to show ==
/// seal? Default-DENY — a char passes only if its Unicode General_Category is
/// one that renders visible content, and it is not one of the few invisible
/// Default_Ignorable codepoints that live inside those categories.
fn is_allowed(c: char) -> bool {
    use GeneralCategory::*;
    // Whitelist by category. Denied by default (and thus dropped): control
    // (Cc), format (Cf: ZWJ / ZWNJ / WORD JOINER / BIDI overrides / BOM / the
    // Tags block / invisible math operators / ...), line & paragraph separators
    // (Zl / Zp), surrogates (Cs), PRIVATE-USE (Co) and UNASSIGNED (Cn) — the last
    // two a blacklist would have missed entirely. Only `SpaceSeparator` (Zs)
    // passes among separators; other whitespace (tabs/newlines) is Cc → dropped,
    // as before.
    let visible = matches!(
        get_general_category(c),
        UppercaseLetter
            | LowercaseLetter
            | TitlecaseLetter
            | ModifierLetter
            | OtherLetter
            | NonspacingMark
            | SpacingMark
            | EnclosingMark
            | DecimalNumber
            | LetterNumber
            | OtherNumber
            | ConnectorPunctuation
            | DashPunctuation
            | OpenPunctuation
            | ClosePunctuation
            | InitialPunctuation
            | FinalPunctuation
            | OtherPunctuation
            | MathSymbol
            | CurrencySymbol
            | ModifierSymbol
            | OtherSymbol
            | SpaceSeparator
    );
    if !visible {
        return false;
    }
    // The invisible Default_Ignorable codepoints that sit INSIDE the allowed
    // categories (variation selectors + combining grapheme joiner → Mark;
    // Hangul fillers → Letter; Mongolian free variation selectors → Mark). They
    // are the only Default_Ignorable members not already in a denied category, so
    // this short, stable list — not a growing blacklist — is all the category
    // whitelist needs on top. Legitimate VISIBLE combining marks (accents,
    // harakat, matras — Mn/Mc, NOT Default_Ignorable) are kept.
    !matches!(c,
        '\u{034F}'                    // combining grapheme joiner
        | '\u{115F}'..='\u{1160}'     // hangul choseong / jungseong filler
        | '\u{17B4}'..='\u{17B5}'     // khmer vowel inherent aq / aa
        | '\u{180B}'..='\u{180F}'     // mongolian free variation selectors (+ MVS)
        | '\u{3164}'                  // hangul filler
        | '\u{FE00}'..='\u{FE0F}'     // variation selectors 1-16
        | '\u{FFA0}'                  // halfwidth hangul filler
        | '\u{E0100}'..='\u{E01EF}'   // variation selectors supplement (17-256)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- blacklist-era cases still hold ---

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
        // ASCII smuggler: invisible codepoints in the Tags block (Cf).
        assert_eq!(sanitize_string("Alice\u{E0041}\u{E0042}\u{E0043}"), "Alice");
    }

    #[test]
    fn sanitize_truncates_long_value() {
        let long = "a".repeat(MAX_TEXT_VALUE_SOFT_CHARS + 100);
        assert_eq!(sanitize_text_value(&long).chars().count(), MAX_TEXT_VALUE_SOFT_CHARS);
    }

    // --- the invisibles the blacklist MISSED (the V3 gap) ---

    #[test]
    fn strips_word_joiner_and_invisible_format() {
        // U+2060 WORD JOINER + U+2061 FUNCTION APPLICATION (invisible math),
        // both Cf — the classic blacklist gaps.
        assert_eq!(sanitize_string("Ber\u{2060}lin\u{2061}"), "Berlin");
    }

    #[test]
    fn strips_variation_selectors_incl_supplement() {
        // Variation selectors (Mn, Default_Ignorable) masquerade as marks — the
        // basic plane (FE00-FE0F) AND the supplement above the old E007F ceiling.
        assert_eq!(sanitize_string("Berlin\u{FE0F}"), "Berlin");
        assert_eq!(sanitize_string("Berlin\u{E0100}"), "Berlin");
        assert_eq!(sanitize_string("A\u{034F}B"), "AB"); // combining grapheme joiner
    }

    #[test]
    fn strips_private_use_and_line_separator() {
        // Default-deny wins a blacklist wouldn't get: private-use (Co, renders as
        // .notdef) and line separator (Zl) are dropped.
        assert_eq!(sanitize_string("A\u{E000}B"), "AB");
        assert_eq!(sanitize_string("line1\u{2028}line2"), "line1line2");
    }

    #[test]
    fn strips_hangul_fillers() {
        // Invisible Letter-category codepoints (Lo, Default_Ignorable).
        assert_eq!(sanitize_string("A\u{3164}B\u{FFA0}"), "AB");
    }

    // --- legitimate global identity data survives (no over-stripping) ---

    #[test]
    fn keeps_multiscript_names() {
        // Cyrillic, CJK, Greek — all visible letters, kept verbatim.
        for name in ["Иван Петров", "李明", "Γεώργιος"] {
            assert_eq!(sanitize_string(name), name);
        }
    }

    #[test]
    fn keeps_legitimate_combining_marks() {
        // Decomposed Latin accent (o + COMBINING ACUTE, Mn non-DI) and an Arabic
        // letter + harakat (FATHA, Mn non-DI) are VISIBLE diacritics — kept, unlike
        // a width-0 blanket strip which would have corrupted them.
        assert_eq!(sanitize_string("Jose\u{0301}"), "Jose\u{0301}");
        assert_eq!(sanitize_string("\u{0639}\u{064E}"), "\u{0639}\u{064E}");
    }

    #[test]
    fn keeps_digits_and_punctuation() {
        assert_eq!(sanitize_string("Doc AB-123/45.6"), "Doc AB-123/45.6");
    }
}
