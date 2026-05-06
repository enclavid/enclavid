//! Hardening for prompt_disclosure: size limits + unicode sanitization.
//! Runs inside attested TEE code; policy cannot bypass.

use crate::enclavid::disclosure::disclosure::{DisplayField, FieldKey, LocalizedText};

pub const MAX_EXPOSE_FIELDS: usize = 20;
pub const MAX_VALUE_LENGTH: usize = 200;
/// Generous BCP-47 cap (longest realistic tag is ~12 bytes, e.g.
/// `zh-Hant-HK`). Anything longer is policy bug or covert channel.
pub const MAX_CUSTOM_LANGUAGE_LENGTH: usize = 16;
/// Custom label rendered as-is by SDKs. Same budget as old free-text
/// label.
pub const MAX_CUSTOM_TEXT_LENGTH: usize = 50;
/// Purpose-of-use prose shown on the consent screen — longer than a
/// single label since it usually describes one or two sentences worth
/// of justification.
pub const MAX_REASON_TEXT_LENGTH: usize = 200;

/// Enforce structural limits. Policies exceeding them trap —
/// this is a programming error, not user input.
pub fn validate_fields(fields: &[DisplayField]) -> wasmtime::Result<()> {
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
        if let FieldKey::Custom(loc) = &field.key {
            if loc.language.len() > MAX_CUSTOM_LANGUAGE_LENGTH {
                return Err(wasmtime::Error::msg(format!(
                    "prompt_disclosure custom language exceeds {MAX_CUSTOM_LANGUAGE_LENGTH} bytes"
                )));
            }
            if loc.text.len() > MAX_CUSTOM_TEXT_LENGTH {
                return Err(wasmtime::Error::msg(format!(
                    "prompt_disclosure custom text exceeds {MAX_CUSTOM_TEXT_LENGTH} bytes"
                )));
            }
        }
    }
    Ok(())
}

/// Validate a consent prompt's purpose-of-use statement.
pub fn validate_reason(reason: &LocalizedText) -> wasmtime::Result<()> {
    if reason.language.len() > MAX_CUSTOM_LANGUAGE_LENGTH {
        return Err(wasmtime::Error::msg(format!(
            "prompt_disclosure reason language exceeds {MAX_CUSTOM_LANGUAGE_LENGTH} bytes"
        )));
    }
    if reason.text.len() > MAX_REASON_TEXT_LENGTH {
        return Err(wasmtime::Error::msg(format!(
            "prompt_disclosure reason text exceeds {MAX_REASON_TEXT_LENGTH} bytes"
        )));
    }
    Ok(())
}

pub fn sanitize_localized(loc: LocalizedText) -> LocalizedText {
    LocalizedText {
        language: sanitize_string(&loc.language),
        text: sanitize_string(&loc.text),
    }
}

/// Strip invisible/control/bidi-override codepoints.
/// Silent (no error) — sanitization is defensive, not a policy bug signal.
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
            key: sanitize_key(f.key),
            value: sanitize_string(&f.value),
        })
        .collect()
}

fn sanitize_key(key: FieldKey) -> FieldKey {
    match key {
        FieldKey::Custom(loc) => FieldKey::Custom(sanitize_localized(loc)),
        // Well-known variants carry no policy-controlled string content.
        well_known => well_known,
    }
}

fn is_stripped(c: char) -> bool {
    if c.is_control() {
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

    fn known(key: FieldKey, value: &str) -> DisplayField {
        DisplayField {
            key,
            value: value.to_string(),
        }
    }

    fn custom(language: &str, text: &str, value: &str) -> DisplayField {
        DisplayField {
            key: FieldKey::Custom(LocalizedText {
                language: language.to_string(),
                text: text.to_string(),
            }),
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
    fn validate_too_many_fields_traps() {
        let fields: Vec<_> = (0..21)
            .map(|_| known(FieldKey::FirstName, "v"))
            .collect();
        assert!(validate_fields(&fields).is_err());
    }

    #[test]
    fn validate_long_value_traps() {
        let long = "x".repeat(MAX_VALUE_LENGTH + 1);
        assert!(validate_fields(&[known(FieldKey::FirstName, &long)]).is_err());
    }

    #[test]
    fn validate_long_custom_language_traps() {
        let long = "x".repeat(MAX_CUSTOM_LANGUAGE_LENGTH + 1);
        assert!(validate_fields(&[custom(&long, "Tax ID", "v")]).is_err());
    }

    #[test]
    fn validate_long_custom_text_traps() {
        let long = "x".repeat(MAX_CUSTOM_TEXT_LENGTH + 1);
        assert!(validate_fields(&[custom("en", &long, "v")]).is_err());
    }

    #[test]
    fn validate_at_limits_ok() {
        let value = "x".repeat(MAX_VALUE_LENGTH);
        let language = "x".repeat(MAX_CUSTOM_LANGUAGE_LENGTH);
        let text = "x".repeat(MAX_CUSTOM_TEXT_LENGTH);
        let mut fields: Vec<_> = (0..MAX_EXPOSE_FIELDS - 1)
            .map(|_| known(FieldKey::FirstName, &value))
            .collect();
        fields.push(custom(&language, &text, &value));
        assert!(validate_fields(&fields).is_ok());
    }

    #[test]
    fn sanitize_strips_custom_text() {
        let f = custom("en", "Tax\u{200B}ID", "value");
        let cleaned = sanitize_fields(vec![f]);
        match &cleaned[0].key {
            FieldKey::Custom(loc) => assert_eq!(loc.text, "TaxID"),
            _ => panic!("expected custom"),
        }
    }

    fn reason(language: &str, text: &str) -> LocalizedText {
        LocalizedText {
            language: language.to_string(),
            text: text.to_string(),
        }
    }

    #[test]
    fn validate_long_reason_text_traps() {
        let long = "x".repeat(MAX_REASON_TEXT_LENGTH + 1);
        assert!(validate_reason(&reason("en", &long)).is_err());
    }

    #[test]
    fn validate_long_reason_language_traps() {
        let long = "x".repeat(MAX_CUSTOM_LANGUAGE_LENGTH + 1);
        assert!(validate_reason(&reason(&long, "ok")).is_err());
    }

    #[test]
    fn validate_reason_at_limits_ok() {
        let language = "x".repeat(MAX_CUSTOM_LANGUAGE_LENGTH);
        let text = "x".repeat(MAX_REASON_TEXT_LENGTH);
        assert!(validate_reason(&reason(&language, &text)).is_ok());
    }

    #[test]
    fn sanitize_strips_reason_text() {
        let cleaned = sanitize_localized(reason("en", "Required\u{200B}for compliance"));
        assert_eq!(cleaned.text, "Requiredfor compliance");
    }
}
