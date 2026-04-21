//! Hardening for expose_data: size limits + unicode sanitization.
//! Runs inside attested TEE code; policy cannot bypass.

use crate::enclavid::disclosure::disclosure::DisplayField;

pub const MAX_EXPOSE_FIELDS: usize = 20;
pub const MAX_LABEL_LENGTH: usize = 50;
pub const MAX_VALUE_LENGTH: usize = 200;

/// Enforce structural limits. Policies exceeding them trap —
/// this is a programming error, not user input.
pub fn validate_fields(fields: &[DisplayField]) -> wasmtime::Result<()> {
    if fields.len() > MAX_EXPOSE_FIELDS {
        return Err(wasmtime::Error::msg(format!(
            "expose_data exceeds {MAX_EXPOSE_FIELDS} fields"
        )));
    }
    for field in fields {
        if field.label.len() > MAX_LABEL_LENGTH {
            return Err(wasmtime::Error::msg(format!(
                "expose_data label exceeds {MAX_LABEL_LENGTH} bytes"
            )));
        }
        if field.value.len() > MAX_VALUE_LENGTH {
            return Err(wasmtime::Error::msg(format!(
                "expose_data value exceeds {MAX_VALUE_LENGTH} bytes"
            )));
        }
    }
    Ok(())
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
            label: sanitize_string(&f.label),
            value: sanitize_string(&f.value),
        })
        .collect()
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

    fn field(label: &str, value: &str) -> DisplayField {
        DisplayField {
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
    fn validate_too_many_fields_traps() {
        let fields: Vec<_> = (0..21).map(|i| field(&format!("l{i}"), "v")).collect();
        assert!(validate_fields(&fields).is_err());
    }

    #[test]
    fn validate_long_label_traps() {
        let long = "x".repeat(MAX_LABEL_LENGTH + 1);
        assert!(validate_fields(&[field(&long, "v")]).is_err());
    }

    #[test]
    fn validate_long_value_traps() {
        let long = "x".repeat(MAX_VALUE_LENGTH + 1);
        assert!(validate_fields(&[field("l", &long)]).is_err());
    }

    #[test]
    fn validate_at_limits_ok() {
        let label = "x".repeat(MAX_LABEL_LENGTH);
        let value = "x".repeat(MAX_VALUE_LENGTH);
        let fields: Vec<_> = (0..MAX_EXPOSE_FIELDS).map(|_| field(&label, &value)).collect();
        assert!(validate_fields(&fields).is_ok());
    }
}
