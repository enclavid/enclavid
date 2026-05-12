//! Parsing of service-provided Match Mode input (JSON bytes in SessionMetadata)
//! into the typed `list<tuple<string, eval-args>>` accepted by `policy.evaluate`.
//!
//! Runs at the API boundary before data enters the engine. Size-capped to
//! prevent bulk-matching exfiltration attacks — a malicious service could
//! otherwise smuggle a database of names in and extract match results.

use serde_json::Value;

use enclavid_engine::EvalArgs;

use crate::limits::MAX_MATCH_INPUT_SIZE;

#[derive(Debug)]
pub enum InputError {
    TooLarge,
    InvalidJson,
    NotAnObject,
    NestedValue,
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "input exceeds {MAX_MATCH_INPUT_SIZE} bytes"),
            Self::InvalidJson => write!(f, "input is not valid JSON"),
            Self::NotAnObject => write!(f, "input must be a JSON object"),
            Self::NestedValue => write!(f, "input values must be scalars (no objects or arrays)"),
        }
    }
}

impl std::error::Error for InputError {}

/// Parse service-provided args into a flat list of typed entries.
/// Returns an empty list if `bytes` is empty.
pub fn parse_input(bytes: &[u8]) -> Result<Vec<(String, EvalArgs)>, InputError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() > MAX_MATCH_INPUT_SIZE {
        return Err(InputError::TooLarge);
    }
    let root: Value = serde_json::from_slice(bytes).map_err(|_| InputError::InvalidJson)?;
    let Value::Object(map) = root else {
        return Err(InputError::NotAnObject);
    };

    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        out.push((k, to_eval_arg(v)?));
    }
    Ok(out)
}

fn to_eval_arg(v: Value) -> Result<EvalArgs, InputError> {
    match v {
        Value::Null => Ok(EvalArgs::Null),
        Value::Bool(b) => Ok(EvalArgs::Bool(b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(EvalArgs::Int(i))
            } else if let Some(f) = n.as_f64() {
                Ok(EvalArgs::Float(f))
            } else {
                Err(InputError::InvalidJson)
            }
        }
        Value::String(s) => Ok(EvalArgs::String(s)),
        Value::Array(_) | Value::Object(_) => Err(InputError::NestedValue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_empty_list() {
        assert!(parse_input(b"").unwrap().is_empty());
    }

    #[test]
    fn empty_object_is_empty_list() {
        assert!(parse_input(b"{}").unwrap().is_empty());
    }

    #[test]
    fn parses_scalars() {
        let parsed = parse_input(
            br#"{"name":"Alex","age":30,"score":1.5,"active":true,"note":null}"#,
        )
        .unwrap();
        let map: std::collections::HashMap<_, _> = parsed.into_iter().collect();
        assert!(matches!(map.get("name"), Some(EvalArgs::String(s)) if s == "Alex"));
        assert!(matches!(map.get("age"), Some(EvalArgs::Int(30))));
        assert!(matches!(map.get("score"), Some(EvalArgs::Float(_))));
        assert!(matches!(map.get("active"), Some(EvalArgs::Bool(true))));
        assert!(matches!(map.get("note"), Some(EvalArgs::Null)));
    }

    #[test]
    fn rejects_nested_object() {
        let err = parse_input(br#"{"addr":{"city":"SF"}}"#).unwrap_err();
        assert!(matches!(err, InputError::NestedValue));
    }

    #[test]
    fn rejects_array_value() {
        let err = parse_input(br#"{"tags":["a","b"]}"#).unwrap_err();
        assert!(matches!(err, InputError::NestedValue));
    }

    #[test]
    fn rejects_non_object_root() {
        let err = parse_input(br#"[1,2,3]"#).unwrap_err();
        assert!(matches!(err, InputError::NotAnObject));
    }

    #[test]
    fn rejects_invalid_json() {
        let err = parse_input(b"not json").unwrap_err();
        assert!(matches!(err, InputError::InvalidJson));
    }

    #[test]
    fn rejects_oversized() {
        let big = vec![b'x'; MAX_MATCH_INPUT_SIZE + 1];
        let err = parse_input(&big).unwrap_err();
        assert!(matches!(err, InputError::TooLarge));
    }
}
