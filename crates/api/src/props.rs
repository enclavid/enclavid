//! The props a consumer gives a session at creation: a JSON object, kept as the
//! compact JSON the policy later reads them from.
//!
//! What the object may hold is the policy's to say — it declares the record the
//! props become, and the execution-worker refuses a round whose props do not fit
//! it. Here they are only held to a size, [`MAX_PROPS_SIZE`]: the bulk-matching
//! defence, so a consumer cannot smuggle a database of names in and read match
//! results back out.

use serde_json::{Map, Value};

use crate::limits::MAX_PROPS_SIZE;

/// The props as api keeps them: empty when the consumer gave none, else the
/// object as compact JSON. `None` when that is over [`MAX_PROPS_SIZE`].
pub fn encode(props: Option<&Map<String, Value>>) -> Option<Vec<u8>> {
    let Some(props) = props else {
        return Some(Vec::new());
    };
    // A map of JSON values always serializes; a failure would only be refused.
    let json = serde_json::to_vec(props).ok()?;
    (json.len() <= MAX_PROPS_SIZE).then_some(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(json: &str) -> Map<String, Value> {
        serde_json::from_str(json).expect("a JSON object")
    }

    #[test]
    fn no_props_are_kept_as_nothing() {
        assert_eq!(encode(None), Some(Vec::new()));
    }

    #[test]
    fn props_are_kept_as_compact_json() {
        let props = object(r#"{ "min-age": 18, "people": [ { "name": "A" } ] }"#);
        assert_eq!(
            encode(Some(&props)).as_deref(),
            Some(br#"{"min-age":18,"people":[{"name":"A"}]}"#.as_slice())
        );
    }

    #[test]
    fn props_are_held_to_their_size_as_kept() {
        // `{"k":"…"}` is eight bytes around the string.
        let at_bound = object(&format!(r#"{{"k": "{}"}}"#, "x".repeat(MAX_PROPS_SIZE - 8)));
        assert_eq!(
            encode(Some(&at_bound)).map(|json| json.len()),
            Some(MAX_PROPS_SIZE)
        );
        let over = object(&format!(r#"{{"k": "{}"}}"#, "x".repeat(MAX_PROPS_SIZE - 7)));
        assert_eq!(encode(Some(&over)), None);
    }
}
