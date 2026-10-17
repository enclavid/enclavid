//! The props a consumer gives a session: a JSON value, kept at creation as the
//! compact JSON it came in ([`encode`]).
//!
//! What the value may be is the policy's to say — it declares the type the
//! props become, a record as a rule. The execution-worker reads them against
//! that type when the session is prepared (`crate::init`), and where they do not
//! fit, says where and why; api writes that answer for the consumer ([`fault`])
//! only once it is one the props themselves bear out. Here they are only held
//! to a size, [`MAX_PROPS_SIZE`]: the bulk-matching defence, so a consumer
//! cannot smuggle a database of names in and read match results back out.

use std::fmt::Write;

use serde_json::{Map, Value as Json};

use engine_types::props::{PropsProblem, PropsRefusal, Step};
use session_types::{MAX_PROPS_AT_BYTES, PropsFault};

use crate::limits::MAX_PROPS_SIZE;

/// How [`PropsFault::at`] names the props themselves.
const ROOT: &str = "props";

/// The props as api keeps them: empty when the consumer gave none, else the
/// value as compact JSON. `None` when that is over [`MAX_PROPS_SIZE`].
pub fn encode(props: Option<&Json>) -> Option<Vec<u8>> {
    let Some(props) = props else {
        return Some(Vec::new());
    };
    // A JSON value always serializes; a failure would only be refused.
    let json = serde_json::to_vec(props).ok()?;
    (json.len() <= MAX_PROPS_SIZE).then_some(json)
}

/// The worker's `refusal` of the props `json` as the consumer reads it: the
/// place written as the props spell it — `props.inner.flag`, `props.tags[1]` —
/// and the problem. `None` when the props do not bear the refusal out.
///
/// What the props bear out is checked, and nothing else is let through: the
/// place must be one the props hold, and the problem one their value there has
/// — not a bool where a bool is wanted, a string where an enum's case is, an
/// object where a field is missing, a key the record lacks. So what the
/// consumer reads is a problem from a fixed set at a place in its own props,
/// whatever the worker said; the names in it are the consumer's own keys. How
/// the place is written is api's.
///
/// Props not given are read by the worker as a record with no field given, or
/// as `null`: what either bears out at the props themselves, an empty object
/// bears out alike — a field missing, or a value wanted that is not there.
pub fn fault(refusal: &PropsRefusal, json: &[u8]) -> Option<PropsFault> {
    let given = !json.is_empty();
    let json: &[u8] = if given { json } else { b"{}" };
    let props = serde_json::from_slice::<Json>(json).ok();
    let root = refusal.path.is_empty();
    let bears_out = match (&refusal.problem, &props) {
        (PropsProblem::NotJson, props) => root && props.is_none(),
        (PropsProblem::NotDeclared, Some(props)) => {
            root && given && *props != Json::Object(Map::new())
        }
        (PropsProblem::TooLong, Some(_)) => root,
        (problem, Some(props)) => {
            at(props, &refusal.path).is_some_and(|value| has(*problem, value, &refusal.path))
        }
        (_, None) => false,
    };
    bears_out.then(|| PropsFault {
        at: written(&refusal.path),
        problem: refusal.problem,
    })
}

/// The value `path` leads to in `props`, if they hold one there.
fn at<'a>(props: &'a Json, path: &[Step]) -> Option<&'a Json> {
    path.iter()
        .try_fold(props, |value, step| match (step, value) {
            (Step::Key(key), Json::Object(fields)) => fields.get(key),
            (Step::Index(i), Json::Array(items)) => items.get(usize::try_from(*i).ok()?),
            _ => None,
        })
}

/// Whether `value`, at the end of `path`, has `problem`.
fn has(problem: PropsProblem, value: &Json, path: &[Step]) -> bool {
    use PropsProblem as P;
    match problem {
        P::ShouldBeBool => !value.is_boolean(),
        P::ShouldBeWholeNumber | P::ShouldBeNumber => !value.is_number(),
        P::ShouldBeOneCharacter => value.as_str().is_none_or(|s| s.chars().count() != 1),
        P::ShouldBeString => !value.is_string(),
        P::ShouldBeArray => !value.is_array(),
        P::ShouldBeObject => !value.is_object(),
        // A value given for a type props cannot hold: any value the props hold.
        P::Unholdable => true,
        P::NotACase => value.is_string(),
        P::OutOfRange => value.is_number(),
        // The value is there, so the key is: the last step names it.
        P::UnknownField => matches!(path.last(), Some(Step::Key(_))),
        P::Missing => value.is_object(),
        // Said of the props themselves, and checked as such above.
        P::NotDeclared | P::NotJson | P::TooLong => false,
    }
}

/// `path` as the props spell it, cut on a character past [`MAX_PROPS_AT_BYTES`].
fn written(path: &[Step]) -> String {
    let mut at = String::from(ROOT);
    for step in path {
        let _ = match step {
            Step::Key(key) => write!(at, ".{key}"),
            Step::Index(i) => write!(at, "[{i}]"),
        };
    }
    let mut end = at.len().min(MAX_PROPS_AT_BYTES);
    while !at.is_char_boundary(end) {
        end -= 1;
    }
    at.truncate(end);
    at
}

#[cfg(test)]
mod tests;
