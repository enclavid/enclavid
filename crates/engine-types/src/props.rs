//! Props that do not fit the type a policy declares for them: where in them, and
//! what is wrong there, as the executor reads them against that type before any
//! round — and as api checks that answer against the props it holds before the
//! consumer reads it.

use serde::{Deserialize, Serialize};

/// Where the consumer's props do not fit the type the policy declares, and
/// what is wrong there. Never a value: the values are the consumer's, about the
/// applicant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropsRefusal {
    /// The place, as the steps from the props object into it — empty for the
    /// props themselves. What reads it checks it against the props it holds.
    pub path: Vec<Step>,
    pub problem: PropsProblem,
}

/// One step into the props: a key of an object they hold, or an index of an
/// array.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    Key(String),
    Index(u32),
}

/// What is wrong where props do not fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropsProblem {
    ShouldBeBool,
    ShouldBeWholeNumber,
    ShouldBeNumber,
    ShouldBeOneCharacter,
    ShouldBeString,
    ShouldBeArray,
    ShouldBeObject,
    /// A value given for a type props cannot hold: a tuple, variant, flags,
    /// result or resource.
    Unholdable,
    /// A string that is none of the enum's cases.
    NotACase,
    /// A number its integer type does not hold, or not a whole one.
    OutOfRange,
    /// A key the record does not have; the place is that key.
    UnknownField,
    /// A field the record requires is not given; the place is the object it is
    /// missing from, which the field's name is not part of — the name is the
    /// policy's, and nothing the props hold could vouch for it.
    Missing,
    /// The session has props, and the policy declares none.
    NotDeclared,
    /// Not JSON.
    NotJson,
    /// Read as the type the policy declares, the props are past what a round
    /// carries.
    TooLong,
}
