//! The serde seed that builds a value of a WIT type from JSON, in one pass.

use std::fmt;

use serde::Deserializer;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use wasmtime::component::{Type, Val};

use super::values::Number;

/// The seed that builds a [`Val`] of `ty` from a JSON value. It is its own
/// visitor: JSON says which kind of value comes next, and `ty` says what that
/// kind must become (see `values`). A `ty` props cannot hold is refused here,
/// when a value of it is given; a field of it left out never reaches the seed.
///
/// Its errors say what is wrong and not where: the caller reads through
/// `serde_path_to_error`, which knows the path.
#[derive(Clone, Copy)]
pub(super) struct Typed<'a> {
    pub(super) ty: &'a Type,
}

impl<'de> DeserializeSeed<'de> for Typed<'_> {
    type Value = Val;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Val, D::Error> {
        d.deserialize_any(self)
    }
}

impl Typed<'_> {
    /// A present value of an `option<T>` is `some` of a `T`: `visit` runs with
    /// the options peeled off, and what it builds is wrapped back in them.
    fn through_options<E>(self, visit: impl FnOnce(Typed<'_>) -> Result<Val, E>) -> Result<Val, E> {
        match self.ty {
            Type::Option(option) => {
                let inner = option.ty();
                Typed { ty: &inner }
                    .through_options(visit)
                    .map(|value| Val::Option(Some(Box::new(value))))
            }
            _ => visit(self),
        }
    }

    /// The value here is of another kind than `ty` takes, or `ty` is a type
    /// props cannot hold at all.
    pub(super) fn mismatch<E: de::Error>(self) -> E {
        match expected(self.ty) {
            Some(kind) => E::custom(format_args!("should be {kind}")),
            None => E::custom(
                "a type props cannot hold: only records, lists, options, enums, strings, \
                 chars, numbers and bools",
            ),
        }
    }
}

// Every kind of value JSON has, handled here rather than by serde's defaults,
// whose errors quote the value.
impl<'de> Visitor<'de> for Typed<'_> {
    type Value = Val;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(expected(self.ty).unwrap_or("a type props can hold"))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Val, E> {
        match self.ty {
            Type::Option(_) => Ok(Val::Option(None)),
            _ => Err(self.mismatch()),
        }
    }

    fn visit_none<E: de::Error>(self) -> Result<Val, E> {
        self.visit_unit()
    }

    fn visit_bool<E: de::Error>(self, b: bool) -> Result<Val, E> {
        self.through_options(|typed| match typed.ty {
            Type::Bool => Ok(Val::Bool(b)),
            _ => Err(typed.mismatch()),
        })
    }

    fn visit_u64<E: de::Error>(self, n: u64) -> Result<Val, E> {
        self.through_options(|typed| typed.number(Number::Unsigned(n)))
    }

    fn visit_i64<E: de::Error>(self, n: i64) -> Result<Val, E> {
        self.through_options(|typed| typed.number(Number::Signed(n)))
    }

    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Val, E> {
        self.through_options(|typed| typed.number(Number::Float(n)))
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Val, E> {
        self.through_options(|typed| typed.string(s))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Val, A::Error> {
        self.through_options(|typed| typed.list(seq))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Val, A::Error> {
        self.through_options(|typed| typed.record(map))
    }
}

/// What JSON a value of `ty` is given as, for an error naming the mismatch, or
/// `None` for a type props cannot hold: a tuple, variant, flags, result, map or
/// resource.
fn expected(ty: &Type) -> Option<&'static str> {
    Some(match ty {
        Type::Bool => "true or false",
        Type::S8
        | Type::U8
        | Type::S16
        | Type::U16
        | Type::S32
        | Type::U32
        | Type::S64
        | Type::U64 => "a whole number",
        Type::Float32 | Type::Float64 => "a number",
        Type::Char => "a one-character string",
        Type::String | Type::Enum(_) => "a string",
        Type::List(_) => "an array",
        Type::Record(_) => "an object",
        Type::Option(option) => return expected(&option.ty()),
        _ => return None,
    })
}
