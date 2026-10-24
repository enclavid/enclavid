//! The consumer's props, as the value the policy's `get` returns.
//!
//! A policy that takes props imports [`INTERFACE`], whose one function `get`
//! returns a value of the policy's own type — a record, as a rule. WIT cannot
//! leave a type open for the importer to fill in, so the policy writes the
//! interface itself — the package stays the host's to serve all the same (see
//! `engine_compiler::compose`) — and the host serves `get` dynamically, with the
//! type read off the component.
//!
//! The props are read against that type once, when the session is prepared
//! and before any round ([`read`]): the JSON value the consumer gave, written
//! as WAVE, the component model's own value encoding. api keeps the WAVE and
//! hands it every round, which reads it back into the value ([`value`]).
//!
//! JSON maps onto the type one way. An object is a record, keyed by its field
//! names as the WIT spells them (`min-age`); an array is a list; a string is a
//! `string`, a `char` of one character, or an enum's case; a number is an
//! integer type it fits, or a float; `true` and `false` are a `bool`; `null`, or
//! a key left out, is an option's `none`. A key the record does not have is
//! refused. Any other type — a tuple, variant, flags or result — is refused
//! where the props give a value of it; an optional field of it the props leave
//! out is `none`, like any other. Props not given at all are a record with no
//! field given, or `null` for any other type.
//!
//! The reading goes by the type, not by the JSON: each field a record declares
//! is looked for, and the keys left over are ones it does not have. A refusal
//! ([`PropsRefusal`]) says where in the props they went wrong and what is wrong
//! there, from a fixed set — never a value: the values are the consumer's,
//! about the applicant.

use std::borrow::Cow;

use serde_json::{Map, Number, Value as Json};
use wasmtime::component::types::{ComponentFunc, ComponentItem};
use wasmtime::component::wasm_wave::wasm::{WasmType, WasmTypeKind, WasmValue, WasmValueError};
use wasmtime::component::{Component, Type, Val};
use wasmtime::{Engine, Result, bail};
use wasmtime_environ::component::alternate_lookup_key;

use engine_types::limits::MAX_PROPS_BYTES;
use engine_types::props::{PropsProblem, PropsRefusal, Step};

/// The interface a policy imports to read its props.
pub(crate) const INTERFACE: &str = engine_types::compile::POLICY_PROPS;

/// Its one function, taking nothing and returning the props.
pub(crate) const FUNCTION: &str = "get";

/// The type of `get`, when `component` imports [`INTERFACE`] — at its own
/// version or a semver-compatible one, the rule the linker looks the name up by
/// and the compile admits it by. The first import on that track: the one the
/// compile checked, which admits no second.
pub(crate) fn declared(component: &Component, engine: &Engine) -> Option<ComponentFunc> {
    let ty = component.component_type();
    let (_, item) = ty.imports(engine).find(|(name, _)| is_props(name))?;
    let ComponentItem::ComponentInstance(instance) = item.ty else {
        return None;
    };
    instance
        .exports(engine)
        .find_map(|(name, item)| match item.ty {
            ComponentItem::ComponentFunc(func) if name == FUNCTION => Some(func),
            _ => None,
        })
}

/// Whether an import `name` is [`INTERFACE`]: exactly, or on its semver track.
fn is_props(name: &str) -> bool {
    name == INTERFACE
        || alternate_lookup_key(name).is_some_and(|(track, _)| {
            alternate_lookup_key(INTERFACE).is_some_and(|(key, _)| key == track)
        })
}

/// The consumer's `json` read as the value `get` returns, and written as WAVE;
/// `None` for a composition that declares none.
///
/// No bytes are props not given, which is what a session created without them
/// holds: a record with no field given, `null` for any other type. Props given
/// to a policy that declares none — anything but nothing, or `{}` — are refused
/// rather than dropped, so a consumer that pinned the wrong policy hears of it.
pub(crate) fn read(
    get: Option<&ComponentFunc>,
    json: &[u8],
) -> std::result::Result<Option<String>, PropsRefusal> {
    let given = if json.is_empty() {
        None
    } else {
        let Ok(json) = serde_json::from_slice::<Json>(json) else {
            return Err(at_root(PropsProblem::NotJson));
        };
        Some(json)
    };
    let Some(get) = get else {
        return match given {
            None => Ok(None),
            Some(Json::Object(given)) if given.is_empty() => Ok(None),
            Some(_) => Err(at_root(PropsProblem::NotDeclared)),
        };
    };
    // The compile refuses a `get` that returns nothing.
    let ty = get
        .results()
        .next()
        .ok_or_else(|| at_root(PropsProblem::Unholdable))?;
    let json = given.unwrap_or_else(|| match ty.kind() {
        WasmTypeKind::Record => Json::Object(Map::new()),
        _ => Json::Null,
    });
    let props = Reading { path: Vec::new() }.value(&ty, &json)?;
    let wave = props
        .to_wave()
        .map_err(|_| at_root(PropsProblem::Unholdable))?;
    // Longer than the JSON wherever it writes `some(…)` or spells a float out,
    // and bounded by what a round carries.
    if wave.len() > MAX_PROPS_BYTES {
        return Err(at_root(PropsProblem::TooLong));
    }
    Ok(Some(wave))
}

/// The value `get` returns: the round's `props`, WAVE of the type `get`
/// declares, or `None` for a composition that declares none.
pub(crate) fn value(get: Option<&ComponentFunc>, props: &[u8]) -> Result<Option<Val>> {
    let Some(get) = get else {
        if !props.is_empty() {
            bail!("the round has props, and the composition does not import {INTERFACE}");
        }
        return Ok(None);
    };
    let Some(ty) = get.results().next() else {
        bail!("`{FUNCTION}` in {INTERFACE} returns nothing");
    };
    Ok(Some(Val::from_wave(&ty, std::str::from_utf8(props)?)?))
}

fn at_root(problem: PropsProblem) -> PropsRefusal {
    PropsRefusal {
        path: Vec::new(),
        problem,
    }
}

/// A walk over the record and the JSON together, keeping where it is in the
/// props.
struct Reading {
    path: Vec<Step>,
}

impl Reading {
    /// The JSON value here as a value of `ty`.
    fn value(&mut self, ty: &Type, json: &Json) -> std::result::Result<Val, PropsRefusal> {
        use WasmTypeKind as K;
        Ok(match (ty.kind(), json) {
            (K::Bool, Json::Bool(b)) => Val::make_bool(*b),
            (K::S8, Json::Number(n)) => Val::make_s8(self.whole(n)?),
            (K::S16, Json::Number(n)) => Val::make_s16(self.whole(n)?),
            (K::S32, Json::Number(n)) => Val::make_s32(self.whole(n)?),
            (K::S64, Json::Number(n)) => Val::make_s64(self.whole(n)?),
            (K::U8, Json::Number(n)) => Val::make_u8(self.whole(n)?),
            (K::U16, Json::Number(n)) => Val::make_u16(self.whole(n)?),
            (K::U32, Json::Number(n)) => Val::make_u32(self.whole(n)?),
            (K::U64, Json::Number(n)) => Val::make_u64(self.whole(n)?),
            // A float takes the nearest value it holds.
            (K::F32, Json::Number(n)) => Val::make_f32(n.as_f64().unwrap_or_default() as f32),
            (K::F64, Json::Number(n)) => Val::make_f64(n.as_f64().unwrap_or_default()),
            (K::Char, Json::String(s)) => {
                let mut chars = s.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) => Val::make_char(c),
                    _ => return Err(self.refusal(PropsProblem::ShouldBeOneCharacter)),
                }
            }
            (K::String, Json::String(s)) => Val::make_string(Cow::Borrowed(s)),
            (K::Enum, Json::String(s)) if ty.enum_cases().any(|case| case == s.as_str()) => {
                self.made(Val::make_enum(ty, s))?
            }
            (K::Enum, Json::String(_)) => return Err(self.refusal(PropsProblem::NotACase)),
            (K::Option, Json::Null) => self.made(Val::make_option(ty, None))?,
            (K::Option, json) => {
                let some = ty
                    .option_some_type()
                    .ok_or_else(|| self.refusal(PropsProblem::Unholdable))?;
                let value = self.value(&some, json)?;
                self.made(Val::make_option(ty, Some(value)))?
            }
            (K::List, Json::Array(items)) => self.list(ty, items)?,
            (K::Record, Json::Object(given)) => self.record(ty, given)?,
            (kind, _) => return Err(self.refusal(expected(kind))),
        })
    }

    fn list(&mut self, ty: &Type, items: &[Json]) -> std::result::Result<Val, PropsRefusal> {
        let element = ty
            .list_element_type()
            .ok_or_else(|| self.refusal(PropsProblem::Unholdable))?;
        let mut values = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            values.push(self.within(Step::Index(index), |at| at.value(&element, item))?);
        }
        self.made(Val::make_list(ty, values))
    }

    /// Each field the record declares, in its order, from the key of its name:
    /// absent is an option's `none` or refused, here. A key no field has is
    /// refused before any field is read.
    fn record(
        &mut self,
        ty: &Type,
        given: &Map<String, Json>,
    ) -> std::result::Result<Val, PropsRefusal> {
        let fields: Vec<(Cow<'_, str>, Type)> = ty.record_fields().collect();
        if let Some(unknown) = given
            .keys()
            .find(|key| !fields.iter().any(|(name, _)| name == key.as_str()))
        {
            return Err(self.within(Step::Key(unknown.clone()), |at| {
                at.refusal(PropsProblem::UnknownField)
            }));
        }
        let mut values = Vec::with_capacity(fields.len());
        for (name, field) in &fields {
            let value = match given.get(name.as_ref()) {
                Some(json) => {
                    self.within(Step::Key(name.to_string()), |at| at.value(field, json))?
                }
                None if field.kind() == WasmTypeKind::Option => {
                    self.made(Val::make_option(field, None))?
                }
                None => return Err(self.refusal(PropsProblem::Missing)),
            };
            values.push((name.as_ref(), value));
        }
        self.made(Val::make_record(ty, values))
    }

    /// The number here as an integer of type `T`, if it is a whole number `T`
    /// holds.
    fn whole<T: TryFrom<u64> + TryFrom<i64>>(
        &self,
        n: &Number,
    ) -> std::result::Result<T, PropsRefusal> {
        n.as_u64()
            .and_then(|u| T::try_from(u).ok())
            .or_else(|| n.as_i64().and_then(|i| T::try_from(i).ok()))
            .ok_or_else(|| self.refusal(PropsProblem::OutOfRange))
    }

    /// A value made of one this reading built to the type — which it refuses
    /// only for a type props cannot hold.
    fn made(
        &self,
        made: std::result::Result<Val, WasmValueError>,
    ) -> std::result::Result<Val, PropsRefusal> {
        made.map_err(|_| self.refusal(PropsProblem::Unholdable))
    }

    /// Run `read` one step deeper.
    fn within<T>(&mut self, step: Step, read: impl FnOnce(&mut Self) -> T) -> T {
        self.path.push(step);
        let read = read(self);
        self.path.pop();
        read
    }

    /// `problem` here.
    fn refusal(&self, problem: PropsProblem) -> PropsRefusal {
        PropsRefusal {
            path: self.path.clone(),
            problem,
        }
    }
}

/// What a value of `kind` should have been, for a JSON value of another kind —
/// or that `kind` is a type props cannot hold.
fn expected(kind: WasmTypeKind) -> PropsProblem {
    use WasmTypeKind as K;
    match kind {
        K::Bool => PropsProblem::ShouldBeBool,
        K::S8 | K::S16 | K::S32 | K::S64 | K::U8 | K::U16 | K::U32 | K::U64 => {
            PropsProblem::ShouldBeWholeNumber
        }
        K::F32 | K::F64 => PropsProblem::ShouldBeNumber,
        K::Char => PropsProblem::ShouldBeOneCharacter,
        K::String | K::Enum => PropsProblem::ShouldBeString,
        K::List => PropsProblem::ShouldBeArray,
        K::Record => PropsProblem::ShouldBeObject,
        _ => PropsProblem::Unholdable,
    }
}

#[cfg(test)]
mod tests;
