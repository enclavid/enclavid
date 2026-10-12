//! What [`Typed`] builds from each kind of JSON value: a number, a string, a
//! list or a record, as the WIT type at that point in the props says.

use serde::de::{self, MapAccess, SeqAccess};
use wasmtime::component::{Type, Val};

use super::seed::Typed;

/// A JSON number, as the deserializer hands it over.
#[derive(Clone, Copy)]
pub(super) enum Number {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
}

impl Number {
    fn as_f64(self) -> f64 {
        match self {
            Number::Unsigned(u) => u as f64,
            Number::Signed(i) => i as f64,
            Number::Float(f) => f,
        }
    }
}

impl Typed<'_> {
    pub(super) fn number<E: de::Error>(self, n: Number) -> Result<Val, E> {
        Ok(match self.ty {
            Type::S8 => Val::S8(whole(n)?),
            Type::U8 => Val::U8(whole(n)?),
            Type::S16 => Val::S16(whole(n)?),
            Type::U16 => Val::U16(whole(n)?),
            Type::S32 => Val::S32(whole(n)?),
            Type::U32 => Val::U32(whole(n)?),
            Type::S64 => Val::S64(whole(n)?),
            Type::U64 => Val::U64(whole(n)?),
            // A float takes the nearest value it holds.
            Type::Float32 => Val::Float32(n.as_f64() as f32),
            Type::Float64 => Val::Float64(n.as_f64()),
            _ => return Err(self.mismatch()),
        })
    }

    pub(super) fn string<E: de::Error>(self, s: &str) -> Result<Val, E> {
        match self.ty {
            Type::String => Ok(Val::String(s.to_owned())),
            Type::Char => {
                let mut chars = s.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) => Ok(Val::Char(c)),
                    _ => Err(E::custom("not one character")),
                }
            }
            Type::Enum(cases) if cases.names().any(|case| case == s) => Ok(Val::Enum(s.to_owned())),
            Type::Enum(_) => Err(E::custom("not one of the enum's cases")),
            _ => Err(self.mismatch()),
        }
    }

    pub(super) fn list<'de, A: SeqAccess<'de>>(self, mut seq: A) -> Result<Val, A::Error> {
        let Type::List(list) = self.ty else {
            return Err(self.mismatch());
        };
        let element = list.ty();
        // Grown as elements arrive, not reserved off the size hint: the bytes
        // the props came in already bound how many there can be.
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Typed { ty: &element })? {
            items.push(item);
        }
        Ok(Val::List(items))
    }

    /// The fields arrive in the JSON's order and are kept in the record's: each
    /// goes to its field's place, and a field never given is an option's `none`
    /// or refused. These errors are the record's, so they name the field.
    pub(super) fn record<'de, A: MapAccess<'de>>(self, mut map: A) -> Result<Val, A::Error> {
        let Type::Record(record) = self.ty else {
            return Err(self.mismatch());
        };
        let fields: Vec<_> = record.fields().collect();
        let mut given: Vec<Option<Val>> = fields.iter().map(|_| None).collect();
        while let Some(key) = map.next_key::<String>()? {
            let Some(i) = fields.iter().position(|field| field.name == key) else {
                return Err(de::Error::custom(format_args!(
                    "`{key}` is not a field of the record"
                )));
            };
            if given[i].is_some() {
                return Err(de::Error::custom(format_args!("`{key}` is given twice")));
            }
            given[i] = Some(map.next_value_seed(Typed { ty: &fields[i].ty })?);
        }
        let mut values = Vec::with_capacity(fields.len());
        for (field, value) in fields.iter().zip(given) {
            let value = match value {
                Some(value) => value,
                None if matches!(field.ty, Type::Option(_)) => Val::Option(None),
                None => {
                    return Err(de::Error::custom(format_args!(
                        "`{}` is missing",
                        field.name
                    )));
                }
            };
            values.push((field.name.to_string(), value));
        }
        Ok(Val::Record(values))
    }
}

/// `n` as an integer of type `T`, if it is a whole number `T` holds.
fn whole<T: TryFrom<u64> + TryFrom<i64>, E: de::Error>(n: Number) -> Result<T, E> {
    let fits = match n {
        Number::Unsigned(u) => T::try_from(u).ok(),
        Number::Signed(i) => T::try_from(i).ok(),
        Number::Float(_) => None,
    };
    fits.ok_or_else(|| E::custom("not a whole number its type holds"))
}
