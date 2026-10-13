//! The consumer's props, in the type the policy declares for them.
//!
//! A policy that takes props imports [`INTERFACE`], whose one function `get`
//! returns a record of the policy's own. WIT cannot leave a type open for the
//! importer to fill in, so the policy writes the interface itself — the package
//! stays the host's to serve all the same (see `engine_compiler::compose`) — and
//! the host serves `get` dynamically: it reads the record's type from the
//! component and builds the value from the JSON object the consumer gave at
//! session creation.
//!
//! JSON maps onto the record one way. An object is a record, keyed by its field
//! names as the WIT spells them (`min-age`); an array is a list; a string is a
//! `string`, a `char` of one character, or an enum's case; a number is an integer
//! type it fits, or a float; `true` and `false` are a `bool`; `null`, or a key
//! left out, is an option's `none`. A key the record does not have, or one given
//! twice, is refused. Any other type — a tuple, variant, flags, result, map or
//! resource — is refused where the props give a value of it; an optional field
//! of it the props leave out is `none`, like any other.
//!
//! Errors name where in the record the props went wrong, never a value: the
//! values are the consumer's, about the applicant. Where comes from
//! `serde_path_to_error`, which the JSON is read through.
//!
//! ```text
//! mod.rs   ← the interface's names; `declared` and `value`, what a round calls
//! seed     ← `Typed`, the serde seed that walks the JSON with its WIT type, in
//!            one pass, and the visitor that answers every kind of JSON value
//! values   ← what `Typed` builds from each kind: numbers, strings, lists, records
//! ```

mod seed;
mod values;

use std::collections::BTreeMap;

use serde::de::{DeserializeSeed, IgnoredAny};
use serde_path_to_error::Track;
use wasmtime::component::types::{ComponentFunc, ComponentItem};
use wasmtime::component::{Component, Type, Val};
use wasmtime::{Engine, Result, bail};

use seed::Typed;

/// The interface a policy imports to read its props.
pub(crate) const INTERFACE: &str = engine_types::compile::POLICY_PROPS;

/// Its one function, taking nothing and returning the props.
pub(crate) const FUNCTION: &str = "get";

/// The type of `get`, when `component` imports [`INTERFACE`].
pub(crate) fn declared(component: &Component, engine: &Engine) -> Option<ComponentFunc> {
    component
        .component_type()
        .imports(engine)
        .find_map(|(name, item)| match item.ty {
            ComponentItem::ComponentInstance(instance) if name == INTERFACE => instance
                .exports(engine)
                .find_map(|(name, item)| match item.ty {
                    ComponentItem::ComponentFunc(func) if name == FUNCTION => Some(func),
                    _ => None,
                }),
            _ => None,
        })
}

/// The value `get` returns: the consumer's `json` object as the record `get`
/// declares, or `None` for a policy that declares none.
///
/// No bytes read as `{}`, which is what a session created without props holds.
/// Props given to a policy that declares none are refused rather than dropped,
/// so a consumer that pinned the wrong policy hears of it.
pub(crate) fn value(get: Option<&ComponentFunc>, json: &[u8]) -> Result<Option<Val>> {
    let json: &[u8] = if json.is_empty() { b"{}" } else { json };
    let Some(get) = get else {
        let Ok(given) = serde_json::from_slice::<BTreeMap<String, IgnoredAny>>(json) else {
            bail!("the props are not a JSON object");
        };
        if given.is_empty() {
            return Ok(None);
        }
        bail!("the session has props, but the policy does not import {INTERFACE}");
    };
    if get.params().len() != 0 {
        bail!("`{FUNCTION}` in {INTERFACE} takes parameters");
    }
    let mut results = get.results();
    let (Some(root @ Type::Record(_)), None) = (results.next(), results.next()) else {
        bail!("`{FUNCTION}` in {INTERFACE} does not return one record");
    };

    let mut de = serde_json::Deserializer::from_slice(json);
    let mut track = Track::new();
    let props = Typed { ty: &root }
        .deserialize(serde_path_to_error::Deserializer::new(&mut de, &mut track))
        .and_then(|props| de.end().map(|()| props));
    match props {
        Ok(props) => Ok(Some(props)),
        Err(e) => {
            let path = track.path();
            if path.iter().next().is_none() {
                bail!("props: {e}")
            }
            bail!("props.{path}: {e}")
        }
    }
}

#[cfg(test)]
mod tests;
