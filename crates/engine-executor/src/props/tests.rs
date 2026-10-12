use super::*;

use engine_compiler::Compiler;
use wit_component::{ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata};
use wit_parser::{ManglingAndAbi, Resolve};

/// The type of `get` in a component whose `policy-props` interface holds
/// `body` — its types and its `get`.
fn get_in(body: &str) -> ComponentFunc {
    let wit = format!(
        "package test:policy;

         world policy {{
             import {INTERFACE};
         }}

         package enclavid:host-ext@0.1.0 {{
             interface policy-props {{
                 {body}
             }}
         }}"
    );
    let mut resolve = Resolve::default();
    let package = resolve
        .push_str("policy.wit", &wit)
        .expect("the WIT parses");
    let world = resolve
        .select_world(&[package], Some("policy"))
        .expect("the world");
    let mut module = dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8)
        .expect("the metadata");
    let bytes = ComponentEncoder::default()
        .module(&module)
        .expect("the module")
        .validate(true)
        .encode()
        .expect("the component");
    let component = Compiler::new()
        .expect("a compiler")
        .compile(&bytes)
        .expect("it compiles");
    declared(&component, component.engine()).expect("the component imports `get`")
}

/// `get` returning `record props { <fields> }`, beside `types`.
fn props_with(types: &str, fields: &str) -> ComponentFunc {
    get_in(&format!(
        "{types}
         record props {{ {fields} }}
         get: func() -> props;"
    ))
}

fn read(get: &ComponentFunc, json: &str) -> Result<Val> {
    value(Some(get), json.as_bytes()).map(|props| props.expect("a policy with props gets some"))
}

fn refusal(get: &ComponentFunc, json: &str) -> String {
    match read(get, json) {
        Ok(props) => panic!("{json} read as {props:?}"),
        Err(e) => e.to_string(),
    }
}

fn record(fields: &[(&str, Val)]) -> Val {
    Val::Record(
        fields
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()))
            .collect(),
    )
}

fn some(value: Val) -> Val {
    Val::Option(Some(Box::new(value)))
}

#[test]
fn json_becomes_the_record_the_policy_declares() {
    let get = props_with(
        "enum mode { strict, lenient }
         record person { name: string, age: option<u8> }",
        "min-age: u8,
         country: string,
         expected-name: option<string>,
         mode: mode,
         ratio: f64,
         scale: f32,
         initial: char,
         strict: bool,
         limit: s64,
         people: list<person>",
    );
    let props = read(
        &get,
        r#"{
            "people": [{"name": "A"}, {"name": "B", "age": 30}],
            "min-age": 18,
            "country": "DE",
            "mode": "lenient",
            "ratio": 0.5,
            "scale": 2,
            "initial": "Ж",
            "strict": true,
            "limit": -9007199254740993
        }"#,
    )
    .expect("the props fit");
    // In the record's own order, whatever the JSON's, and an option left out is
    // `none`.
    assert_eq!(
        props,
        record(&[
            ("min-age", Val::U8(18)),
            ("country", Val::String("DE".into())),
            ("expected-name", Val::Option(None)),
            ("mode", Val::Enum("lenient".into())),
            ("ratio", Val::Float64(0.5)),
            ("scale", Val::Float32(2.0)),
            ("initial", Val::Char('Ж')),
            ("strict", Val::Bool(true)),
            ("limit", Val::S64(-9007199254740993)),
            (
                "people",
                Val::List(vec![
                    record(&[
                        ("name", Val::String("A".into())),
                        ("age", Val::Option(None)),
                    ]),
                    record(&[
                        ("name", Val::String("B".into())),
                        ("age", some(Val::U8(30))),
                    ]),
                ]),
            ),
        ])
    );
}

#[test]
fn null_is_none_and_a_value_is_some() {
    let get = props_with("", "note: option<string>, count: option<u32>");
    assert_eq!(
        read(&get, r#"{"note": null, "count": 3}"#).unwrap(),
        record(&[("note", Val::Option(None)), ("count", some(Val::U32(3)))])
    );
}

#[test]
fn no_props_read_as_an_empty_object() {
    let optional = props_with("", "note: option<string>");
    let none = record(&[("note", Val::Option(None))]);
    assert_eq!(value(Some(&optional), b"").unwrap(), Some(none.clone()));
    assert_eq!(value(Some(&optional), b"{}").unwrap(), Some(none));

    let required = props_with("", "country: string");
    let e = value(Some(&required), b"").unwrap_err().to_string();
    assert!(e.contains("props: `country` is missing"), "{e}");
}

#[test]
fn a_field_is_named_as_the_wit_spells_it() {
    let get = props_with("", "min-age: u8");
    let e = refusal(&get, r#"{"minAge": 18}"#);
    assert!(e.contains("props: `minAge` is not a field"), "{e}");
    assert_eq!(
        read(&get, r#"{"min-age": 18}"#).unwrap(),
        record(&[("min-age", Val::U8(18))])
    );
}

#[test]
fn a_key_the_record_lacks_is_refused() {
    let get = props_with("", "country: string, extra: option<string>");
    let e = refusal(&get, r#"{"country": "DE", "typo": "x"}"#);
    assert!(e.contains("props: `typo` is not a field"), "{e}");
}

#[test]
fn an_integer_must_fit_its_type() {
    let get = props_with("", "age: u8");
    for json in [
        r#"{"age": 256}"#,
        r#"{"age": -1}"#,
        r#"{"age": 18.5}"#,
        r#"{"age": 18.0}"#,
    ] {
        let e = refusal(&get, json);
        assert!(e.contains("props.age: not a whole number"), "{json}: {e}");
    }
}

#[test]
fn a_wrong_shape_names_what_was_expected() {
    let get = props_with(
        "enum mode { strict }
         record inner { flag: bool }",
        "mode: option<mode>,
         initial: option<char>,
         inner: option<inner>,
         tags: option<list<string>>,
         count: option<u32>",
    );
    for (json, says) in [
        (
            r#"{"mode": "loose"}"#,
            "props.mode: not one of the enum's cases",
        ),
        (r#"{"mode": 1}"#, "props.mode: should be a string"),
        (r#"{"initial": "ab"}"#, "props.initial: not one character"),
        (
            r#"{"inner": {"flag": "yes"}}"#,
            "props.inner.flag: should be true or false",
        ),
        (r#"{"inner": {}}"#, "props.inner: `flag` is missing"),
        (r#"{"inner": []}"#, "props.inner: should be an object"),
        (r#"{"tags": ["a", 2]}"#, "props.tags[1]: should be a string"),
        (r#"{"tags": "a"}"#, "props.tags: should be an array"),
        (r#"{"count": "3"}"#, "props.count: should be a whole number"),
    ] {
        let e = refusal(&get, json);
        assert!(e.contains(says), "{json}: {e}");
    }
}

#[test]
fn a_refusal_never_carries_a_value() {
    let get = props_with("", "expected-name: u8");
    let e = refusal(&get, r#"{"expected-name": "Jane Q. Citizen"}"#);
    assert!(!e.contains("Jane"), "{e}");
}

#[test]
fn a_type_props_cannot_hold_is_refused_where_a_value_of_it_is_given() {
    for (types, field, json) in [
        ("", "pair: option<tuple<u8, u8>>", r#"{"pair": [1, 2]}"#),
        (
            "variant choice { a, b(u8) }",
            "choice: option<choice>",
            r#"{"choice": "a"}"#,
        ),
        (
            "variant choice { a, b(u8) }",
            "choice: option<choice>",
            r#"{"choice": {"b": 1}}"#,
        ),
        (
            "flags perms { read }",
            "perms: option<perms>",
            r#"{"perms": ["read"]}"#,
        ),
        ("", "outcome: option<result<u8>>", r#"{"outcome": 1}"#),
        ("", "pairs: list<tuple<u8, u8>>", r#"{"pairs": [[1, 2]]}"#),
        ("", "pair: tuple<u8, u8>", r#"{"pair": null}"#),
    ] {
        let get = props_with(types, field);
        let e = refusal(&get, json);
        assert!(e.contains("a type props cannot hold"), "{json}: {e}");
    }
}

#[test]
fn a_field_of_a_type_props_cannot_hold_left_out_is_none_or_missing() {
    let get = props_with(
        "",
        "pair: option<tuple<u8, u8>>, pairs: list<tuple<u8, u8>>",
    );
    // The props never reach either type: an optional field is `none`, and an
    // empty list holds nothing of its element's type.
    assert_eq!(
        read(&get, r#"{"pairs": []}"#).unwrap(),
        record(&[("pair", Val::Option(None)), ("pairs", Val::List(vec![]))])
    );

    let required = props_with("", "pair: tuple<u8, u8>");
    let e = refusal(&required, "{}");
    assert!(e.contains("props: `pair` is missing"), "{e}");
}

#[test]
fn get_must_return_one_record() {
    let get = get_in("get: func() -> u32;");
    let e = value(Some(&get), b"{}").unwrap_err().to_string();
    assert!(e.contains("does not return one record"), "{e}");

    let get = get_in("record props { a: u8 } get: func(x: u8) -> props;");
    let e = value(Some(&get), b"{}").unwrap_err().to_string();
    assert!(e.contains("takes parameters"), "{e}");
}

#[test]
fn a_policy_without_props_takes_none() {
    assert_eq!(value(None, b"").unwrap(), None);
    assert_eq!(value(None, b"{}").unwrap(), None);
    let e = value(None, br#"{"country": "DE"}"#)
        .unwrap_err()
        .to_string();
    assert!(e.contains("does not import"), "{e}");
}

#[test]
fn a_key_given_twice_is_refused() {
    let get = props_with("", "country: string");
    let e = refusal(&get, r#"{"country": "DE", "country": "FR"}"#);
    assert!(e.contains("props: `country` is given twice"), "{e}");
}

#[test]
fn props_that_are_not_one_object_are_refused() {
    let get = props_with("", "note: option<string>");
    for json in ["[]", "1", "\"x\"", "null"] {
        let e = value(Some(&get), json.as_bytes()).unwrap_err().to_string();
        assert!(e.contains("props: should be an object"), "{json}: {e}");
    }
    for json in ["not json", "{} {}", r#"{"note": "a""#] {
        assert!(value(Some(&get), json.as_bytes()).is_err(), "{json}");
    }
    for json in ["[]", "1", "not json"] {
        let e = value(None, json.as_bytes()).unwrap_err().to_string();
        assert!(e.contains("not a JSON object"), "{json}: {e}");
    }
}
