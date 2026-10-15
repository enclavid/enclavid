use super::*;

use engine_compiler::Compiler;
use wit_component::{ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata};
use wit_parser::{ManglingAndAbi, Resolve};

use PropsProblem as P;

/// The type of `get` in a component whose `policy-props` package holds
/// `package` — the interface and any it uses.
fn get_in_package(package: &str) -> ComponentFunc {
    let wit = format!(
        "package test:policy;

         world policy {{
             import {INTERFACE};
         }}

         {package}"
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

/// `get` returning `record props { fields }`, beside `types`.
fn props_with(types: &str, fields: &str) -> ComponentFunc {
    get_in_package(&format!(
        "package enclavid:host-ext@0.1.0 {{
             interface policy-props {{
                 {types}
                 record props {{ {fields} }}
                 get: func() -> props;
             }}
         }}"
    ))
}

/// `json` read as the record `get` returns — and the WAVE read back as that
/// record, as a round reads it, so what is written is what a round gets.
fn fits(get: &ComponentFunc, json: &str) -> String {
    let wave = read(Some(get), json.as_bytes())
        .unwrap_or_else(|refusal| panic!("{json}: {refusal:?}"))
        .expect("a policy with props gets some");
    let back = value(Some(get), wave.as_bytes())
        .unwrap_or_else(|e| panic!("{wave}: {e}"))
        .expect("a policy with props gets some");
    assert_eq!(back.to_wave().unwrap(), wave);
    wave
}

fn refusal(get: &ComponentFunc, json: &str) -> PropsRefusal {
    match read(Some(get), json.as_bytes()) {
        Ok(props) => panic!("{json} read as {props:?}"),
        Err(refusal) => refusal,
    }
}

fn key(k: &str) -> Step {
    Step::Key(k.into())
}

fn at(path: &[Step], problem: PropsProblem) -> PropsRefusal {
    PropsRefusal {
        path: path.to_vec(),
        problem,
    }
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
    // In the record's own order, whatever the JSON's; an option left out is
    // `none`, which WAVE leaves out too.
    assert_eq!(
        fits(
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
            }"#
        ),
        r#"{min-age: 18, country: "DE", mode: lenient, ratio: 0.5, scale: 2, initial: 'Ж', strict: true, limit: -9007199254740993, people: [{name: "A"}, {name: "B", age: some(30)}]}"#
    );
}

#[test]
fn null_is_none_and_a_value_is_some() {
    let get = props_with("", "note: option<string>, count: option<u32>");
    assert_eq!(
        fits(&get, r#"{"note": null, "count": 3}"#),
        "{count: some(3)}"
    );
}

#[test]
fn no_props_read_as_an_empty_object() {
    let optional = props_with("", "note: option<string>");
    assert_eq!(fits(&optional, ""), "{:}");
    assert_eq!(fits(&optional, "{}"), "{:}");

    let required = props_with("", "country: string");
    assert_eq!(read(Some(&required), b""), Err(at(&[], P::Missing)));
}

#[test]
fn a_field_is_named_as_the_wit_spells_it() {
    let get = props_with("", "min-age: u8");
    assert_eq!(
        refusal(&get, r#"{"minAge": 18}"#),
        at(&[key("minAge")], P::UnknownField)
    );
    assert_eq!(fits(&get, r#"{"min-age": 18}"#), "{min-age: 18}");
}

#[test]
fn a_key_the_record_lacks_is_refused() {
    let get = props_with("", "country: string, extra: option<string>");
    assert_eq!(
        refusal(&get, r#"{"country": "DE", "typo": "x"}"#),
        at(&[key("typo")], P::UnknownField)
    );
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
        assert_eq!(
            refusal(&get, json),
            at(&[key("age")], P::OutOfRange),
            "{json}"
        );
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
        (r#"{"mode": "loose"}"#, at(&[key("mode")], P::NotACase)),
        (r#"{"mode": 1}"#, at(&[key("mode")], P::ShouldBeString)),
        (
            r#"{"initial": "ab"}"#,
            at(&[key("initial")], P::ShouldBeOneCharacter),
        ),
        (
            r#"{"inner": {"flag": "yes"}}"#,
            at(&[key("inner"), key("flag")], P::ShouldBeBool),
        ),
        // Missing from `inner`, which is where it is said to be.
        (r#"{"inner": {}}"#, at(&[key("inner")], P::Missing)),
        (r#"{"inner": []}"#, at(&[key("inner")], P::ShouldBeObject)),
        (
            r#"{"tags": ["a", 2]}"#,
            at(&[key("tags"), Step::Index(1)], P::ShouldBeString),
        ),
        (r#"{"tags": "a"}"#, at(&[key("tags")], P::ShouldBeArray)),
        (
            r#"{"count": "3"}"#,
            at(&[key("count")], P::ShouldBeWholeNumber),
        ),
    ] {
        assert_eq!(refusal(&get, json), says, "{json}");
    }
}

#[test]
fn a_refusal_never_carries_a_value() {
    let get = props_with("", "expected-name: u8");
    let refusal = refusal(&get, r#"{"expected-name": "Jane Q. Citizen"}"#);
    assert!(!format!("{refusal:?}").contains("Jane"), "{refusal:?}");
}

#[test]
fn a_type_props_cannot_hold_is_refused_where_a_value_of_it_is_given() {
    for (types, field, json, path) in [
        (
            "",
            "pair: option<tuple<u8, u8>>",
            r#"{"pair": [1, 2]}"#,
            vec![key("pair")],
        ),
        (
            "variant choice { a, b(u8) }",
            "choice: option<choice>",
            r#"{"choice": "a"}"#,
            vec![key("choice")],
        ),
        (
            "flags perms { read }",
            "perms: option<perms>",
            r#"{"perms": ["read"]}"#,
            vec![key("perms")],
        ),
        (
            "",
            "outcome: option<result<u8>>",
            r#"{"outcome": 1}"#,
            vec![key("outcome")],
        ),
        (
            "",
            "pairs: list<tuple<u8, u8>>",
            r#"{"pairs": [[1, 2]]}"#,
            vec![key("pairs"), Step::Index(0)],
        ),
        (
            "",
            "pair: tuple<u8, u8>",
            r#"{"pair": null}"#,
            vec![key("pair")],
        ),
    ] {
        let get = props_with(types, field);
        assert_eq!(refusal(&get, json), at(&path, P::Unholdable), "{json}");
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
    assert_eq!(fits(&get, r#"{"pairs": []}"#), "{pairs: []}");

    let required = props_with("", "pair: tuple<u8, u8>");
    assert_eq!(refusal(&required, "{}"), at(&[], P::Missing));
}

#[test]
fn a_policy_without_props_takes_none() {
    assert_eq!(read(None, b""), Ok(None));
    assert_eq!(read(None, b"{}"), Ok(None));
    for json in [r#"{"country": "DE"}"#, "[]", "1", "\"x\""] {
        assert_eq!(
            read(None, json.as_bytes()),
            Err(at(&[], P::NotDeclared)),
            "{json}"
        );
    }
    assert_eq!(read(None, b"not json"), Err(at(&[], P::NotJson)));
}

#[test]
fn props_for_a_record_that_are_no_object_are_refused() {
    let get = props_with("", "note: option<string>");
    for json in ["[]", "1", "\"x\"", "null"] {
        assert_eq!(refusal(&get, json), at(&[], P::ShouldBeObject), "{json}");
    }
    for json in ["not json", "{} {}", r#"{"note": "a""#] {
        assert_eq!(refusal(&get, json), at(&[], P::NotJson), "{json}");
    }
}

/// `get` returning `ty`, beside `types`.
fn returning(types: &str, ty: &str) -> ComponentFunc {
    get_in_package(&format!(
        "package enclavid:host-ext@0.1.0 {{
             interface policy-props {{
                 {types}
                 get: func() -> {ty};
             }}
         }}"
    ))
}

/// Props of a type that is no record are the JSON value of that type itself.
#[test]
fn props_of_any_type_are_its_json_value() {
    for (types, ty, json, wave) in [
        ("", "u32", "5", "5"),
        ("", "string", r#""DE""#, r#""DE""#),
        ("", "list<string>", r#"["a", "b"]"#, r#"["a", "b"]"#),
        (
            "enum mode { strict, lenient }",
            "mode",
            r#""strict""#,
            "strict",
        ),
        ("", "option<u32>", "7", "some(7)"),
        ("", "option<u32>", "null", "none"),
    ] {
        assert_eq!(fits(&returning(types, ty), json), wave, "{ty} {json}");
    }
    assert_eq!(refusal(&returning("", "u8"), "256"), at(&[], P::OutOfRange));
    assert_eq!(
        refusal(&returning("", "u32"), r#"{"a": 1}"#),
        at(&[], P::ShouldBeWholeNumber)
    );
}

/// Props not given are `null` to a type that is no record: `none` to an
/// option, and refused where a value is required.
#[test]
fn props_not_given_are_null_to_a_type_that_is_no_record() {
    assert_eq!(fits(&returning("", "option<u32>"), ""), "none");
    assert_eq!(
        read(Some(&returning("", "u32")), b""),
        Err(at(&[], P::ShouldBeWholeNumber))
    );
    assert_eq!(
        read(Some(&returning("", "list<string>")), b""),
        Err(at(&[], P::ShouldBeArray))
    );
}

/// A record whose types come from another interface reads as well.
#[test]
fn a_record_using_another_interfaces_types_reads() {
    let get = get_in_package(
        "package enclavid:host-ext@0.1.0 {
             interface shapes { record point { x: u32, y: u32 } }
             interface policy-props {
                 use shapes.{point};
                 record props { at: point, path: list<point> }
                 get: func() -> props;
             }
         }",
    );
    assert_eq!(
        fits(&get, r#"{"at": {"x": 1, "y": 2}, "path": []}"#),
        "{at: {x: 1, y: 2}, path: []}"
    );
}

/// A field named as a WAVE keyword is written so WAVE reads it back.
#[test]
fn a_field_named_as_a_keyword_reads_back() {
    let get = props_with(
        "enum answer { %true, %none }",
        "%none: option<u8>, ok: answer",
    );
    fits(&get, r#"{"none": 1, "ok": "true"}"#);
}

/// Props whose WAVE is past what a round carries are refused as too long at
/// the props themselves, however short their JSON: each `1e-300` is three
/// hundred digits written out.
#[test]
fn props_past_what_a_round_carries_are_too_long() {
    let get = returning("", "list<f64>");
    let json = format!("[{}]", vec!["1e-300"; 30].join(", "));
    assert!(json.len() < 256);
    assert_eq!(refusal(&get, &json), at(&[], P::TooLong));
}

/// Every float a JSON number spells is written so WAVE reads it back, at its
/// longest well within what a round carries.
#[test]
fn floats_read_back_however_they_are_spelled() {
    let get = props_with("", "tiny: f64, huge: f32, small: list<f64>");
    let wave = fits(
        &get,
        r#"{"tiny": 1e-300, "huge": 3.4e38, "small": [5e-324, -0.0, 1.7976931348623157e308]}"#,
    );
    assert!(wave.len() < MAX_PROPS_BYTES, "{}", wave.len());
}
