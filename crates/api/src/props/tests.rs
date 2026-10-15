use super::*;

use PropsProblem as P;

fn value(json: &str) -> Json {
    serde_json::from_str(json).expect("JSON")
}

#[test]
fn no_props_are_kept_as_nothing() {
    assert_eq!(encode(None), Some(Vec::new()));
}

#[test]
fn props_are_kept_as_compact_json() {
    for (given, kept) in [
        (
            r#"{ "min-age": 18, "people": [ { "name": "A" } ] }"#,
            r#"{"min-age":18,"people":[{"name":"A"}]}"#,
        ),
        ("5", "5"),
        (r#" [ "a", "b" ] "#, r#"["a","b"]"#),
    ] {
        assert_eq!(
            encode(Some(&value(given))).as_deref(),
            Some(kept.as_bytes()),
            "{given}"
        );
    }
}

#[test]
fn props_are_held_to_their_size_as_kept() {
    // `{"k":"…"}` is eight bytes around the string.
    let at_bound = value(&format!(r#"{{"k": "{}"}}"#, "x".repeat(MAX_PROPS_SIZE - 8)));
    assert_eq!(
        encode(Some(&at_bound)).map(|json| json.len()),
        Some(MAX_PROPS_SIZE)
    );
    let over = value(&format!(r#"{{"k": "{}"}}"#, "x".repeat(MAX_PROPS_SIZE - 7)));
    assert_eq!(encode(Some(&over)), None);
}

fn key(k: &str) -> Step {
    Step::Key(k.into())
}

fn refusal(path: &[Step], problem: PropsProblem) -> PropsRefusal {
    PropsRefusal {
        path: path.to_vec(),
        problem,
    }
}

/// What the consumer reads of `refusal` of `json`, if the props bear it out.
fn read(json: &str, path: &[Step], problem: PropsProblem) -> Option<PropsFault> {
    fault(&refusal(path, problem), json.as_bytes())
}

fn said(at: &str, problem: PropsProblem) -> Option<PropsFault> {
    Some(PropsFault {
        at: at.into(),
        problem,
    })
}

const PROPS: &str = r#"{
    "mode": "loose",
    "initial": "ab",
    "inner": {"flag": "yes", "deeper": {}},
    "tags": ["a", 2],
    "count": "3",
    "age": 256,
    "typo": "x",
    "dotted.key": true
}"#;

/// A refusal the props bear out is written as they spell the place.
#[test]
fn a_refusal_the_props_bear_out_is_written_as_they_spell_it() {
    for (path, problem, at) in [
        (vec![key("mode")], P::NotACase, "props.mode"),
        (
            vec![key("initial")],
            P::ShouldBeOneCharacter,
            "props.initial",
        ),
        (
            vec![key("inner"), key("flag")],
            P::ShouldBeBool,
            "props.inner.flag",
        ),
        (
            vec![key("inner"), key("deeper")],
            P::Missing,
            "props.inner.deeper",
        ),
        (vec![], P::Missing, "props"),
        (
            vec![key("tags"), Step::Index(1)],
            P::ShouldBeString,
            "props.tags[1]",
        ),
        (vec![key("count")], P::ShouldBeWholeNumber, "props.count"),
        (vec![key("age")], P::OutOfRange, "props.age"),
        (vec![key("typo")], P::UnknownField, "props.typo"),
        (vec![key("tags")], P::Unholdable, "props.tags"),
        (
            vec![key("dotted.key")],
            P::ShouldBeString,
            "props.dotted.key",
        ),
        (vec![], P::NotDeclared, "props"),
        (vec![], P::TooLong, "props"),
    ] {
        assert_eq!(
            read(PROPS, &path, problem),
            said(at, problem),
            "{at} {problem:?}"
        );
    }
}

/// A problem the value at the place does not have is not borne out, whatever
/// the worker said.
#[test]
fn a_problem_the_value_does_not_have_is_not_borne_out() {
    let json = r#"{"flag": true, "n": 3, "s": "x", "list": [], "obj": {}}"#;
    for (path, problem) in [
        (vec![key("flag")], P::ShouldBeBool),
        (vec![key("n")], P::ShouldBeWholeNumber),
        (vec![key("n")], P::ShouldBeNumber),
        (vec![key("s")], P::ShouldBeOneCharacter),
        (vec![key("s")], P::ShouldBeString),
        (vec![key("list")], P::ShouldBeArray),
        (vec![key("obj")], P::ShouldBeObject),
        (vec![key("n")], P::NotACase),
        (vec![key("s")], P::OutOfRange),
        (vec![key("s")], P::Missing),
        (vec![key("list"), Step::Index(0)], P::Unholdable),
        (vec![key("list")], P::NotDeclared),
        (vec![key("n")], P::TooLong),
        (vec![], P::UnknownField),
    ] {
        assert_eq!(read(json, &path, problem), None, "{path:?} {problem:?}");
    }
}

/// A place the props do not hold is not borne out: a key they lack, an index
/// past an array, a step into a value that is neither — and so no name the
/// worker chose reaches the consumer.
#[test]
fn a_place_the_props_do_not_hold_is_not_borne_out() {
    let json = r#"{"inner": {"flag": "yes"}, "tags": ["a"], "n": 1}"#;
    for (path, problem) in [
        (vec![key("secret-name")], P::UnknownField),
        (vec![key("inner"), key("other")], P::ShouldBeBool),
        (vec![key("missing-object")], P::Missing),
        (vec![key("tags"), Step::Index(1)], P::ShouldBeString),
        (vec![key("tags"), key("0")], P::ShouldBeString),
        (vec![key("n"), key("x")], P::ShouldBeBool),
        (vec![key("inner"), Step::Index(0)], P::ShouldBeBool),
    ] {
        assert_eq!(read(json, &path, problem), None, "{path:?} {problem:?}");
    }
}

/// Of the props themselves: declaring none is borne out only by props given,
/// and not being JSON never by what api keeps.
#[test]
fn what_is_said_of_the_props_themselves_is_checked_as_such() {
    // Declaring none is borne out by props given, of any type, and not by none.
    assert_eq!(read("", &[], P::NotDeclared), None);
    assert_eq!(read("{}", &[], P::NotDeclared), None);
    for given in [r#"{"a": 1}"#, "5", "[]", r#""x""#] {
        assert_eq!(
            read(given, &[], P::NotDeclared),
            said("props", P::NotDeclared),
            "{given}"
        );
    }
    // Not being JSON, only by what does not read as JSON.
    for given in [r#"{"a": 1}"#, "", "[]", "5"] {
        assert_eq!(read(given, &[], P::NotJson), None, "{given}");
    }
    assert_eq!(read("not json", &[], P::NotJson), said("props", P::NotJson));
    assert_eq!(read(r#"{"a": 1}"#, &[key("a")], P::NotDeclared), None);
    assert_eq!(read(r#"{"a": 1}"#, &[key("a")], P::NotJson), None);
}

/// Props of a type that is no record are refused at the props themselves, as
/// their own value bears out — and props not given bear out what the worker
/// finds missing there, a field or a value.
#[test]
fn props_of_any_type_bear_out_what_is_said_of_them() {
    assert_eq!(
        read("256", &[], P::OutOfRange),
        said("props", P::OutOfRange)
    );
    assert_eq!(read(r#""x""#, &[], P::OutOfRange), None);
    assert_eq!(
        read(r#"{"a": 1}"#, &[], P::ShouldBeWholeNumber),
        said("props", P::ShouldBeWholeNumber)
    );
    assert_eq!(read("5", &[], P::ShouldBeWholeNumber), None);
    assert_eq!(
        read(r#"["a", 2]"#, &[Step::Index(1)], P::ShouldBeString),
        said("props[1]", P::ShouldBeString)
    );
    for problem in [P::Missing, P::ShouldBeWholeNumber, P::ShouldBeArray] {
        assert_eq!(
            read("", &[], problem),
            said("props", problem),
            "{problem:?}"
        );
    }
}

#[test]
fn where_is_cut_on_a_character_past_its_bound() {
    let long = "ж".repeat(MAX_PROPS_AT_BYTES);
    let json = format!(r#"{{"{long}": 1}}"#);
    let fault = read(&json, &[key(&long)], P::UnknownField).expect("borne out");
    assert!(fault.at.len() <= MAX_PROPS_AT_BYTES, "{}", fault.at.len());
    assert!(
        fault.at.len() > MAX_PROPS_AT_BYTES - "ж".len(),
        "{}",
        fault.at.len()
    );
    assert!(fault.at.starts_with("props.жж"), "{}", fault.at);
}
