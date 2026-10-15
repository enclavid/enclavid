use super::*;

use engine_types::props::{PropsProblem, PropsRefusal, Step};

/// A session not yet prepared, created with `props`.
fn unprepared(props: &str) -> SessionMetadata {
    SessionMetadata {
        props: props.as_bytes().to_vec(),
        ..Default::default()
    }
}

fn refused(path: Vec<Step>, problem: PropsProblem) -> PropsRead {
    PropsRead::Refused(PropsRefusal { path, problem })
}

/// What a worker read is kept as it read it, up to what a round carries.
#[test]
fn props_read_are_kept_to_what_a_round_carries() {
    let metadata = unprepared("");
    for props in [None, Some("{flag: true}".to_owned())] {
        let Ok(Ok(prepared)) = settled(PropsRead::Read(props.clone()), &metadata) else {
            panic!("{props:?} were not kept");
        };
        assert_eq!(prepared.props, props);
    }
    let longest = "w".repeat(MAX_PROPS_BYTES);
    assert!(matches!(
        settled(PropsRead::Read(Some(longest)), &metadata),
        Ok(Ok(_))
    ));
    let past = "w".repeat(MAX_PROPS_BYTES + 1);
    assert_eq!(
        settled(PropsRead::Read(Some(past)), &metadata).err(),
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
}

/// A refusal is the session's init error only while the session has not
/// started, and only as far as its props bear it out.
#[test]
fn a_refusal_is_kept_only_before_a_round_and_as_the_props_bear_it_out() {
    let borne_out = || refused(vec![Step::Key("age".into())], PropsProblem::OutOfRange);
    let metadata = unprepared(r#"{"age": 256}"#);
    let Ok(Err(Unavailable::Init(InitError::Props(fault)))) = settled(borne_out(), &metadata)
    else {
        panic!("a refusal the props bear out was not kept");
    };
    assert_eq!(fault.at, "props.age");
    assert_eq!(fault.problem, PropsProblem::OutOfRange);

    let started = SessionMetadata {
        prepared: Some(Prepared { props: None }),
        ..metadata.clone()
    };
    assert_eq!(
        settled(borne_out(), &started).err(),
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );

    let not_there = refused(vec![Step::Key("name".into())], PropsProblem::UnknownField);
    assert_eq!(
        settled(not_there, &metadata).err(),
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
}

/// Nothing read, when reading was asked, is no answer.
#[test]
fn nothing_read_is_no_answer() {
    assert_eq!(
        settled(PropsRead::NotRead, &unprepared("")).err(),
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
}
