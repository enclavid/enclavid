use super::*;

use engine_types::props::{PropsProblem, Step};

/// A session not yet prepared, created with `props`.
fn unprepared(props: &str) -> SessionMetadata {
    SessionMetadata {
        props: props.as_bytes().to_vec(),
        ..Default::default()
    }
}

fn refusal(path: Vec<Step>, problem: PropsProblem) -> PropsRefusal {
    PropsRefusal { path, problem }
}

/// What a worker read is kept as it read it, up to what a round carries.
#[test]
fn props_read_are_kept_to_what_a_round_carries() {
    for props in [None, Some("{flag: true}".to_owned())] {
        let Ok(Ok(prepared)) = settled(PropsRead::Read(props.clone())) else {
            panic!("{props:?} were not kept");
        };
        assert_eq!(prepared.props, props);
    }
    let longest = "w".repeat(MAX_PROPS_BYTES);
    assert!(matches!(settled(PropsRead::Read(Some(longest))), Ok(Ok(_))));
    let past = "w".repeat(MAX_PROPS_BYTES + 1);
    assert_eq!(
        settled(PropsRead::Read(Some(past))).err(),
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
}

/// A refusal is the session's init error only while the session has not
/// started, and only as far as its props bear it out.
#[test]
fn a_refusal_is_kept_only_before_a_round_and_as_the_props_bear_it_out() {
    let borne_out = || refusal(vec![Step::Key("age".into())], PropsProblem::OutOfRange);
    let metadata = unprepared(r#"{"age": 256}"#);
    let Err(Unavailable::Init(InitError::Props(fault))) = refused(borne_out(), &metadata) else {
        panic!("a refusal the props bear out was not kept");
    };
    assert_eq!(fault.at, "props.age");
    assert_eq!(fault.problem, PropsProblem::OutOfRange);

    let started = SessionMetadata {
        prepared: Some(Prepared {
            props: None,
            model_files: Vec::new(),
        }),
        ..metadata.clone()
    };
    assert!(matches!(
        refused(borne_out(), &started),
        Err(Unavailable::Request(StatusCode::INTERNAL_SERVER_ERROR))
    ));

    let not_there = refusal(vec![Step::Key("name".into())], PropsProblem::UnknownField);
    assert!(matches!(
        refused(not_there, &metadata),
        Err(Unavailable::Request(StatusCode::INTERNAL_SERVER_ERROR))
    ));
}

/// What a worker read, as it arrives at api's end of the leg.
fn arrived(read: PropsRead) -> Untrusted<PropsRead, (Asserted,), ExecutionWorker> {
    let reply = engine_rpc::PrepareReply {
        props: engine_rpc::Padded::seal(&read).expect("fits the frame"),
    };
    match enclavid_boundary::inbound::<ExecutionWorker, _>(reply).try_map(|r| r.props.open()) {
        Ok(read) => read,
        Err(_) => panic!("the frame decodes"),
    }
}

/// Each answer the worker can give reaches the judgement that is its own: a
/// read is kept, a refusal becomes the session's init error, and nothing read is
/// no answer.
#[test]
fn each_answer_is_judged_on_its_own_grounds() {
    let metadata = unprepared(r#"{"age": 256}"#);
    let Ok(prepared) = judged(arrived(PropsRead::Read(None)), &metadata) else {
        panic!("a read was not kept");
    };
    assert_eq!(prepared.props, None);
    let borne_out = refusal(vec![Step::Key("age".into())], PropsProblem::OutOfRange);
    assert!(matches!(
        judged(arrived(PropsRead::Refused(borne_out)), &metadata),
        Err(Unavailable::Init(InitError::Props(_)))
    ));
    assert!(matches!(
        judged(arrived(PropsRead::NotRead), &metadata),
        Err(Unavailable::Request(StatusCode::INTERNAL_SERVER_ERROR))
    ));
}

/// Nothing read, when reading was asked, is no answer.
#[test]
fn nothing_read_is_no_answer() {
    assert_eq!(
        settled(PropsRead::NotRead).err(),
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
}
