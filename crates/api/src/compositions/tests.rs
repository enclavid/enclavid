use super::*;

fn pin(package: &str, impl_ref: &str) -> PluginPin {
    PluginPin {
        package: package.into(),
        impl_ref: impl_ref.into(),
        key: None,
    }
}

/// A composition's artifacts are the policy and every plugin, in pin order,
/// each with the bearer kept for its own registry — none left out, none sent to
/// another registry.
#[test]
fn every_artifact_comes_with_its_registrys_bearer() {
    let composition = Composition {
        policy_ref: "a.example.com/policy@sha256:aa".into(),
        policy_key: None,
        plugins: vec![
            pin("p1", "b.example.com/p1@sha256:11"),
            pin("p2", "c.example.com/p2@sha256:22"),
            pin("p3", "a.example.com/p3@sha256:33"),
        ],
        registry_auth: HashMap::from([
            ("a.example.com".to_string(), b"bearer-a".to_vec()),
            ("b.example.com".to_string(), b"bearer-b".to_vec()),
        ]),
        consumer: String::new(),
        terms: Terms::default(),
    };
    let plugin = |package: &str| Artifact::Plugin(package.into());
    assert_eq!(
        composition.artifacts(),
        vec![
            (
                Artifact::Policy,
                "a.example.com/policy@sha256:aa",
                &b"bearer-a"[..]
            ),
            (plugin("p1"), "b.example.com/p1@sha256:11", &b"bearer-b"[..]),
            (plugin("p2"), "c.example.com/p2@sha256:22", &b""[..]),
            (plugin("p3"), "a.example.com/p3@sha256:33", &b"bearer-a"[..]),
        ]
    );
}

/// A pull that will not pass is the session's init error, naming the artifact;
/// one that may pass later is a 503 for this request alone.
#[test]
fn a_pull_failure_fails_init_only_when_it_will_not_pass() {
    let plugin = Artifact::Plugin("enclavid:extra@0.1.0".into());
    match pull_failure(plugin.clone(), &policy_pull::PullError::Refused) {
        Unavailable::Init(InitError::Pull { artifact, problem }) => {
            assert_eq!(artifact, plugin);
            assert_eq!(problem, PullProblem::Refused);
        }
        _ => panic!("a refusal is the session's init error"),
    }
    assert!(matches!(
        pull_failure(Artifact::Policy, &policy_pull::PullError::Busy),
        Unavailable::Request(StatusCode::SERVICE_UNAVAILABLE)
    ));
}

/// A refused composition is its pins' to fix: the session's init error, the
/// fault as the compiler gave it. Any other compile failure stays a 500.
#[test]
fn a_refused_composition_is_the_sessions_init_error() {
    let fault = CompileFault::NotAComponent(Artifact::Plugin("enclavid:extra@0.1.0".into()));
    match classify_compile_error(
        "ses_test",
        "r/p@sha256:00",
        CompileError::Refused(fault.clone()),
    ) {
        Unavailable::Init(InitError::Compile(kept)) => assert_eq!(kept, fault),
        _ => panic!("a refusal is the session's init error"),
    }
    assert!(matches!(
        classify_compile_error("ses_test", "r/p@sha256:00", CompileError::Failed),
        Unavailable::Request(StatusCode::INTERNAL_SERVER_ERROR)
    ));
}

#[test]
fn composition_key_deterministic_and_order_sensitive() {
    let plugins = [
        pin("enclavid:well-known", "reg/wk@sha256:11"),
        pin("enclavid:face-age", "reg/fa@sha256:22"),
    ];
    let key = composition_key("reg/policy@sha256:aa", None, &plugins);

    // Same composition → same key (the whole point: cross-session sharing).
    assert_eq!(key, composition_key("reg/policy@sha256:aa", None, &plugins));

    // Plugin ORDER is significant (fusion order fixes merged first-match) →
    // reversing must change the key.
    let reversed = [plugins[1].clone(), plugins[0].clone()];
    assert_ne!(
        key,
        composition_key("reg/policy@sha256:aa", None, &reversed)
    );

    // Different policy ref → different key.
    assert_ne!(key, composition_key("reg/policy@sha256:bb", None, &plugins));

    // Different plugin set (dropping one) → different key.
    assert_ne!(
        key,
        composition_key("reg/policy@sha256:aa", None, &plugins[..1])
    );
}

#[test]
fn composition_key_length_prefixed_no_delimiter_collision() {
    // Without length-prefixing, field boundaries could be ambiguous: a
    // policy ref "ab" + package "c" would concat-collide with ref "a" +
    // package "bc". Length-prefixing must keep them distinct.
    let a = composition_key("ab", None, &[pin("c", "r")]);
    let b = composition_key("a", None, &[pin("bc", "r")]);
    assert_ne!(a, b);
}

#[test]
fn composition_key_partitions_by_decryption_authority() {
    use session_types::KbsKey;
    let plugins = [pin("p", "r")];
    let none = composition_key("policy", None, &plugins);
    let inline_a = composition_key("policy", Some(&Key::Inline(vec![1, 2, 3])), &plugins);
    let inline_b = composition_key("policy", Some(&Key::Inline(vec![9, 9, 9])), &plugins);

    // Plaintext (None) and encrypted (Inline) are distinct scopes, and two
    // different Inline keys never share — a non-holder can't hit a holder's
    // entry (the whole point: a cache hit must not bypass decrypt auth).
    assert_ne!(none, inline_a);
    assert_ne!(inline_a, inline_b);
    // Same Inline key → same key: key-holders DO share.
    assert_eq!(
        inline_a,
        composition_key("policy", Some(&Key::Inline(vec![1, 2, 3])), &plugins)
    );

    // Kbs is attestation-gated (every TEE session equally authorized), so it
    // does NOT partition by endpoint — that would only reduce sharing.
    let kbs = |endpoint: &str| {
        composition_key(
            "policy",
            Some(&Key::Kbs(KbsKey {
                endpoint: endpoint.into(),
            })),
            &plugins,
        )
    };
    assert_eq!(kbs("a"), kbs("b"));
}

/// A composition's key is the one the session's pins give, wherever the
/// composition was read from.
#[test]
fn a_sessions_composition_has_the_key_its_pins_give() {
    let metadata = SessionMetadata {
        policy_ref: "reg/policy@sha256:aa".into(),
        client: Some(Client {
            plugins: vec![pin("p", "reg/p@sha256:11")],
            ..Default::default()
        }),
        ..Default::default()
    };
    let composition = Composition::of(&metadata).expect("a client block");
    assert_eq!(
        composition.key(),
        composition_key("reg/policy@sha256:aa", None, &[pin("p", "reg/p@sha256:11")])
    );
    assert!(Composition::of(&SessionMetadata::default()).is_none());
}
