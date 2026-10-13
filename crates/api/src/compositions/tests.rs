use super::*;

fn pin(package: &str, impl_ref: &str) -> PluginPin {
    PluginPin {
        package: package.into(),
        impl_ref: impl_ref.into(),
        key: None,
    }
}

/// A refused composition is its pins' to fix — the fixed 422 a failing
/// policy gets; any other compile failure stays a 500.
#[test]
fn a_refused_composition_is_a_422() {
    assert!(matches!(
        classify_compile_error("ses_test", "r/p@sha256:00", CompileError::Refused),
        ApiError::StatusWithBody(StatusCode::UNPROCESSABLE_ENTITY, _)
    ));
    assert!(matches!(
        classify_compile_error("ses_test", "r/p@sha256:00", CompileError::Failed),
        ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR)
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
    use hatch_client::KbsKey;
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
