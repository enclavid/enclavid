//! What the host may tell this role, and the check a push has to pass.
//!
//! ## Why this is not on the command line
//!
//! The command line is measured, so anything on it is part of this role's
//! digest. What arrives here is the fleet's SHAPE — which api builds run and at
//! which addresses — and it changes whenever a machine is added or a build is
//! rolled. On the command line it would make the digest a function of the
//! deployment, and a consumer, which verifies THIS role and then trusts it to
//! check api, would have nothing stable to verify against.
//!
//! ## Why it may come from the host at all
//!
//! Every value here says WHERE this role may go, never WHETHER to check what it
//! finds there. An upstream's measurement is a routing hint the connector proves
//! at the handshake, so a lie about one is a route that fails, not a route that
//! is taken. There is deliberately no field that could say otherwise.
//!
//! ## The type is the grammar
//!
//! JSON decoded into these structs with `deny_unknown_fields`: an unknown or
//! misspelt key is a refusal rather than a line quietly ignored, and nothing
//! beyond what the structs spell can be expressed.
//!
//! What the grammar cannot say is whether a value could do its job — a label
//! that survives a URL, a measurement a quote could carry, an address something
//! could dial. That is the second step, and it is a type rather than a habit:
//! [`RawConfig`] is what decodes, [`ValidatedConfig`] is what routing is given,
//! and the only way between them is [`TryFrom`].
//!
//! A push is refused WHOLE if any entry in it is wrong, and the answer says
//! which. There is a sender to tell, and a table missing one declared build is a
//! quieter failure than a push that did not apply.

use serde::Deserialize;

/// One push as it decodes: the complete table, never a change to the previous
/// one.
///
/// What the grammar admits, before anything has looked at the values — a node
/// label that could not travel in a link, a measurement no quote could carry,
/// an address nothing could dial. [`ValidatedConfig`] is the form those have
/// been looked at in.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub upstreams: Vec<Upstream>,
    pub affinity: Affinity,
}

/// A table every check has passed, and the only form routing is given.
///
/// The wrapper exists so that the checks cannot be skipped by a later caller
/// rather than to make them more thorough: `Upstreams::replaced` takes this,
/// and this is reachable only through [`TryFrom`].
pub struct ValidatedConfig(RawConfig);

impl ValidatedConfig {
    /// The table a push declares, or why it is refused.
    ///
    /// Two steps, and the type each one produces says which refused: the
    /// grammar, then the values.
    pub fn parse(body: &[u8]) -> Result<ValidatedConfig, String> {
        serde_json::from_slice::<RawConfig>(body)
            .map_err(|e| e.to_string())?
            .try_into()
    }

    /// The table, consuming the wrapper — its job was to stand between decoding
    /// and use, and by here it has.
    pub fn into_inner(self) -> RawConfig {
        self.0
    }
}

/// What this role signs affinity tokens with — see `crate::affinity` for why
/// this is the host's to give and not something derived from the chip.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Affinity {
    pub key: Key,
    /// The key before it, accepted and never minted with, so that rotating one
    /// does not strand the tokens issued in the minutes before the push.
    #[serde(default)]
    pub previous_key: Option<Key>,
    /// How long a minted token stays good. Bounded here because it is the only
    /// thing limiting how long a consumer can keep placing work on a machine it
    /// was once given.
    pub ttl_seconds: u64,
}

/// The widest a token may be allowed to live.
const MAX_TTL_SECONDS: u64 = 3600;

/// Thirty-two bytes, written as hex.
///
/// A type rather than a string with a check beside it: a key IS bytes, so
/// decoding is the validation, and nothing further in can be handed one that
/// was never looked at. The decoding is `hex`'s, the same one the rest of the
/// workspace reads digests with. `Debug` is deliberately not derived.
#[derive(Deserialize)]
pub struct Key(#[serde(with = "hex::serde")] pub [u8; 32]);

/// One api instance, as the host declares it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// What this instance is called, in a link and in a token.
    ///
    /// A session's state is sealed to the machine that made it, so every later
    /// request of that session has to come back here. The label is how it finds
    /// its way: it travels in the applicant's link and in the consumer's token,
    /// and it says WHICH MACHINE and nothing about whose session.
    pub node: String,
    /// The build the host says runs there. Proved at the handshake, not here.
    ///
    /// Not unique: several nodes run one build, which is the ordinary state of a
    /// fleet and the reason there is anything to choose between.
    pub measurement: String,
    /// Where api serves the applicant surface.
    pub applicant: String,
    /// Where api serves the consumer surface.
    pub client: String,
    /// Where api answers what it knows about itself.
    ///
    /// Reached through the host like everything else, and unauthenticated. A
    /// forged "healthy" sends new sessions to a node that cannot run them —
    /// which the host can cause anyway by not carrying bytes — and it cannot
    /// substitute a build, because identity is proved on every data connection.
    pub health: String,
}

/// What a node label may be.
///
/// It ends up in a URL path and in a token, so it is kept to what is safe in
/// both and short enough to read in a log: lowercase letters, digits and
/// hyphens. The limit is not a security boundary — the label selects among
/// instances the host declared and nothing else — it is there so that a
/// mistake in the host's configuration is refused at the push rather than
/// found in a link.
fn is_node_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 32
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// What the grammar could not say: whether each value could do the job its
/// field names.
///
/// The reason goes back to the sender and nowhere else, and names the entry it
/// is about. It may quote what the host sent, which is the host's own
/// configuration.
impl TryFrom<RawConfig> for ValidatedConfig {
    type Error = String;

    fn try_from(raw: RawConfig) -> Result<ValidatedConfig, String> {
        if raw.affinity.ttl_seconds == 0 || raw.affinity.ttl_seconds > MAX_TTL_SECONDS {
            return Err(format!(
                "affinity.ttl_seconds: expected 1 to {MAX_TTL_SECONDS}"
            ));
        }

        for (i, upstream) in raw.upstreams.iter().enumerate() {
            if !is_node_label(&upstream.node) {
                return Err(format!(
                    "upstreams[{i}].node: expected 1 to 32 characters of a-z, 0-9 or -"
                ));
            }
            // Two entries under one label would make a link ambiguous, and the
            // session it points at lives on exactly one machine.
            if let Some(j) = raw.upstreams[..i]
                .iter()
                .position(|earlier| earlier.node == upstream.node)
            {
                return Err(format!(
                    "upstreams[{i}].node: already declared by upstreams[{j}]"
                ));
            }
            if fleet_transport::Measurement::parse(&upstream.measurement).is_none() {
                return Err(format!(
                    "upstreams[{i}].measurement: expected 96 lowercase hex characters"
                ));
            }
            // Three fields that have to be dialable, each carrying its own name
            // so the refusal says which one — `upstreams[1].client`, not "an
            // address somewhere in the push".
            for (field, addr) in [
                ("applicant", &upstream.applicant),
                ("client", &upstream.client),
                ("health", &upstream.health),
            ] {
                fleet_transport::check_dial_addr(addr)
                    .map_err(|e| format!("upstreams[{i}].{field}: {e}"))?;
            }
        }

        Ok(ValidatedConfig(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(c: char) -> String {
        c.to_string().repeat(96)
    }

    fn upstream(node: &str, measurement: &str, applicant: &str, client: &str) -> String {
        format!(
            r#"{{"node":"{node}","measurement":"{measurement}","applicant":"{applicant}","client":"{client}","health":"127.0.0.1:9"}}"#
        )
    }

    /// A key the validation accepts; what it signs is not this module's concern.
    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn push(entries: &[String]) -> Vec<u8> {
        format!(
            r#"{{"upstreams":[{}],"affinity":{{"key":"{KEY}","ttl_seconds":600}}}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn a_well_formed_push_is_taken_in_order() {
        let got = ValidatedConfig::parse(&push(&[
            upstream("one", &m('a'), "127.0.0.1:1", "127.0.0.1:2"),
            upstream("two", &m('b'), "127.0.0.1:3", "127.0.0.1:4"),
        ]))
        .unwrap()
        .into_inner();
        assert_eq!(got.upstreams.len(), 2);
        assert_eq!(got.upstreams[0].node, "one");
        assert_eq!(got.upstreams[0].measurement, m('a'));
        assert_eq!(got.upstreams[1].client, "127.0.0.1:4");
        assert_eq!(got.affinity.ttl_seconds, 600);
        assert!(got.affinity.previous_key.is_none());
    }

    /// The key is what makes a token unforgeable, and the expiry is what bounds
    /// how long a consumer can keep a machine it was handed. A push without
    /// them, or with a key too short to be one, is refused whole.
    #[test]
    fn affinity_is_required_and_checked() {
        let one = upstream("one", &m('a'), "127.0.0.1:1", "127.0.0.1:2");
        let with = |affinity: &str| {
            format!(r#"{{"upstreams":[{one}],"affinity":{affinity}}}"#).into_bytes()
        };

        assert!(
            ValidatedConfig::parse(&format!(r#"{{"upstreams":[{one}]}}"#).into_bytes()).is_err()
        );
        for bad in [
            r#"{"ttl_seconds":600}"#.to_owned(),
            r#"{"key":"abcd","ttl_seconds":600}"#.to_owned(),
            format!(r#"{{"key":"{KEY}"}}"#),
            format!(r#"{{"key":"{KEY}","ttl_seconds":0}}"#),
            format!(r#"{{"key":"{KEY}","ttl_seconds":3601}}"#),
            format!(r#"{{"key":"{KEY}","previous_key":"nope","ttl_seconds":600}}"#),
        ] {
            assert!(
                ValidatedConfig::parse(&with(&bad)).is_err(),
                "accepted `{bad}`"
            );
        }
        assert!(
            ValidatedConfig::parse(&with(&format!(
                r#"{{"key":"{KEY}","previous_key":"{KEY}","ttl_seconds":600}}"#
            )))
            .is_ok()
        );
    }

    /// The ordinary state of a fleet: several machines running one build. It
    /// used to be refused, back when routing picked by build alone.
    #[test]
    fn one_build_on_several_nodes_is_normal() {
        let got = ValidatedConfig::parse(&push(&[
            upstream("one", &m('a'), "127.0.0.1:1", "127.0.0.1:2"),
            upstream("two", &m('a'), "127.0.0.1:3", "127.0.0.1:4"),
        ]))
        .unwrap()
        .into_inner();
        assert_eq!(got.upstreams.len(), 2);
    }

    #[test]
    fn a_node_label_that_could_not_travel_is_refused() {
        for bad in ["", "Node", "no de", "a/b", "x".repeat(33).as_str()] {
            let err = ValidatedConfig::parse(&push(&[upstream(
                bad,
                &m('a'),
                "127.0.0.1:1",
                "127.0.0.1:2",
            )]))
            .err()
            .unwrap_or_else(|| panic!("accepted `{bad}`"));
            assert!(err.starts_with("upstreams[0].node"), "{err}");
        }
    }

    /// Declaring no api at all is a state the host may choose, not a mistake to
    /// refuse: every request then fails as an unavailable upstream.
    #[test]
    fn an_empty_table_is_a_table() {
        assert!(
            ValidatedConfig::parse(&push(&[]))
                .unwrap()
                .into_inner()
                .upstreams
                .is_empty()
        );
    }

    /// The table is required rather than defaulted: a push that says nothing
    /// about upstreams is not a push that declares none.
    #[test]
    fn a_push_without_the_table_is_refused() {
        assert!(ValidatedConfig::parse(b"{}").is_err());
    }

    #[test]
    fn an_unknown_key_is_refused_not_ignored() {
        assert!(ValidatedConfig::parse(br#"{"upstreams":[],"verify_measurement":false}"#).is_err());

        let body = format!(
            r#"{{"upstreams":[{{"node":"x","measurement":"{}","applicant":"127.0.0.1:1","client":"127.0.0.1:2","health":"127.0.0.1:9","weight":3}}]}}"#,
            m('a')
        );
        assert!(ValidatedConfig::parse(body.as_bytes()).is_err());
    }

    #[test]
    fn a_measurement_that_could_never_be_proved_is_refused() {
        for bad in ["aa11".to_owned(), m('A'), m('g'), String::new()] {
            let err = ValidatedConfig::parse(&push(&[upstream(
                "one",
                &bad,
                "127.0.0.1:1",
                "127.0.0.1:2",
            )]))
            .err()
            .unwrap_or_else(|| panic!("accepted `{bad}`"));
            assert!(err.starts_with("upstreams[0].measurement"), "{err}");
        }
    }

    #[test]
    fn a_node_declared_twice_is_refused() {
        let err = ValidatedConfig::parse(&push(&[
            upstream("one", &m('a'), "127.0.0.1:1", "127.0.0.1:2"),
            upstream("two", &m('b'), "127.0.0.1:3", "127.0.0.1:4"),
            upstream("one", &m('c'), "127.0.0.1:5", "127.0.0.1:6"),
        ]))
        .err()
        .unwrap();
        assert!(
            err.contains("upstreams[2]") && err.contains("upstreams[0]"),
            "{err}"
        );
    }

    /// One bad entry refuses the push whole, and the answer names it.
    #[test]
    fn one_bad_address_refuses_the_whole_push() {
        let err = ValidatedConfig::parse(&push(&[
            upstream("one", &m('a'), "127.0.0.1:1", "127.0.0.1:2"),
            upstream("two", &m('b'), "127.0.0.1:3", "not an address"),
        ]))
        .err()
        .unwrap();
        assert!(err.starts_with("upstreams[1].client"), "{err}");
    }
}
