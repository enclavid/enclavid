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
//! Every value here says WHERE this role may go and HOW MUCH of the work a
//! given instance takes — never WHETHER to check what it finds there. A group's
//! measurement is a routing hint the connector proves at the handshake, so a
//! lie about one is a route that fails, not a route that is taken. There is
//! deliberately no field that could say otherwise.
//!
//! ## A group, not a machine
//!
//! api seals a session's state under a key derived from the chip and the
//! measurement, so every instance of one build on one part can serve any
//! session of that build. The unit this role routes to is therefore that set —
//! a GROUP — and its members are interchangeable. A label names the group, so
//! an applicant's link and a consumer's token survive the loss of any one
//! machine, and a request that fails on one member can be tried on another.
//!
//! The host declares which instances form a group, and this role does not take
//! that on trust: every leg proves a chip and a measurement at the handshake,
//! and a member that proves something other than its group's is refused — see
//! `crate::leg`.
//!
//! ## The shape
//!
//! Groups are declared once and the names refer to them, which is how a
//! reverse proxy's configuration has always read: what a backend IS, then which
//! of them each served name may reach. A group's addresses differ per name
//! because one api process serves the two on two ports.
//!
//! ```text
//! groups: one -> the build it runs
//! names:  verify.example.com -> one -> the addresses of its members there
//!         api.example.com    -> one -> the addresses of its members there
//! ```
//!
//! ## The type is the grammar
//!
//! JSON decoded into these structs with `deny_unknown_fields`: an unknown or
//! misspelt key is a refusal rather than a line quietly ignored, and nothing
//! beyond what the structs spell can be expressed.
//!
//! What the grammar cannot say is whether a value could do its job — a label
//! that survives a URL, a measurement a quote could carry, an address something
//! could dial, a group named in one place and declared in none. That is the
//! second step, and it is a type rather than a habit: [`RawConfig`] is what
//! decodes, [`ValidatedConfig`] is what routing is given, and the only way
//! between them is [`ValidatedConfig::parse`].
//!
//! A push is refused WHOLE if any part of it is wrong, and the answer says
//! which. There is a sender to tell, and a table missing one declared build is
//! a quieter failure than a push that did not apply.

use std::collections::HashMap;

use serde::Deserialize;

/// One push as it decodes: the complete table, never a change to the previous
/// one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    /// What each group is, by the label that names it.
    pub groups: HashMap<String, Group>,
    /// Which members of which group serve each public name.
    pub names: HashMap<String, HashMap<String, Vec<String>>>,
    pub affinity: Affinity,
}

/// What a group is. Only its build today; what it is WORTH — weights, how many
/// at once — belongs beside the addresses in `names`, because that is where the
/// choosing happens.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// The build every member runs. Proved at the handshake, not here.
    pub measurement: String,
}

/// A table every check has passed, and the only form routing is given.
///
/// The wrapper exists so that the checks cannot be skipped by a later caller
/// rather than to make them more thorough: `Upstreams::replaced` takes this,
/// and this is reachable only through [`ValidatedConfig::parse`].
pub struct ValidatedConfig(RawConfig);

impl ValidatedConfig {
    /// The table a push declares, or why it is refused.
    pub fn parse(body: &[u8]) -> Result<ValidatedConfig, String> {
        let raw: RawConfig = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        raw.check()?;
        Ok(ValidatedConfig(raw))
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
    /// thing limiting how long a consumer can keep placing work on a group it
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

/// What a group label may be.
///
/// It ends up in a URL path and in a token, so it is kept to what is safe in
/// both and short enough to read in a log: lowercase letters, digits and
/// hyphens. The limit is not a security boundary — the label selects among
/// groups the host declared and nothing else — it is there so that a mistake in
/// the host's configuration is refused at the push rather than found in a link.
fn is_group_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 32
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl RawConfig {
    /// What the grammar could not say: whether each value could do the job its
    /// field names, and whether the two halves agree with each other.
    ///
    /// The reason goes back to the sender and nowhere else, and names the part
    /// it is about. It may quote what the host sent, which is the host's own
    /// configuration.
    fn check(&self) -> Result<(), String> {
        if self.affinity.ttl_seconds == 0 || self.affinity.ttl_seconds > MAX_TTL_SECONDS {
            return Err(format!(
                "affinity.ttl_seconds: expected 1 to {MAX_TTL_SECONDS}"
            ));
        }

        for (label, group) in &self.groups {
            if !is_group_label(label) {
                return Err(format!(
                    "groups[{label}]: a label is 1 to 32 characters of a-z, 0-9 or -"
                ));
            }
            if fleet_transport::Measurement::parse(&group.measurement).is_none() {
                return Err(format!(
                    "groups[{label}].measurement: expected 96 lowercase hex characters"
                ));
            }
        }

        if self.names.is_empty() {
            return Err("names: a push says which names this role answers to".into());
        }

        for (name, table) in &self.names {
            // A certificate is minted over these, so a name no client could
            // ever match is refused here, where there is a sender to tell —
            // rather than at the mint, where the answer is a role serving
            // nothing. `crate::tls` checks it again because it must.
            if tokio_rustls::rustls::pki_types::DnsName::try_from(name.clone()).is_err() {
                return Err(format!("names[{name}]: not a DNS name"));
            }
            // Every group must be reachable on every name, or a session placed
            // through one name would be unroutable through another — which the
            // caller would meet as an unavailable upstream, long after the
            // mistake was made.
            for label in self.groups.keys() {
                if !table.contains_key(label) {
                    return Err(format!(
                        "names[{name}][{label}]: missing, and it is declared"
                    ));
                }
            }
            for (label, members) in table {
                if !self.groups.contains_key(label) {
                    return Err(format!("names[{name}][{label}]: no such group is declared"));
                }
                if members.is_empty() {
                    return Err(format!("names[{name}][{label}]: declares no members"));
                }
                for (i, addr) in members.iter().enumerate() {
                    fleet_transport::check_dial_addr(addr)
                        .map_err(|e| format!("names[{name}][{label}][{i}]: {e}"))?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPLICANT: &str = "verify.example.com";
    const CONSUMER: &str = "api.example.com";

    fn m(c: char) -> String {
        c.to_string().repeat(96)
    }

    /// A key the validation accepts; what it signs is not this module's concern.
    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// One group on two machines, reachable under both names.
    fn push() -> String {
        format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{APPLICANT}": {{ "one": ["127.0.0.1:1", "127.0.0.1:3"] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2", "127.0.0.1:4"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a')
        )
    }

    fn parse(body: &str) -> Result<ValidatedConfig, String> {
        ValidatedConfig::parse(body.as_bytes())
    }

    #[test]
    fn a_group_is_declared_once_and_reached_under_both_names() {
        let got = parse(&push()).unwrap().into_inner();
        assert_eq!(got.groups["one"].measurement, m('a'));
        assert_eq!(got.names[APPLICANT]["one"].len(), 2);
        assert_eq!(got.names[CONSUMER]["one"][1], "127.0.0.1:4");
        assert_eq!(got.affinity.ttl_seconds, 600);
    }

    /// The members of a group are interchangeable, so the two names need not
    /// list the same number of them — what has to match is the group, and that
    /// is proved at the handshake rather than counted here.
    #[test]
    fn the_two_names_need_not_list_the_same_members() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{APPLICANT}": {{ "one": ["127.0.0.1:1", "127.0.0.1:3"] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a')
        );
        assert!(parse(&body).is_ok());
    }

    /// A group placed through one name and unreachable through the other is a
    /// session that can be created and never continued.
    #[test]
    fn a_group_missing_from_one_name_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }},
                           "two": {{ "measurement": "{}" }} }},
              "names": {{
                "{APPLICANT}": {{ "one": ["127.0.0.1:1"], "two": ["127.0.0.1:5"] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a'),
            m('b')
        );
        let err = parse(&body).err().unwrap();
        assert!(err.contains("two") && err.contains(CONSUMER), "{err}");
    }

    #[test]
    fn a_name_pointing_at_no_declared_group_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{APPLICANT}": {{ "one": ["127.0.0.1:1"], "ghost": ["127.0.0.1:9"] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a')
        );
        let err = parse(&body).err().unwrap();
        assert!(err.contains("ghost"), "{err}");
    }

    /// The names are the push's to declare, and a third one is a third name
    /// this role will answer for — not a mistake.
    #[test]
    fn a_push_may_declare_any_names() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{APPLICANT}": {{ "one": ["127.0.0.1:1"] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }},
                "elsewhere.example.com": {{ "one": ["127.0.0.1:9"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a')
        );
        let got = parse(&body).unwrap().into_inner();
        assert_eq!(got.names.len(), 3);
    }

    /// A certificate is minted over these, so one no client could match is
    /// refused where there is still a sender to tell.
    #[test]
    fn a_name_that_is_not_a_name_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{ "not a dns name": {{ "one": ["127.0.0.1:1"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a')
        );
        let err = parse(&body).err().unwrap();
        assert!(err.contains("not a DNS name"), "{err}");
    }

    /// A push declaring no name at all leaves nothing to mint a certificate
    /// over, which is a role that could serve nobody.
    #[test]
    fn a_push_with_no_names_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{}},
              "names": {{}},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#
        );
        assert!(parse(&body).is_err());
    }

    #[test]
    fn a_group_with_no_members_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{APPLICANT}": {{ "one": [] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a')
        );
        assert!(parse(&body).is_err());
    }

    /// Declaring no group at all is a state the host may choose, not a mistake
    /// to refuse: every request then fails as an unavailable upstream.
    #[test]
    fn an_empty_table_is_a_table() {
        let body = format!(
            r#"{{
              "groups": {{}},
              "names": {{ "{APPLICANT}": {{}}, "{CONSUMER}": {{}} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#
        );
        assert!(parse(&body).unwrap().into_inner().groups.is_empty());
    }

    #[test]
    fn a_label_that_could_not_travel_is_refused() {
        for bad in ["Group", "no de", "a/b", &"x".repeat(33)] {
            let body = format!(
                r#"{{
                  "groups": {{ "{bad}": {{ "measurement": "{}" }} }},
                  "names": {{
                    "{APPLICANT}": {{ "{bad}": ["127.0.0.1:1"] }},
                    "{CONSUMER}":  {{ "{bad}": ["127.0.0.1:2"] }} }},
                  "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
                m('a')
            );
            assert!(parse(&body).is_err(), "accepted `{bad}`");
        }
    }

    #[test]
    fn a_measurement_that_could_never_be_proved_is_refused() {
        for bad in ["aa11".to_owned(), m('A'), m('g'), String::new()] {
            let body = format!(
                r#"{{
                  "groups": {{ "one": {{ "measurement": "{bad}" }} }},
                  "names": {{
                    "{APPLICANT}": {{ "one": ["127.0.0.1:1"] }},
                    "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }} }},
                  "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#
            );
            let err = parse(&body)
                .err()
                .unwrap_or_else(|| panic!("accepted `{bad}`"));
            assert!(err.contains("measurement"), "{err}");
        }
    }

    #[test]
    fn one_bad_address_refuses_the_whole_push() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{APPLICANT}": {{ "one": ["127.0.0.1:1"] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2", "not an address"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a')
        );
        let err = parse(&body).err().unwrap();
        assert!(err.contains("[one][1]"), "{err}");
    }

    #[test]
    fn an_unknown_key_is_refused_not_ignored() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}", "verify": false }} }},
              "names": {{
                "{APPLICANT}": {{ "one": ["127.0.0.1:1"] }},
                "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#,
            m('a')
        );
        assert!(parse(&body).is_err());
    }

    /// The key is what makes a token unforgeable, and the expiry is what bounds
    /// how long a consumer can keep a group it was handed.
    #[test]
    fn affinity_is_required_and_checked() {
        let with = |affinity: &str| {
            format!(
                r#"{{
                  "groups": {{ "one": {{ "measurement": "{}" }} }},
                  "names": {{
                    "{APPLICANT}": {{ "one": ["127.0.0.1:1"] }},
                    "{CONSUMER}":  {{ "one": ["127.0.0.1:2"] }} }},
                  "affinity": {affinity} }}"#,
                m('a')
            )
        };

        for bad in [
            r#"{"ttl_seconds":600}"#.to_owned(),
            r#"{"key":"abcd","ttl_seconds":600}"#.to_owned(),
            format!(r#"{{"key":"{KEY}"}}"#),
            format!(r#"{{"key":"{KEY}","ttl_seconds":0}}"#),
            format!(r#"{{"key":"{KEY}","ttl_seconds":3601}}"#),
            format!(r#"{{"key":"{KEY}","previous_key":"nope","ttl_seconds":600}}"#),
        ] {
            assert!(parse(&with(&bad)).is_err(), "accepted `{bad}`");
        }
        assert!(
            parse(&with(&format!(
                r#"{{"key":"{KEY}","previous_key":"{KEY}","ttl_seconds":600}}"#
            )))
            .is_ok()
        );
    }
}
