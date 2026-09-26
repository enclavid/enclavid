//! The table a push decodes into, and the check it has to pass.
//!
//! A module of its own so that nothing else — the port beside it included —
//! can see `RawConfig` or build a [`ValidatedConfig`] without
//! [`ValidatedConfig::parse`]. See `crate::config` for why that matters.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

/// One push as it decodes: the complete table, never a change to the previous
/// one.
///
/// Private to this module, and that is the whole of the guarantee: a decoded
/// table cannot be named anywhere else, so nothing outside can hold one that has
/// not been through `check`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// What each group is, by the label that names it.
    #[serde(deserialize_with = "unique")]
    groups: HashMap<String, Group>,
    /// Which members of which group serve each public name.
    #[serde(deserialize_with = "unique_tables")]
    names: Names,
    affinity: Affinity,
    #[serde(default)]
    tuning: Tuning,
}

/// Each public name, and under it the addresses of each group's members there.
pub type Names = HashMap<String, HashMap<String, Vec<String>>>;

/// A JSON object read into a map, refusing a key it has read already.
///
/// The JSON decoder keeps the last of two equal keys and says nothing, so a
/// push declaring one group or one name twice would have one of the two
/// quietly win. A struct needs none of this: a field given twice is already an
/// error there.
struct Unique<V>(HashMap<String, V>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Unique<V> {
    fn deserialize<D: serde::Deserializer<'de>>(from: D) -> Result<Unique<V>, D::Error> {
        struct Reading<V>(std::marker::PhantomData<V>);

        impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Reading<V> {
            type Value = Unique<V>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object with no key given twice")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut entries: A,
            ) -> Result<Unique<V>, A::Error> {
                let mut read = HashMap::new();
                while let Some((key, value)) = entries.next_entry::<String, V>()? {
                    match read.entry(key) {
                        std::collections::hash_map::Entry::Occupied(taken) => {
                            return Err(serde::de::Error::custom(format!(
                                "{} is given twice",
                                taken.key()
                            )));
                        }
                        std::collections::hash_map::Entry::Vacant(free) => {
                            free.insert(value);
                        }
                    }
                }
                Ok(Unique(read))
            }
        }

        from.deserialize_map(Reading(std::marker::PhantomData))
    }
}

/// A map with no key given twice — see [`Unique`].
fn unique<'de, D, V>(from: D) -> Result<HashMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Deserialize<'de>,
{
    Unique::deserialize(from).map(|read| read.0)
}

/// The names, with no name given twice, nor a group twice under one name.
fn unique_tables<'de, D>(from: D) -> Result<Names, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Unique::<Unique<Vec<String>>>::deserialize(from).map(|read| {
        read.0
            .into_iter()
            .map(|(name, table)| (name, table.0))
            .collect()
    })
}

/// What a group is: the build every one of its members runs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// The build every member runs. Proved at the handshake, not here.
    pub measurement: String,
}

/// A table every check has passed, and the only form routing is given.
///
/// The wrapper exists so that the checks cannot be skipped by a later caller
/// rather than to make them more thorough. It has no way out: `RawConfig` is
/// private to this module, so a reader borrows fields THROUGH this type and
/// never comes to hold a table whose provenance it cannot see. Reachable only
/// through [`ValidatedConfig::parse`].
pub struct ValidatedConfig(RawConfig);

impl ValidatedConfig {
    /// The table a push declares, or why it is refused.
    pub fn parse(body: &[u8]) -> Result<ValidatedConfig, String> {
        let raw: RawConfig = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        raw.check()?;
        Ok(ValidatedConfig(raw))
    }

    /// What each group is, by the label that names it.
    pub fn groups(&self) -> &HashMap<String, Group> {
        &self.0.groups
    }

    /// Which members of which group serve each public name.
    pub fn names(&self) -> &Names {
        &self.0.names
    }

    /// What affinity tokens are signed with, and for how long.
    pub fn affinity(&self) -> &Affinity {
        &self.0.affinity
    }

    /// Every timeout, limit and retry count, as this push sets them.
    pub fn tuning(&self) -> &Tuning {
        &self.0.tuning
    }
}

/// Every timeout, limit and retry count this role runs by.
///
/// Every part may be left out — the section, either half of it, any field —
/// and takes the value in the `Default` below: a number whose any reasonable
/// value works is one the host should not have to spell. A misspelt field is
/// still refused rather than quietly defaulted. Each value is bounded here by
/// what this build allows, and the few that depend on one another are checked
/// together — a push breaking any of it is refused whole.
#[derive(Deserialize, Clone, Copy, PartialEq, Debug, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Tuning {
    pub listener: ListenerTuning,
    pub upstream: UpstreamTuning,
}

/// The public listener's numbers. Read for each connection as it is accepted,
/// except `connections`, which is resized under the listener — see
/// `crate::listener`.
#[derive(Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct ListenerTuning {
    /// How many public connections are served at once.
    pub connections: usize,
    /// How many of those one source may hold.
    pub connections_per_source: usize,
    /// How many requests one public connection may have in flight. Each takes
    /// a leg to api, so this, times `connections`, is what bounds legs.
    pub streams_per_connection: u32,
    /// How long the PROXY header and the TLS handshake may take, together.
    #[serde(rename = "handshake_timeout_ms", deserialize_with = "millis")]
    pub handshake_timeout: Duration,
    /// How long an HTTP/1 request head may take to arrive.
    #[serde(rename = "header_timeout_ms", deserialize_with = "millis")]
    pub header_timeout: Duration,
    /// How often an idle HTTP/2 connection is pinged, and how long the answer
    /// may take before the peer is taken to be gone.
    #[serde(rename = "ping_interval_ms", deserialize_with = "millis")]
    pub ping_interval: Duration,
    /// How long a connection may go from its handshake to its first request.
    #[serde(rename = "first_request_timeout_ms", deserialize_with = "millis")]
    pub first_request_timeout: Duration,
    /// How long a connection may go between requests.
    #[serde(rename = "idle_timeout_ms", deserialize_with = "millis")]
    pub idle_timeout: Duration,
    /// How long any connection may live, busy or not.
    #[serde(rename = "lifetime_ms", deserialize_with = "millis")]
    pub lifetime: Duration,
    /// How long a connection being shut down has to finish what it started.
    #[serde(rename = "drain_timeout_ms", deserialize_with = "millis")]
    pub drain_timeout: Duration,
    /// How long a request body may pause between two frames.
    #[serde(rename = "request_body_pause_ms", deserialize_with = "millis")]
    pub request_body_pause: Duration,
    /// How long a request body may take to arrive whole, counted from the
    /// request's head.
    #[serde(rename = "request_body_timeout_ms", deserialize_with = "millis")]
    pub request_body_timeout: Duration,
}

/// The numbers for reaching api. Part of a set's identity, like its build: a
/// push that changes them builds the sets afresh — see `crate::upstream`.
#[derive(Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamTuning {
    /// How many requests one member may be starting at once — until api's
    /// answer head comes back.
    pub requests_per_member: usize,
    /// How long a request waits for a member that can take it, counted from
    /// when it asks — and again from when a member hands it back.
    #[serde(rename = "member_wait_ms", deserialize_with = "millis")]
    pub member_wait: Duration,
    /// How long a member has to START answering, counted from when the request
    /// body has all been sent.
    #[serde(rename = "answer_timeout_ms", deserialize_with = "millis")]
    pub answer_timeout: Duration,
    /// How many times one request may be offered, when legs will not open.
    pub tries: usize,
    /// How long a member is left out after a leg to it would not open.
    #[serde(rename = "cooldown_ms", deserialize_with = "millis")]
    pub cooldown: Duration,
    /// How long opening an attested leg may take — the dial and the handshake.
    #[serde(rename = "open_timeout_ms", deserialize_with = "millis")]
    pub open_timeout: Duration,
    /// How long a leg may sit parked before it is closed.
    #[serde(rename = "leg_idle_ms", deserialize_with = "millis")]
    pub leg_idle: Duration,
    /// How many legs may be parked across every member at once.
    pub parked_legs: usize,
}

/// What a push that leaves the listener's numbers out gets.
impl Default for ListenerTuning {
    fn default() -> ListenerTuning {
        ListenerTuning {
            connections: 256,
            // Generous, because many honest callers can share one address
            // behind a carrier's NAT.
            connections_per_source: 32,
            streams_per_connection: 8,
            handshake_timeout: Duration::from_secs(10),
            // The HTTP library's own default, stated because without a timer
            // it is not applied at all.
            header_timeout: Duration::from_secs(30),
            ping_interval: Duration::from_secs(20),
            // A caller that finished a handshake sends its request within a
            // round trip.
            first_request_timeout: Duration::from_secs(5),
            // Long enough that a page between two requests keeps its
            // connection; short enough that a place held for nothing comes back
            // within a minute.
            idle_timeout: Duration::from_secs(60),
            lifetime: Duration::from_secs(300),
            // Room for a request that had just started when the shutdown came:
            // its whole upload and its whole answer — see the relation checked
            // below.
            drain_timeout: Duration::from_secs(300),
            request_body_pause: Duration::from_secs(15),
            // A large capture over a slow mobile link.
            request_body_timeout: Duration::from_secs(120),
        }
    }
}

/// What a push that leaves the upstream numbers out gets.
impl Default for UpstreamTuning {
    fn default() -> UpstreamTuning {
        UpstreamTuning {
            requests_per_member: 16,
            // Short: both reasons a set has nothing to give resolve on their
            // own or not at all.
            member_wait: Duration::from_secs(2),
            // Far beyond any round api should take — a ceiling against
            // hanging, not a latency budget.
            answer_timeout: Duration::from_secs(120),
            // Rides out two members lost at once.
            tries: 3,
            cooldown: Duration::from_secs(10),
            open_timeout: Duration::from_secs(5),
            leg_idle: Duration::from_secs(60),
            parked_legs: 256,
        }
    }
}

fn millis<'de, D: serde::Deserializer<'de>>(from: D) -> Result<Duration, D::Error> {
    u64::deserialize(from).map(Duration::from_millis)
}

/// The most public connections a push may ask for.
const MOST_CONNECTIONS: usize = 4096;

/// The most streams one public connection may be allowed.
const MOST_STREAMS: u32 = 128;

/// The most legs a push may let park.
const MOST_PARKED: usize = 16384;

/// The descriptors this process holds besides connections and legs: its three
/// listeners, the log and attestation devices, the runtime's own, and the
/// configuration and health connections — with room to spare.
pub const OWN_DESCRIPTORS: u64 = 64;

/// The descriptors the largest tuning this build allows could need. What the
/// process asks for at boot; a push needing more than it got is refused.
pub const MOST_DESCRIPTORS: u64 =
    OWN_DESCRIPTORS + MOST_CONNECTIONS as u64 * (1 + MOST_STREAMS as u64) + MOST_PARKED as u64;

impl Tuning {
    /// The descriptors this tuning lets the process hold at once: one per
    /// public connection, one per stream in flight on it, and the parked legs.
    pub fn descriptors(&self) -> u64 {
        OWN_DESCRIPTORS
            + self.listener.connections as u64 * (1 + self.listener.streams_per_connection as u64)
            + self.upstream.parked_legs as u64
    }

    fn check(&self) -> Result<(), String> {
        let (l, u) = (&self.listener, &self.upstream);
        within("listener.connections", l.connections, 1, MOST_CONNECTIONS)?;
        within(
            "listener.connections_per_source",
            l.connections_per_source,
            1,
            l.connections,
        )?;
        within(
            "listener.streams_per_connection",
            l.streams_per_connection,
            1,
            MOST_STREAMS,
        )?;
        within(
            "upstream.requests_per_member",
            u.requests_per_member,
            1,
            1024,
        )?;
        within("upstream.tries", u.tries, 1, 10)?;
        within("upstream.parked_legs", u.parked_legs, 0, MOST_PARKED)?;
        for (field, value, least, most) in [
            (
                "listener.handshake_timeout_ms",
                l.handshake_timeout,
                100,
                60_000,
            ),
            ("listener.header_timeout_ms", l.header_timeout, 100, 120_000),
            ("listener.ping_interval_ms", l.ping_interval, 1_000, 300_000),
            (
                "listener.first_request_timeout_ms",
                l.first_request_timeout,
                100,
                60_000,
            ),
            ("listener.idle_timeout_ms", l.idle_timeout, 100, 3_600_000),
            ("listener.lifetime_ms", l.lifetime, 1_000, 86_400_000),
            ("listener.drain_timeout_ms", l.drain_timeout, 100, 3_600_000),
            (
                "listener.request_body_pause_ms",
                l.request_body_pause,
                100,
                300_000,
            ),
            (
                "listener.request_body_timeout_ms",
                l.request_body_timeout,
                1_000,
                3_600_000,
            ),
            ("upstream.member_wait_ms", u.member_wait, 10, 60_000),
            (
                "upstream.answer_timeout_ms",
                u.answer_timeout,
                100,
                3_600_000,
            ),
            ("upstream.cooldown_ms", u.cooldown, 10, 600_000),
            ("upstream.open_timeout_ms", u.open_timeout, 100, 60_000),
            ("upstream.leg_idle_ms", u.leg_idle, 100, 3_600_000),
        ] {
            within(field, value.as_millis(), least, most)?;
        }

        // A connection being shut down must outlast the longest a request on
        // it may still be waiting for its answer to start — every try's wait
        // for a member and its opening, its whole upload, then the answer's own
        // wait — or the shutdown cuts off requests that were being served.
        let longest = (u.member_wait + u.open_timeout) * u.tries as u32
            + l.request_body_timeout
            + u.answer_timeout;
        if l.drain_timeout <= longest {
            return Err(format!(
                "tuning.listener.drain_timeout_ms: must exceed tries x (member_wait_ms + \
                 open_timeout_ms) + request_body_timeout_ms + answer_timeout_ms = {} ms",
                longest.as_millis()
            ));
        }
        Ok(())
    }
}

/// `value` within `least..=most`, or why not.
fn within<T: PartialOrd + std::fmt::Display>(
    field: &str,
    value: T,
    least: T,
    most: T,
) -> Result<(), String> {
    if value < least || value > most {
        return Err(format!("tuning.{field}: expected {least} to {most}"));
    }
    Ok(())
}

/// What this role signs affinity tokens with — see `crate::route::affinity` for
/// why this is the host's to give and not something derived from the chip.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Affinity {
    pub key: Key,
    /// The key before it, accepted and never minted with, so that rotating one
    /// does not strand the tokens issued in the minutes before the push.
    #[serde(default)]
    pub previous_key: Option<Key>,
    /// How long a minted token stays good. Bounded here because it is the only
    /// thing limiting how long a caller can keep placing work on a group it was
    /// once given.
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
        self.tuning.check()?;

        if self.affinity.ttl_seconds == 0 || self.affinity.ttl_seconds > MAX_TTL_SECONDS {
            return Err(format!(
                "affinity.ttl_seconds: expected 1 to {MAX_TTL_SECONDS}"
            ));
        }
        // All zeros is what a key left unset reads as, and a token signed with
        // it is one any caller could mint.
        for (field, key) in [
            ("affinity.key", Some(&self.affinity.key)),
            ("affinity.previous_key", self.affinity.previous_key.as_ref()),
        ] {
            if key.is_some_and(|key| key.0 == [0; 32]) {
                return Err(format!("{field}: all zeros, which is no key"));
            }
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

        let mut seen: HashMap<String, &str> = HashMap::new();
        // Which group each address is under. One group only: an api instance
        // under two labels is one key domain wearing two names, and a label no
        // other session shares is a tag on the session placed there.
        let mut under: HashMap<&str, &str> = HashMap::new();
        for (name, table) in &self.names {
            // A certificate is minted over these, so a name no client could
            // ever match is refused here, where there is a sender to tell —
            // rather than at the mint, where the answer is a role serving
            // nothing. `crate::identity::tls` checks it again because it must.
            if tokio_rustls::rustls::pki_types::DnsName::try_from(name.clone()).is_err() {
                return Err(format!("names[{name}]: not a DNS name"));
            }
            // A DNS name may end in a dot, and a certificate would be minted
            // over it, but a client asks for the name WITHOUT one — so every
            // connection would be told this role does not serve it, while the
            // role looked perfectly well.
            if name.ends_with('.') {
                return Err(format!("names[{name}]: drop the trailing dot"));
            }
            // Names are matched without regard to case, so two that differ only
            // in case are one name declared twice, with two tables — and which
            // one a connection got would depend on an ordering nobody chose.
            if let Some(other) = seen.insert(name.to_ascii_lowercase(), name) {
                return Err(format!("names[{name}]: the same name as names[{other}]"));
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
                    if let Some(other) = under.insert(addr, label)
                        && other != label
                    {
                        return Err(format!(
                            "names[{name}][{label}][{i}]: {addr} is under group {other} as well; \
                             an address belongs to one group"
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// TCP arm only: the fixtures declare TCP member addresses, which the vsock arm
/// rightly refuses.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use crate::config::testing::TUNING;

    /// Two names, and nothing here distinguishes them — a push declares names
    /// and what each one means is not this role's business.
    const FIRST: &str = "first.example.com";
    const SECOND: &str = "second.example.com";

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
                "{FIRST}": {{ "one": ["127.0.0.1:1", "127.0.0.1:3"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2", "127.0.0.1:4"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            m('a')
        )
    }

    fn parse(body: &str) -> Result<ValidatedConfig, String> {
        ValidatedConfig::parse(body.as_bytes())
    }

    #[test]
    fn a_group_is_declared_once_and_reached_under_both_names() {
        let got = parse(&push()).unwrap();
        assert_eq!(got.groups()["one"].measurement, m('a'));
        assert_eq!(got.names()[FIRST]["one"].len(), 2);
        assert_eq!(got.names()[SECOND]["one"][1], "127.0.0.1:4");
        assert_eq!(got.affinity().ttl_seconds, 600);
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
                "{FIRST}": {{ "one": ["127.0.0.1:1", "127.0.0.1:3"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
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
                "{FIRST}": {{ "one": ["127.0.0.1:1"], "two": ["127.0.0.1:5"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            m('a'),
            m('b')
        );
        let err = parse(&body).err().unwrap();
        assert!(err.contains("two") && err.contains(SECOND), "{err}");
    }

    #[test]
    fn a_name_pointing_at_no_declared_group_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1"], "ghost": ["127.0.0.1:9"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
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
                "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }},
                "elsewhere.example.com": {{ "one": ["127.0.0.1:9"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            m('a')
        );
        let got = parse(&body).unwrap();
        assert_eq!(got.names().len(), 3);
    }

    /// A certificate is minted over these, so one no client could match is
    /// refused where there is still a sender to tell.
    #[test]
    fn a_name_that_is_not_a_name_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{ "not a dns name": {{ "one": ["127.0.0.1:1"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            m('a')
        );
        let err = parse(&body).err().unwrap();
        assert!(err.contains("not a DNS name"), "{err}");
    }

    /// A name a client could never ask for, or one declared twice, is refused
    /// while there is still a sender to tell — not found later as a role that
    /// answers every connection with "not served here".
    #[test]
    fn a_name_no_client_asks_for_or_one_declared_twice_is_refused() {
        let with_names = |first: &str, second: &str| {
            format!(
                r#"{{
                  "groups": {{ "one": {{ "measurement": "{}" }} }},
                  "names": {{
                    "{first}": {{ "one": ["127.0.0.1:1"] }},
                    "{second}":  {{ "one": ["127.0.0.1:2"] }} }},
                  "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
                m('a')
            )
        };

        let dotted = parse(&with_names("first.example.com.", SECOND))
            .err()
            .unwrap();
        assert!(dotted.contains("trailing dot"), "{dotted}");

        let twice = parse(&with_names(FIRST, "FIRST.example.com"))
            .err()
            .unwrap();
        assert!(twice.contains("the same name"), "{twice}");
    }

    /// A push declaring no name at all leaves nothing to mint a certificate
    /// over, which is a role that could serve nobody.
    #[test]
    fn a_push_with_no_names_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{}},
              "names": {{}},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#
        );
        assert!(parse(&body).is_err());
    }

    #[test]
    fn a_group_with_no_members_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{FIRST}": {{ "one": [] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
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
              "names": {{ "{FIRST}": {{}}, "{SECOND}": {{}} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#
        );
        assert!(parse(&body).unwrap().groups().is_empty());
    }

    #[test]
    fn a_label_that_could_not_travel_is_refused() {
        for bad in ["Group", "no de", "a/b", &"x".repeat(33)] {
            let body = format!(
                r#"{{
                  "groups": {{ "{bad}": {{ "measurement": "{}" }} }},
                  "names": {{
                    "{FIRST}": {{ "{bad}": ["127.0.0.1:1"] }},
                    "{SECOND}":  {{ "{bad}": ["127.0.0.1:2"] }} }},
                  "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
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
                    "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                    "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
                  "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#
            );
            let err = parse(&body)
                .err()
                .unwrap_or_else(|| panic!("accepted `{bad}`"));
            assert!(err.contains("measurement"), "{err}");
        }
    }

    /// An address belongs to one group: under two labels, one api instance
    /// would be one key domain wearing two names — and a label that no other
    /// session shares is a tag on the session placed on it. The same group may
    /// list the address under every name.
    #[test]
    fn an_address_under_two_groups_is_refused() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }},
                           "two": {{ "measurement": "{}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1"], "two": ["127.0.0.1:5"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"], "two": ["127.0.0.1:1"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            m('a'),
            m('b')
        );
        let err = parse(&body).err().unwrap();
        assert!(err.contains("127.0.0.1:1"), "{err}");

        let shared_by_names = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:1"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            m('a')
        );
        assert!(parse(&shared_by_names).is_ok());
    }

    #[test]
    fn one_bad_address_refuses_the_whole_push() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2", "not an address"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            m('a')
        );
        let err = parse(&body).err().unwrap();
        assert!(err.contains("[one][1]"), "{err}");
    }

    /// A group, a name, or a group under one name given twice is refused,
    /// rather than one of the two quietly winning.
    #[test]
    fn a_key_given_twice_is_refused() {
        let group = format!(r#"{{ "measurement": "{}" }}"#, m('a'));
        for (twice, which) in [
            (
                format!(
                    r#"{{
                      "groups": {{ "one": {group}, "one": {group} }},
                      "names": {{
                        "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                        "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
                      "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#
                ),
                "one",
            ),
            (
                format!(
                    r#"{{
                      "groups": {{ "one": {group} }},
                      "names": {{
                        "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                        "{FIRST}": {{ "one": ["127.0.0.1:3"] }},
                        "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
                      "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#
                ),
                FIRST,
            ),
            (
                format!(
                    r#"{{
                      "groups": {{ "one": {group} }},
                      "names": {{
                        "{FIRST}": {{ "one": ["127.0.0.1:1"], "one": ["127.0.0.1:3"] }},
                        "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
                      "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#
                ),
                "one",
            ),
        ] {
            let err = parse(&twice)
                .err()
                .unwrap_or_else(|| panic!("accepted {twice}"));
            assert!(err.contains(&format!("{which} is given twice")), "{err}");
        }
    }

    #[test]
    fn an_unknown_key_is_refused_not_ignored() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}", "verify": false }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            m('a')
        );
        assert!(parse(&body).is_err());
    }

    /// The key is what makes a token unforgeable, and the expiry is what bounds
    /// how long a caller can keep a group it was handed.
    #[test]
    fn affinity_is_required_and_checked() {
        let with = |affinity: &str| {
            format!(
                r#"{{
                  "groups": {{ "one": {{ "measurement": "{}" }} }},
                  "names": {{
                    "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                    "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
                  "affinity": {affinity}, {TUNING} }}"#,
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
            format!(r#"{{"key":"{}","ttl_seconds":600}}"#, "0".repeat(64)),
            format!(
                r#"{{"key":"{KEY}","previous_key":"{}","ttl_seconds":600}}"#,
                "0".repeat(64)
            ),
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

    /// A push whose `tuning` member is `tuning`.
    fn tuned(tuning: &str) -> String {
        format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:2"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }}, {tuning} }}"#,
            m('a')
        )
    }

    /// The fixture every test pushes says what the constants beside it say, so
    /// a test reading one and a fixture sending the other cannot drift apart.
    #[test]
    fn the_test_tuning_says_what_its_constants_say() {
        assert_eq!(
            *parse(&push()).unwrap().tuning(),
            crate::config::testing::tuning()
        );
    }

    /// Any part of the tuning may be left out — all of it, or all but one
    /// number — and what is left out takes its default. A misspelt field is
    /// still refused: quietly defaulting it would hide the mistake.
    #[test]
    fn tuning_may_be_left_out_in_whole_or_in_part() {
        let without_tuning = push().replace(&format!(", {TUNING}"), "");
        assert_ne!(without_tuning, push());
        assert_eq!(*parse(&without_tuning).unwrap().tuning(), Tuning::default());

        let one_number = parse(&tuned(r#""tuning": { "upstream": { "tries": 2 } }"#)).unwrap();
        let expected = Tuning {
            upstream: UpstreamTuning {
                tries: 2,
                ..UpstreamTuning::default()
            },
            ..Tuning::default()
        };
        assert_eq!(*one_number.tuning(), expected);

        let misspelt = TUNING.replace(r#""tries": 3,"#, r#""tires": 3,"#);
        assert_ne!(misspelt, TUNING);
        assert!(parse(&tuned(&misspelt)).is_err(), "a misspelt field");
    }

    /// The defaults pass every check a push has to, and fit the most
    /// descriptors this build asks for.
    #[test]
    fn the_defaults_are_a_tuning_a_push_could_send() {
        let defaults = Tuning::default();
        assert_eq!(defaults.check(), Ok(()));
        assert!(defaults.descriptors() <= MOST_DESCRIPTORS);
    }

    #[test]
    fn each_value_is_bounded() {
        for (from, to, field) in [
            (
                r#""connections": 256"#,
                r#""connections": 0"#,
                "listener.connections",
            ),
            (
                r#""connections": 256"#,
                r#""connections": 4097"#,
                "listener.connections",
            ),
            (
                r#""connections_per_source": 2"#,
                r#""connections_per_source": 257"#,
                "listener.connections_per_source",
            ),
            (
                r#""streams_per_connection": 8"#,
                r#""streams_per_connection": 0"#,
                "listener.streams_per_connection",
            ),
            (
                r#""idle_timeout_ms": 1000"#,
                r#""idle_timeout_ms": 0"#,
                "listener.idle_timeout_ms",
            ),
            (r#""tries": 3"#, r#""tries": 0"#, "upstream.tries"),
            (
                r#""parked_legs": 256"#,
                r#""parked_legs": 16385"#,
                "upstream.parked_legs",
            ),
        ] {
            let bad = TUNING.replace(from, to);
            assert_ne!(bad, TUNING, "{to}");
            let err = parse(&tuned(&bad)).err().unwrap();
            assert!(err.contains(field), "{to}: {err}");
        }
    }

    /// The values that depend on one another are checked together, and a push
    /// breaking the relation is refused even though each value is in range.
    #[test]
    fn values_that_depend_on_each_other_are_checked_together() {
        // A shutdown would cut off requests still waiting for their answer:
        // 3 x (200 + 200) + 5000 + 300.
        let short_drain = TUNING.replace(
            r#""drain_timeout_ms": 150000"#,
            r#""drain_timeout_ms": 6500"#,
        );
        let err = parse(&tuned(&short_drain)).err().unwrap();
        assert!(err.contains("drain_timeout_ms"), "{err}");
        let just_enough = TUNING.replace(
            r#""drain_timeout_ms": 150000"#,
            r#""drain_timeout_ms": 6501"#,
        );
        assert!(parse(&tuned(&just_enough)).is_ok());

        // Each share is at most the whole.
        let greedy = TUNING.replace(
            r#""connections_per_source": 2"#,
            r#""connections_per_source": 257"#,
        );
        assert!(parse(&tuned(&greedy)).is_err());
    }

    /// What a tuning can make the process hold: one descriptor per connection,
    /// one per stream on it, and the parked legs, on top of its own.
    #[test]
    fn a_tuning_says_how_many_descriptors_it_needs() {
        let tuning = crate::config::testing::tuning();
        assert_eq!(tuning.descriptors(), 64 + 256 * (1 + 8) + 256);
        assert!(tuning.descriptors() <= MOST_DESCRIPTORS);
    }
}
