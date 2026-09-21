//! Which api a request goes to, and how the connection to it is made.
//!
//! ## The unit is a group, not a machine
//!
//! api seals a session's state under a key derived from the chip and the
//! measurement, and reads that state back from the storage CVM on every
//! request — it keeps no session in memory. So every instance of one build on
//! one part can serve any session of that build, and the thing worth naming is
//! that SET rather than any one machine.
//!
//! A label names the group. A link carries it, a token carries it, and inside it
//! every member will do: a request whose member has gone can be tried on another,
//! and a link outlives the machine that answered it first.
//!
//! What the host declares about grouping this role does not take on trust. Each
//! leg proves a chip and a measurement at the handshake, so a group whose
//! members are not one key domain produces a leg that fails rather than a route
//! that is taken.
//!
//! ## Two questions, two answers, and neither is a path
//!
//! **Which NAME** comes from the TLS handshake, and it decides which addresses
//! of a group are the right ones, because one api process listens on more than
//! one port. WHY it does is not known here and is not needed; a name maps to
//! addresses and that is the whole of it.
//!
//! **Which GROUP** comes from the caller: a label it was given, or — having
//! none — a measurement it names, against which this role places it. This role
//! holds no pin of its own: the caller says which build it is willing to be
//! served by, having first verified this role's own attestation. That is a
//! delegation, and it is what lets api be upgraded without rebuilding this role.
//!
//! So this role never parses a path beyond the label a link carries, and
//! whatever else that path holds stays out of its reach.
//!
//! ## The host says where, and never what
//!
//! Addresses arrive from the host. An address is an untrusted input rather than
//! an assertion — it says where this role MAY go, never what it will accept —
//! and the declared measurement is a routing hint that [`connect`] PROVES at
//! the handshake before a byte of HTTP crosses. A substituted address fails
//! there; a lie about which build sits at it fails there too.
//!
//! Each push produces a whole new [`Upstreams`], and a request routes against
//! whichever table was current when it arrived, so no request sees half of one
//! push and half of the next.
//!
//! ## The connection to api is attested, in the attested build
//!
//! Both guests may be anywhere, so the hop is guest → host → guest and a host
//! process splices every byte. Without TLS on this leg, everything the public
//! session protected on its first hop would be in the clear on its second, and
//! this role would move the exposure rather than remove it.
//!
//! api asks this end for nothing — it could not, since what it serves is open to
//! callers that hold no certificate. See `enclavid_api::endorsement`. This end
//! still verifies api, which is the direction that carries the weight.
//!
//! A developer build dials plain TCP and verifies nothing, because there is no
//! host between the two processes to protect anything from — the same axis on
//! which api's own inbound chooses whether to terminate RA-TLS at all.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Whether a member can be given work.
///
/// Learned from this role's own legs rather than declared: a member that would
/// not answer is marked when a request meets it, and proved well again by a
/// dial that succeeds — see `crate::probe`. Nothing the host says sets it.
#[derive(Debug)]
pub struct Ready(AtomicBool);

impl Default for Ready {
    /// A freshly declared member starts ready. The host has just said it is
    /// part of the fleet, and the alternative — refusing work until something
    /// proves otherwise — turns each push into an outage.
    fn default() -> Self {
        Ready(AtomicBool::new(true))
    }
}

impl Ready {
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Relaxed);
    }

    pub fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// One instance of a group, at the address it serves one name on.
struct Instance {
    addr: String,
    ready: Arc<Ready>,
}

/// One instance and everything needed to reach it, as the prober sees it.
pub struct Member {
    pub addr: String,
    pub measurement: String,
    pub part: Arc<Part>,
    pub ready: Arc<Ready>,
}

/// A set of api instances that are one key domain, and so interchangeable.
struct Group {
    /// The build every member is DECLARED to run. [`connect`] proves it.
    measurement: String,
    /// The part every member must prove it runs on — see [`Part`].
    part: Arc<Part>,
    /// Members by the name they serve. The lists need not be the same length:
    /// what has to match across names is the group, not the machine.
    by_name: HashMap<String, Vec<Instance>>,
}

/// The chip a group's members turned out to be on.
///
/// A group is a set of instances that can serve each other's sessions, and what
/// makes that true is a key api derives from the PART and the measurement. The
/// measurement the host declares and this role proves; the part it does not
/// declare at all — so the first member to answer settles it, and every member
/// after has to agree.
///
/// A host that staples two key domains into one label therefore gets a leg that
/// fails rather than a session that lands where its state cannot be opened. The
/// answer is per table: a later push may say something different, and a session
/// could not have survived that push anyway.
#[derive(Default)]
pub struct Part(std::sync::OnceLock<String>);

impl Part {
    /// Settle the part, or refuse a member that is not on it.
    pub fn agrees(&self, chip: &str) -> bool {
        self.0.get_or_init(|| chip.to_owned()) == chip
    }
}

/// Everywhere this role may forward to, as of one push.
pub struct Upstreams {
    /// The names this role answers to, as the push declared them. A
    /// certificate is minted over exactly these — see `crate::listen`.
    served: Vec<String>,
    /// Built once, at boot, and carried into every table after. It holds the
    /// attestor and the verifier, neither of which changes with the fleet.
    tls: Tls,
    groups: HashMap<String, Group>,
    /// What affinity tokens are signed with, as of this push. `None` only
    /// before the first one, when nothing is served yet.
    affinity: Option<crate::affinity::Keys>,
    /// Where the next choice starts, among groups and among members.
    ///
    /// Round robin, and deliberately the dullest thing that spreads load: this
    /// role knows nothing about how much work a session is, and a cleverer rule
    /// would be guessing. It is not carried across pushes — after one, the
    /// table it counted over no longer exists.
    next: AtomicUsize,
}

/// Where one request goes: a group, an address in it, the build that must be
/// proved there, and the part the rest of that group turned out to be on.
pub struct Target<'a> {
    pub group: &'a str,
    pub addr: &'a str,
    pub measurement: &'a str,
    pub part: Arc<Part>,
}

/// Why a request could not be forwarded.
///
/// Two variants because they are two answers to the caller: one says nothing
/// was asked for, the other says what was asked for is not here. What the
/// caller is told for each is `crate::proxy`'s to decide.
pub enum NoRoute {
    /// No measurement was named where one is required.
    Unspecified,
    /// A build was named and no group declares it; or a label was named and no
    /// group carries it; or the name this connection settled is not served. One
    /// answer for all three: which groups exist and what they run is the host's
    /// business and changes under it.
    NoSuchGroup,
}

impl Upstreams {
    /// No api and no names: what this role holds until the host's first push.
    ///
    /// Nothing is served in this state — there is no certificate to present,
    /// because a certificate is over names and the names have not arrived.
    pub fn empty() -> Upstreams {
        Upstreams {
            served: Vec::new(),
            tls: tls_client(),
            groups: HashMap::new(),
            affinity: None,
            next: AtomicUsize::new(0),
        }
    }

    /// The table a push declares, keeping what this role has learned about the
    /// members it still declares.
    ///
    /// A member is the same member if its group, its name and its address are
    /// the same. Anything else is a member this table has not met, and it
    /// starts ready.
    /// Read THROUGH the wrapper rather than out of it: what a push decoded into
    /// cannot be named outside `crate::config`, so this is where the checked
    /// form turns into the routing one and nowhere else could be.
    pub fn replaced(&self, declared: &crate::config::ValidatedConfig) -> Upstreams {
        let groups = declared
            .groups()
            .iter()
            .map(|(label, group)| {
                let by_name = declared
                    .names()
                    .iter()
                    .filter_map(|(name, table)| {
                        let members = table.get(label)?;
                        let members = members
                            .iter()
                            .map(|addr| Instance {
                                ready: self.known(label, name, addr),
                                addr: addr.clone(),
                            })
                            .collect();
                        Some((name.clone(), members))
                    })
                    .collect();
                (
                    label.clone(),
                    Group {
                        measurement: group.measurement.clone(),
                        part: Arc::new(Part::default()),
                        by_name,
                    },
                )
            })
            .collect();

        let mut served: Vec<String> = declared.names().keys().cloned().collect();
        // Sorted so that two pushes declaring the same names produce the same
        // list, and the certificate is rebuilt only when the names truly differ.
        served.sort();

        let affinity = declared.affinity();
        Upstreams {
            served,
            tls: self.tls.clone(),
            groups,
            affinity: Some(crate::affinity::Keys::new(
                affinity.key.0,
                affinity.previous_key.as_ref().map(|key| key.0),
                std::time::Duration::from_secs(affinity.ttl_seconds),
            )),
            next: AtomicUsize::new(0),
        }
    }

    /// What this table already knows about a member the next one declares.
    fn known(&self, label: &str, name: &str, addr: &str) -> Arc<Ready> {
        self.groups
            .get(label)
            .and_then(|group| group.by_name.get(name))
            .and_then(|members| members.iter().find(|m| m.addr == addr))
            .map(|m| m.ready.clone())
            .unwrap_or_default()
    }

    /// A member of the group a caller was given, at the address serving `name`.
    ///
    /// Readiness is a preference here and not a filter: the session this
    /// request belongs to lives in this group and nowhere else, so a group
    /// whose members all look unwell is still the only place it could go.
    pub fn at_group(&self, name: &str, label: &str) -> Result<Target<'_>, NoRoute> {
        let group = self.groups.get(label).ok_or(NoRoute::NoSuchGroup)?;
        let members = group.by_name.get(name).ok_or(NoRoute::NoSuchGroup)?;
        let member = self.pick(members).ok_or(NoRoute::NoSuchGroup)?;
        Ok(Target {
            group: self.label(label).ok_or(NoRoute::NoSuchGroup)?,
            addr: &member.addr,
            measurement: &group.measurement,
            part: group.part.clone(),
        })
    }

    /// Where a NEW session goes: a group running the build the caller named,
    /// and a member of it.
    ///
    /// Groups are taken in turn, so successive sessions naming one build spread
    /// across the groups that run it.
    pub fn place(&self, name: &str, measurement: &str) -> Result<Target<'_>, NoRoute> {
        let mut candidates: Vec<&String> = self
            .groups
            .iter()
            .filter(|(_, group)| group.measurement == measurement)
            .map(|(label, _)| label)
            .collect();
        if candidates.is_empty() {
            return Err(NoRoute::NoSuchGroup);
        }
        // A map's order is its own; sorting makes the turn mean the same thing
        // on every table built from the same push.
        candidates.sort();

        let turn = self.next.fetch_add(1, Ordering::Relaxed);
        for step in 0..candidates.len() {
            let label = candidates[(turn + step) % candidates.len()];
            if let Ok(target) = self.at_group(name, label) {
                return Ok(target);
            }
        }
        Err(NoRoute::NoSuchGroup)
    }

    /// One member, preferring those that are ready.
    fn pick<'a>(&self, members: &'a [Instance]) -> Option<&'a Instance> {
        if members.is_empty() {
            return None;
        }
        let turn = self.next.fetch_add(1, Ordering::Relaxed);
        let ready: Vec<&Instance> = members.iter().filter(|m| m.ready.get()).collect();
        // None ready is not none available: a member that was marked may have
        // recovered, and refusing every request until something proves it would
        // turn one bad answer into an outage. The nginx rule, and for the same
        // reason.
        if ready.is_empty() {
            Some(&members[turn % members.len()])
        } else {
            Some(ready[turn % ready.len()])
        }
    }

    /// The label as this table spells it, so a `Target` borrows from the table
    /// rather than from the caller's copy.
    fn label<'a>(&'a self, label: &str) -> Option<&'a str> {
        self.groups
            .get_key_value(label)
            .map(|(held, _)| held.as_str())
    }

    /// Every member, as the prober needs it: where it is, what it must prove,
    /// the part its group settled on, and what is currently believed of it.
    pub fn members(&self) -> Vec<Member> {
        self.groups
            .values()
            .flat_map(|group| {
                group.by_name.values().flatten().map(|member| Member {
                    addr: member.addr.clone(),
                    measurement: group.measurement.clone(),
                    part: group.part.clone(),
                    ready: member.ready.clone(),
                })
            })
            .collect()
    }

    /// What the member at `addr` is known by, so a failed request can mark it.
    pub fn mark(&self, addr: &str, ready: bool) {
        for group in self.groups.values() {
            for members in group.by_name.values() {
                for member in members {
                    if member.addr == addr {
                        member.ready.set(ready);
                    }
                }
            }
        }
    }

    /// The names this role answers to, as of this push.
    pub fn served(&self) -> &[String] {
        &self.served
    }

    pub fn affinity(&self) -> Option<&crate::affinity::Keys> {
        self.affinity.as_ref()
    }

    pub fn tls(&self) -> &Tls {
        &self.tls
    }

    /// How many groups the host has declared. For the one line that says a push
    /// was taken, and for tests.
    pub fn len(&self) -> usize {
        self.groups.len()
    }
}

/// What a finished connection to api is.
#[cfg(feature = "vsock")]
type Upstream = tokio_rustls::client::TlsStream<fleet_transport::Stream>;
#[cfg(not(feature = "vsock"))]
type Upstream = fleet_transport::Stream;

/// What securing a connection takes, or a placeholder where it takes nothing.
#[cfg(feature = "vsock")]
pub type Tls = tokio_rustls::TlsConnector;

/// A unit STRUCT rather than `()`, and `Clone` without `Copy`. The table holds
/// one of these and clones it into every table after; `()` makes every one of
/// those lines read as a mistake, and `Copy` makes the clone read as one. The
/// placeholder behaves like the thing it stands in for.
#[cfg(not(feature = "vsock"))]
#[derive(Clone)]
pub struct Tls;

/// Verifies api and presents nothing.
///
/// api asks no caller for a certificate, and could not, because the callers it
/// is open to hold none. So this end carries none either. The attestor is still
/// required and still does the work that matters: it is what VERIFIES api's quote
/// during the handshake.
///
/// `AcceptAny` is the policy, and it is not an absence. It runs the whole of
/// `verify_quote` — a genuine AMD part, VMPL 0, debug off, no migration agent,
/// platform TCB above this build's floor, and the quote bound to the very TLS
/// key in front of it. What it does not decide is WHICH image, because this role
/// holds no pin. That question is answered one line later, against what the
/// caller named.
#[cfg(feature = "vsock")]
fn tls_client() -> Tls {
    let attestor = crate::identity::attestor();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        enclavid_ra_tls::public_client_config(
            attestor,
            enclavid_ra_tls::MeasurementPolicy::AcceptAny,
        )
        .unwrap_or_else(|e| {
            safe_logger::debug!("{e}");
            safe_logger::error_and_panic!(
                "gateway: cannot build the RA-TLS client config for the api leg. Stopping.",
                safe_logger::reason!("a constant reporting a platform state the host provisioned")
            )
        }),
    ))
}

#[cfg(not(feature = "vsock"))]
fn tls_client() -> Tls {
    Tls
}

/// Open one connection to api and refuse it unless it is the declared build,
/// on the part the rest of its group is on.
///
/// The server name is RA-TLS's fixed placeholder and settles nothing: an RA-TLS
/// certificate carries no name, and who the peer is comes from the quote the
/// verifier checks during the handshake. Which is also why nothing here needs
/// the public name the caller used.
///
/// Both checks are here rather than at the routing table because this is where
/// they can be true. Routing picks by what the host DECLARED; the handshake is
/// what the peer PROVED, and the two must agree or the connection does not
/// exist. The part is stronger still: the host does not declare it at all, so
/// there is nothing to compare against except what the group's other members
/// proved — see [`Part`].
#[cfg(feature = "vsock")]
pub async fn connect(
    addr: &str,
    expected: &str,
    part: &Part,
    tls: &Tls,
) -> std::io::Result<Upstream> {
    let stream = fleet_transport::dial(addr).await?;
    let tls = tls.connect(enclavid_ra_tls::server_name(), stream).await?;

    let (proved, chip) = enclavid_ra_tls::peer_identity(tls.get_ref().1).ok_or_else(|| {
        std::io::Error::other("the peer completed an attested handshake carrying no measurement")
    })?;
    if proved != expected {
        // The values are both this build's own configuration and a digest of a
        // published image, so neither is a secret. They still do not go to an
        // outward tier: the host chooses how often this happens, and a line whose
        // rate a caller picks is a channel.
        safe_logger::debug!("upstream at {addr} proved {proved}, declared {expected}");
        return Err(std::io::Error::other(
            "the upstream is not the build it was declared to be",
        ));
    }
    if !part.agrees(&chip) {
        safe_logger::debug!("upstream at {addr} is on another part than its group");
        return Err(std::io::Error::other(
            "the upstream is not on the part its group is on",
        ));
    }
    Ok(tls)
}

/// A developer build proves nothing, so there is nothing to compare — but the
/// group still settles on a part, because every process on one box is on one
/// part and saying so keeps the shape the same on both builds.
#[cfg(not(feature = "vsock"))]
pub async fn connect(
    addr: &str,
    _expected: &str,
    part: &Part,
    _tls: &Tls,
) -> std::io::Result<Upstream> {
    if !part.agrees("this box") {
        return Err(std::io::Error::other(
            "the upstream is not on the part its group is on",
        ));
    }
    fleet_transport::dial(addr).await
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Two names, and nothing here distinguishes them: what a name means to
    /// whatever serves it is not this role's business, and a fixture that named
    /// them for it would teach the next reader otherwise.
    pub(crate) const FIRST: &str = "first.example.com";
    pub(crate) const SECOND: &str = "second.example.com";

    /// Two builds, spelled the way a real one is: what routing compares is the
    /// string, and a table refuses anything a quote could not carry.
    pub(crate) const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub(crate) const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A table as the host would have pushed one — through the same checks, so
    /// a fixture nothing could route is a failing test rather than a passing
    /// one.
    pub(crate) fn pushed(body: &str) -> crate::config::ValidatedConfig {
        crate::config::ValidatedConfig::parse(body.as_bytes())
            .expect("the fixture declares a routable table")
    }

    const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// One group on two machines and a second group on one, all under both
    /// names.
    fn table() -> Upstreams {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }},
                           "two": {{ "measurement": "{B}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1000", "127.0.0.1:2000"],
                                  "two": ["127.0.0.1:3000"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:1001", "127.0.0.1:2001"],
                                  "two": ["127.0.0.1:3001"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#
        );
        Upstreams::empty().replaced(&pushed(&body))
    }

    #[test]
    fn the_name_picks_the_address_and_the_label_picks_the_group() {
        let up = table();
        let first = up.at_group(FIRST, "one").ok().unwrap();
        assert!(first.addr.ends_with("000"), "{}", first.addr);
        assert_eq!(first.measurement, A);

        let second = up.at_group(SECOND, "one").ok().unwrap();
        assert!(second.addr.ends_with("001"), "{}", second.addr);
        assert_eq!(second.group, "one");
    }

    /// Every member of a group serves the sessions of that group, so requests
    /// spread over all of them.
    #[test]
    fn requests_go_round_the_members_of_a_group() {
        let up = table();
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..4 {
            seen.push(up.at_group(FIRST, "one").ok().unwrap().addr.to_owned());
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 2, "both members answered");
    }

    #[test]
    fn a_new_session_is_placed_on_a_group_running_that_build() {
        let up = table();
        let placed = up.place(SECOND, B).ok().unwrap();
        assert_eq!(placed.group, "two");
        assert_eq!(placed.addr, "127.0.0.1:3001");

        assert!(
            up.place(SECOND, &"c".repeat(96)).is_err(),
            "a build nobody runs is nowhere to place"
        );
    }

    #[test]
    fn a_label_nobody_carries_is_one_answer() {
        let up = table();
        assert!(up.at_group(FIRST, "three").is_err());
        assert!(up.at_group("elsewhere.example.com", "one").is_err());
    }

    #[test]
    fn an_empty_table_routes_nothing() {
        let up = Upstreams::empty();
        assert_eq!(up.len(), 0);
        assert!(up.at_group(FIRST, "one").is_err());
        assert!(up.place(SECOND, A).is_err());
    }

    /// A member marked unwell is skipped while another can take the work.
    #[test]
    fn an_unwell_member_is_passed_over() {
        let up = table();
        up.mark("127.0.0.1:1000", false);
        for _ in 0..4 {
            let got = up.at_group(FIRST, "one").ok().unwrap();
            assert_eq!(got.addr, "127.0.0.1:2000");
        }
    }

    /// And a group whose members all look unwell still answers, because the
    /// session it holds has nowhere else to be.
    #[test]
    fn a_group_with_nothing_well_is_still_where_its_sessions_are() {
        let up = table();
        up.mark("127.0.0.1:1000", false);
        up.mark("127.0.0.1:2000", false);
        assert!(up.at_group(FIRST, "one").is_ok());
    }

    /// What this role learned survives a push that still declares the member,
    /// and is not inherited by one it does not.
    #[test]
    fn a_verdict_survives_a_push_that_keeps_the_member() {
        let up = table();
        up.mark("127.0.0.1:1000", false);

        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1000", "127.0.0.1:9000"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:1001"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#
        );
        let next = up.replaced(&pushed(&body));

        let member = |addr: &str| {
            next.members()
                .into_iter()
                .find(|m| m.addr == addr)
                .unwrap_or_else(|| panic!("{addr} is declared"))
        };
        assert!(
            !member("127.0.0.1:1000").ready.get(),
            "the verdict came across"
        );
        assert!(
            member("127.0.0.1:9000").ready.get(),
            "a member it has not met starts ready"
        );
    }

    /// The host declares which instances form a group and never declares the
    /// part. So the first member to answer settles it, and one that proves
    /// another part is not in this group however it was declared — which is
    /// what stops two key domains being stapled under one label.
    #[test]
    fn a_group_is_one_part_and_the_first_answer_settles_it() {
        let part = Part::default();
        assert!(part.agrees("chip-a"), "the first answer settles it");
        assert!(part.agrees("chip-a"), "and agrees with itself after");
        assert!(!part.agrees("chip-b"), "another part is another group");
    }

    /// A later push may say something different, and a session could not have
    /// survived that push anyway — so the answer is per table, not for ever.
    #[test]
    fn a_push_settles_the_part_again() {
        let up = table();
        let settled = up.at_group(FIRST, "one").ok().unwrap().part;
        assert!(settled.agrees("chip-a"));

        let next = up.replaced(&pushed(&format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["127.0.0.1:1000"] }},
                "{SECOND}":  {{ "one": ["127.0.0.1:1001"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#
        )));
        let after = next.at_group(FIRST, "one").ok().unwrap().part;
        assert!(after.agrees("chip-b"), "a new table settles it anew");
    }

    #[test]
    fn a_group_the_next_push_omits_stops_routing() {
        let up = table();
        let body = format!(
            r#"{{
              "groups": {{ "two": {{ "measurement": "{B}" }} }},
              "names": {{
                "{FIRST}": {{ "two": ["127.0.0.1:3000"] }},
                "{SECOND}":  {{ "two": ["127.0.0.1:3001"] }} }},
              "affinity": {{ "key": "{KEY}", "ttl_seconds": 600 }} }}"#
        );
        let next = up.replaced(&pushed(&body));
        assert!(next.at_group(FIRST, "one").is_err());
        assert!(next.at_group(FIRST, "two").is_ok());
    }
}
