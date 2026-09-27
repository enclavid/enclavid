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
//! A label names the group. A link carries it, as does every request after the
//! one it was placed by, and inside it every member will do: a request whose
//! member's leg would not open goes to another, and a link outlives the machine
//! that responded to it first. A request that reached api is never sent again;
//! asking again after that is the caller's.
//!
//! What the host declares about grouping this role does not take on trust. Each
//! leg proves a chip and a measurement at the handshake, so a group whose
//! members are not one key domain in those two produces a leg that fails
//! rather than a route that is taken.
//!
//! Those two are what a leg CAN prove, and they are not all of api's key: the
//! guest policy it launched under goes into it as well, and a quote here says
//! nothing of that. So agreeing on part and build is necessary for two members
//! to serve each other's sessions, not sufficient. A host that launched one
//! build under two policies on one part gets a group whose sessions fail on
//! half its members — loudly, as sealed state that will not open, never as
//! state opened where it should not be.
//!
//! ## Two questions, two answers, and neither is a path
//!
//! **Which NAME** comes from the TLS handshake, and it decides which addresses
//! of a group are the right ones, because one api process listens on more than
//! one port. WHY it does is not known here and is not needed; a name maps to
//! addresses and that is the whole of it.
//!
//! Nor is it proved. A leg proves the build and the part behind an address,
//! not which of api's listeners answered there, since api presents one
//! identity on all of them. So the host chooses which of them a name reaches,
//! and that each listener refuses what is not its own is api's to hold.
//!
//! **Which GROUP** comes from the caller: a label it was given, or — having
//! none — a measurement it names, against which this role places it. This role
//! holds no pin of its own: the caller says which build it is willing to be
//! served by, having first verified this role's own attestation. That is a
//! delegation, and it is what lets api be upgraded without rebuilding this role.
//!
//! So neither is read from a path beyond the marker a link carries. The rest
//! of it is matched against the name's rules, which say whether a request may
//! name its group or must, never which group it goes to — see
//! `crate::route::Rules`.
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

pub mod balance;
pub mod member;

use std::collections::HashMap;
use std::sync::Arc;

use balance::Members;

/// A set of api instances that are one key domain, and so interchangeable.
struct Group {
    /// What every member must prove, shared with the sets below.
    proof: Arc<Proof>,
    /// Members by the name they serve, and the legs open to them. The sets need
    /// not be the same size: what has to match across names is the group, not
    /// the machine. See `crate::upstream::balance`.
    by_name: HashMap<String, Arc<Members>>,
}

/// What every member of one group must prove at the handshake, and what a leg
/// to it is opened with.
///
/// One per group, held by the group, by its set under each name and by every
/// member in them — so the build a leg must prove is written down once, and
/// [`connect`] is handed it whole.
pub struct Proof {
    /// The build every member is DECLARED to run. [`connect`] proves it.
    measurement: String,
    /// The group's label, which claims its key domain — see [`Proof::agrees`].
    label: String,
    /// The chip the group's members turned out to be on — see
    /// [`Proof::agrees`].
    chip: std::sync::OnceLock<String>,
    /// Which label holds each key domain, across the whole table.
    domains: Arc<Domains>,
    /// Set when a push did not carry this proof into its table. A leg of the
    /// replaced table still mid-handshake then claims nothing: its claim would
    /// outlive the prune that push made, holding a domain for a label no table
    /// declares any more.
    retired: std::sync::atomic::AtomicBool,
    /// What verifies the member's quote. Read only where legs are RA-TLS: a
    /// developer build's placeholder has nothing in it to read.
    #[cfg_attr(not(feature = "vsock"), allow(dead_code))]
    tls: Tls,
}

/// Which label holds each key domain — a build on a part — across the whole
/// table, and across pushes.
///
/// One label per domain. The instances of one build on one part can serve each
/// other's sessions, so they are one group whatever the host calls them; a
/// second label on them would be a name no other session shares, and a session
/// placed there would carry it like a tag on every request after. So the first
/// label to prove a domain holds it, and a leg that would prove it for another
/// is refused.
#[derive(Default)]
pub struct Domains(std::sync::Mutex<HashMap<(String, String), String>>);

impl Proof {
    /// What a member of the group `label`, declared to run `measurement`, must
    /// prove — with the chip still to be settled against `domains`.
    pub fn new(measurement: &str, label: &str, tls: Tls, domains: Arc<Domains>) -> Proof {
        Proof {
            measurement: measurement.to_owned(),
            label: label.to_owned(),
            chip: std::sync::OnceLock::new(),
            domains,
            retired: std::sync::atomic::AtomicBool::new(false),
            tls,
        }
    }

    /// Settle the chip, or refuse a member that is not on it — or whose key
    /// domain another label already holds.
    ///
    /// A group is a set of instances that can serve each other's sessions, and
    /// what makes that true is a key api derives from the PART and the
    /// measurement. The measurement the host declares and this role proves; the
    /// part it does not declare at all — so the first member to answer settles
    /// it, and every member after has to agree.
    ///
    /// A host that staples two key domains into one label therefore gets a leg
    /// that fails rather than a session that lands where its state cannot be
    /// opened; and one that splits one domain across two labels gets the same
    /// for the second — see [`Domains`]. Both answers hold for as long as the
    /// label is declared with that build, across pushes, and are asked again
    /// only once it is removed, renamed or rolled to another build — a session
    /// could not have survived that anyway.
    pub fn agrees(&self, chip: &str) -> bool {
        if let Some(settled) = self.chip.get() {
            return settled == chip;
        }
        let domain = (self.measurement.clone(), chip.to_owned());
        let mut held = self.domains.0.lock().expect("never held on panic");
        if self.retired.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        let claimed = !held.contains_key(&domain);
        if held
            .entry(domain.clone())
            .or_insert_with(|| self.label.clone())
            != &self.label
        {
            return false;
        }
        // Two members of one group answering at once, from two parts: one
        // settles the chip, and the other's claim is given back.
        if self.chip.get_or_init(|| chip.to_owned()) != chip {
            if claimed {
                held.remove(&domain);
            }
            return false;
        }
        true
    }
}

impl Domains {
    /// Let go of every domain whose label the table no longer declares with
    /// that build — a label removed, renamed, or rolled to another build.
    fn keep_declared(&self, declared: &crate::config::ValidatedConfig) {
        self.0
            .lock()
            .expect("never held on panic")
            .retain(|(measurement, _), label| {
                declared
                    .groups()
                    .get(label)
                    .is_some_and(|group| group.measurement == *measurement)
            });
    }
}

/// Everywhere this role may forward to, as of one push.
pub struct Upstreams {
    /// The names this role answers to, as the push declared them. A certificate
    /// is minted over exactly these — see `crate::listener::certificate`.
    served: Vec<String>,
    /// Built once, at boot, and carried into every table after. It holds the
    /// attestor and the verifier, neither of which changes with the fleet.
    tls: Tls,
    groups: HashMap<String, Group>,
    /// What each name's requests are held to, as of this push — see
    /// `crate::route::Rules`.
    rules: HashMap<String, crate::route::Rules>,
    /// Every timeout, limit and retry count, as of this push. `None` only
    /// before the first one — and the public listener does not open until
    /// there is one, so nothing that serves a caller reads it empty.
    tuning: Option<crate::config::Tuning>,
    /// Which label holds each key domain. Carried into every table after, and
    /// pruned to what each push declares.
    domains: Arc<Domains>,
    /// Where an ACME validator's TLS-ALPN-01 connection is carried, as of this
    /// push — see `crate::listener::acme`.
    tls_alpn_01: Option<Arc<str>>,
}

/// Where one request goes: a group, the build that must be proved there, and
/// the set of members serving the name it arrived on.
///
/// No member is named here. Routing answers WHICH GROUP, and which member of it
/// takes the request is settled later, when the request is handed over — by
/// whichever two of them can take work at that instant. Choosing earlier would
/// mean choosing before knowing who is busy.
pub struct Target<'a> {
    pub group: &'a str,
    pub measurement: &'a str,
    pub members: Arc<Members>,
}

/// Why a request could not be forwarded.
///
/// Three variants, and two answers to the caller: the first two say the
/// request is missing what only the caller can supply, or carries what a rule
/// forbids; the last says what was asked for is not here. What the caller is
/// told for each is `crate::route`'s to decide.
pub enum NoRoute {
    /// No measurement was named where one is required.
    Unspecified,
    /// The request names its group where a rule says this role places it, or
    /// names none where a rule says it must — see `crate::route::Rules`.
    AgainstRule,
    /// A build was named and no group declares it; or a label was named and no
    /// group carries it; or the name this connection settled is not served. One
    /// answer for all three: which groups exist and what they run is the host's
    /// business and changes under it. One in what it says, and given at once —
    /// sooner than a declared group whose members are down answers; see
    /// `crate::route` for why that is not padded.
    NoSuchGroup,
}

impl Upstreams {
    /// No api and no names: what this role holds until the host's first push.
    ///
    /// Nothing is served in this state — there is no certificate to present,
    /// because a certificate is over names and the names have not arrived.
    ///
    /// `attestor` is the one this process proves itself with, handed in rather
    /// than built again: building one asks the Secure Processor for a report.
    /// It verifies api on every leg, and every table after this one carries it.
    pub fn empty(attestor: Arc<dyn enclavid_attestation::Attestor>) -> Upstreams {
        Upstreams {
            served: Vec::new(),
            tls: tls_client(attestor),
            groups: HashMap::new(),
            rules: HashMap::new(),
            tuning: None,
            domains: Arc::new(Domains::default()),
            tls_alpn_01: None,
        }
    }

    /// The table a push declares.
    ///
    /// A new table, but not a new fleet. Every set of members a push declares
    /// again is CARRIED ACROSS — the legs open to it stay open and a member that
    /// is out stays out, and only the difference in membership is told to it. A
    /// push is a rare, deliberate act; the traffic across it is not, and nothing
    /// here interrupts it.
    ///
    /// What is NOT carried is a set whose group's declared BUILD changed. Its
    /// legs proved the old build, so they must not serve a request that named
    /// the new one; the set is built afresh and the old one is dropped whole,
    /// which closes them. See `crate::upstream::balance`.
    ///
    /// Nor a set whose numbers changed — the `upstream` part of the tuning.
    /// Each member is built with them, so a set keeping its members would keep
    /// the old ones; built afresh, its legs reopen and its cooldowns start
    /// over. The proof is still carried, because the build and the part it
    /// settles have not moved.
    ///
    /// Not async. Carried sets are told their new membership while this runs,
    /// so a suspension point here would be a place a timeout could stop it with
    /// some sets told and the table never published.
    ///
    /// Read THROUGH the wrapper rather than out of it: what a push decoded into
    /// cannot be named outside `crate::config`, so this is where the checked
    /// form turns into the routing one and nowhere else could be.
    pub fn replaced(&self, declared: &crate::config::ValidatedConfig) -> Upstreams {
        let tuning = *declared.tuning();
        let same_numbers = self
            .tuning
            .is_some_and(|held| held.upstream == tuning.upstream);
        let mut groups: HashMap<String, Group> = HashMap::new();
        for (label, group) in declared.groups() {
            // Carried only while the build is the same — see above. The proof
            // comes with it, chip and all, because the members proving it are
            // the same members on the same chip; a set built afresh settles the
            // chip again.
            let carried = self
                .groups
                .get(label)
                .filter(|held| held.proof.measurement == group.measurement);
            let proof = carried.map_or_else(
                || {
                    Arc::new(Proof::new(
                        &group.measurement,
                        label,
                        self.tls.clone(),
                        self.domains.clone(),
                    ))
                },
                |held| held.proof.clone(),
            );
            let mut by_name: HashMap<String, Arc<Members>> = HashMap::new();
            for (name, table) in declared.names() {
                let Some(addrs) = table.get(label) else {
                    continue;
                };
                let members = carried
                    .filter(|_| same_numbers)
                    .and_then(|held| held.by_name.get(name))
                    .cloned()
                    .unwrap_or_else(|| Arc::new(Members::new(proof.clone(), tuning.upstream)));
                members.declare(&addrs.iter().cloned().collect());
                by_name.insert(name.clone(), members);
            }
            groups.insert(label.clone(), Group { proof, by_name });
        }
        // Retired before the prune, so a leg of this table finishing its
        // handshake after the prune finds its proof retired and claims nothing.
        for (label, held) in &self.groups {
            let carried = groups
                .get(label)
                .is_some_and(|group| Arc::ptr_eq(&group.proof, &held.proof));
            if !carried {
                held.proof
                    .retired
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        self.domains.keep_declared(declared);

        let mut served: Vec<String> = declared.names().keys().cloned().collect();
        // Sorted so that two pushes declaring the same names produce the same
        // list, and the certificate is rebuilt only when the names truly differ.
        served.sort();

        Upstreams {
            served,
            tls: self.tls.clone(),
            groups,
            rules: declared.rules().clone(),
            tuning: Some(tuning),
            domains: self.domains.clone(),
            tls_alpn_01: declared.acme().tls_alpn_01.as_deref().map(Arc::from),
        }
    }

    /// The members of the group a caller was given that serve `name`.
    pub fn at_group(&self, name: &str, label: &str) -> Result<Target<'_>, NoRoute> {
        let group = self.groups.get(label).ok_or(NoRoute::NoSuchGroup)?;
        let members = group.by_name.get(name).ok_or(NoRoute::NoSuchGroup)?;
        Ok(Target {
            group: self.label(label).ok_or(NoRoute::NoSuchGroup)?,
            measurement: &group.proof.measurement,
            members: members.clone(),
        })
    }

    /// Where a NEW session goes: a group running the build the caller named.
    ///
    /// Chosen at random among the groups that run it, which spreads sessions as
    /// well as a turn would and gives the host nothing to aim with. A turn is
    /// predictable — it restarts with every push — so a host that pushed a
    /// label sorting first could have the next new session placed on it for
    /// certain, and follow that session by it; chance gives it no such hold.
    pub fn place(&self, name: &str, measurement: &str) -> Result<Target<'_>, NoRoute> {
        let candidates: Vec<&String> = self
            .groups
            .iter()
            .filter(|(_, group)| group.proof.measurement == measurement)
            .map(|(label, _)| label)
            .collect();
        if candidates.is_empty() {
            return Err(NoRoute::NoSuchGroup);
        }

        let turn = random_below(candidates.len());
        for step in 0..candidates.len() {
            let label = candidates[(turn + step) % candidates.len()];
            if let Ok(target) = self.at_group(name, label) {
                return Ok(target);
            }
        }
        Err(NoRoute::NoSuchGroup)
    }

    /// What each key domain is held by, for the tests.
    #[cfg(test)]
    pub fn domains(&self) -> &Arc<Domains> {
        &self.domains
    }

    /// The label as this table spells it, so a `Target` borrows from the table
    /// rather than from the caller's copy.
    fn label<'a>(&'a self, label: &str) -> Option<&'a str> {
        self.groups
            .get_key_value(label)
            .map(|(held, _)| held.as_str())
    }

    /// The names this role answers to, as of this push.
    pub fn served(&self) -> &[String] {
        &self.served
    }

    /// What requests under `name` are held to, if the push said anything.
    pub fn rules(&self, name: &str) -> Option<&crate::route::Rules> {
        self.rules.get(name)
    }

    /// Every timeout, limit and retry count, as of this push.
    pub fn tuning(&self) -> Option<&crate::config::Tuning> {
        self.tuning.as_ref()
    }

    /// Where an ACME validator's TLS-ALPN-01 connection is carried, if anywhere.
    pub fn tls_alpn_01(&self) -> Option<&Arc<str>> {
        self.tls_alpn_01.as_ref()
    }

    /// How many groups the host has declared. For the one line that says a push
    /// was taken, and for tests.
    pub fn len(&self) -> usize {
        self.groups.len()
    }
}

/// A number below `n`, from the same random source the TLS draws on.
fn random_below(n: usize) -> usize {
    let mut drawn = [0u8; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut drawn)
        .expect("a guest that terminates TLS has a random source");
    (u64::from_le_bytes(drawn) % n as u64) as usize
}

/// What a finished connection to api is.
#[cfg(feature = "vsock")]
pub type Upstream = tokio_rustls::client::TlsStream<fleet_transport::Stream>;
#[cfg(not(feature = "vsock"))]
pub type Upstream = fleet_transport::Stream;

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
fn tls_client(attestor: Arc<dyn enclavid_attestation::Attestor>) -> Tls {
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

/// A developer build's leg is plain TCP and verifies nothing, so the attestor
/// has nothing to do here.
#[cfg(not(feature = "vsock"))]
fn tls_client(_attestor: Arc<dyn enclavid_attestation::Attestor>) -> Tls {
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
/// proved — see [`Proof::agrees`].
#[cfg(feature = "vsock")]
pub async fn connect(addr: &str, proof: &Proof) -> std::io::Result<Upstream> {
    let stream = fleet_transport::dial(addr).await?;
    let tls = proof
        .tls
        .connect(enclavid_ra_tls::server_name(), stream)
        .await?;
    prove(addr, tls.get_ref().1, proof)?;
    Ok(tls)
}

/// Whether the peer of a finished attested handshake is the declared build, on
/// the part its group is on — all [`connect`] checks once the handshake is done.
///
/// Apart from the dial, so that it is tested in every build: over a pipe, on
/// the software backend, which needs no hardware — see the tests.
#[cfg(any(feature = "vsock", test))]
fn prove(
    addr: &str,
    conn: &tokio_rustls::rustls::CommonState,
    proof: &Proof,
) -> std::io::Result<()> {
    let expected = &proof.measurement;
    let (proved, chip) = enclavid_ra_tls::peer_identity(conn).ok_or_else(|| {
        std::io::Error::other("the peer completed an attested handshake carrying no measurement")
    })?;
    if &proved != expected {
        // The values are both this build's own configuration and a digest of a
        // published image, so neither is a secret. They still do not go to an
        // outward tier: the host chooses how often this happens, and a line whose
        // rate a caller picks is a channel.
        safe_logger::debug!("upstream at {addr} proved {proved}, declared {expected}");
        return Err(std::io::Error::other(
            "the upstream is not the build it was declared to be",
        ));
    }
    if !proof.agrees(&chip) {
        safe_logger::debug!("upstream at {addr} is on another part than its group");
        return Err(std::io::Error::other(
            "the upstream is not on the part its group is on",
        ));
    }
    Ok(())
}

/// A developer build proves nothing, so there is nothing to compare — but the
/// group still settles on a part, because every process on one box is on one
/// part and saying so keeps the shape the same on both builds.
#[cfg(not(feature = "vsock"))]
pub async fn connect(addr: &str, proof: &Proof) -> std::io::Result<Upstream> {
    if !proof.agrees("this box") {
        return Err(std::io::Error::other(
            "the upstream is not on the part its group is on",
        ));
    }
    fleet_transport::dial(addr).await
}

/// Routing and the table alone — nothing here opens a leg — so in every build,
/// each declaring member addresses the way its own transport dials them.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::config::testing::TUNING;

    /// A member's address as this build dials one; the port is all a fixture
    /// chooses.
    pub(crate) fn at(port: u32) -> String {
        #[cfg(not(feature = "vsock"))]
        return format!("127.0.0.1:{port}");
        #[cfg(feature = "vsock")]
        return format!("vsock://2:{port}");
    }

    /// Members at `ports`, as a push lists them.
    fn listed(ports: &[u32]) -> String {
        ports
            .iter()
            .map(|port| format!("\"{}\"", at(*port)))
            .collect::<Vec<_>>()
            .join(", ")
    }

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

    /// One group on two machines and a second group on one, all under both
    /// names.
    fn body() -> String {
        format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }},
                           "two": {{ "measurement": "{B}" }} }},
              "names": {{
                "{FIRST}": {{ "one": [{}], "two": [{}] }},
                "{SECOND}":  {{ "one": [{}], "two": [{}] }} }},
              {TUNING} }}"#,
            listed(&[1000, 2000]),
            listed(&[3000]),
            listed(&[1001, 2001]),
            listed(&[3001]),
        )
    }

    async fn table() -> Upstreams {
        Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&body()))
    }

    /// The members at `ports` as a set, which is how a set of members is
    /// compared.
    fn set(ports: &[u32]) -> std::collections::BTreeSet<String> {
        ports.iter().map(|port| at(*port)).collect()
    }

    /// Two questions, two answers: the label picks the GROUP, and the name
    /// picks which of that group's addresses serve it.
    ///
    /// Every member named here serves the sessions of that group — which of
    /// them takes a given request is settled later, by whichever can take work
    /// at that instant. See `crate::upstream::balance`.
    #[tokio::test]
    async fn the_name_picks_the_addresses_and_the_label_picks_the_group() {
        let up = table().await;
        let first = up.at_group(FIRST, "one").ok().unwrap();
        assert_eq!(first.members.addresses(), set(&[1000, 2000]));
        assert_eq!(first.measurement, A);

        let second = up.at_group(SECOND, "one").ok().unwrap();
        assert_eq!(second.members.addresses(), set(&[1001, 2001]));
        assert_eq!(second.group, "one");
    }

    #[tokio::test]
    async fn a_new_session_is_placed_on_a_group_running_that_build() {
        let up = table().await;
        let placed = up.place(SECOND, B).ok().unwrap();
        assert_eq!(placed.group, "two");
        assert_eq!(placed.members.addresses(), set(&[3001]));

        assert!(
            up.place(SECOND, &"c".repeat(96)).is_err(),
            "a build nobody runs is nowhere to place"
        );
    }

    /// Two groups can run one build — that is how a build is rolled out or how
    /// a fleet spans two parts. New sessions naming it must spread over both,
    /// or one group takes every session and the other stands idle.
    #[tokio::test]
    async fn new_sessions_spread_over_every_group_running_the_build() {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }},
                           "two": {{ "measurement": "{A}" }} }},
              "names": {{
                "{FIRST}":  {{ "one": [{}], "two": [{}] }},
                "{SECOND}": {{ "one": [{}], "two": [{}] }} }},
              {TUNING} }}"#,
            listed(&[1000]),
            listed(&[2000]),
            listed(&[1001]),
            listed(&[2001]),
        );
        let up = Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&body));

        // At random, so enough placements that missing a group is a chance of
        // one in 2^63.
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..64 {
            seen.push(up.place(SECOND, A).ok().unwrap().group.to_owned());
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 2, "every group running the build was placed on");

        // And not by a turn that restarts with each push: the FIRST placement on
        // each fresh table lands on either group, so a host cannot push a label
        // that sorts first and have the next new session placed on it.
        let mut first: Vec<String> = Vec::new();
        for _ in 0..64 {
            let fresh = Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&body));
            first.push(fresh.place(SECOND, A).ok().unwrap().group.to_owned());
        }
        first.sort();
        first.dedup();
        assert_eq!(first.len(), 2, "the first placement after a push is chance");
    }

    #[tokio::test]
    async fn a_label_nobody_carries_is_one_answer() {
        let up = table().await;
        assert!(up.at_group(FIRST, "three").is_err());
        assert!(up.at_group("elsewhere.example.com", "one").is_err());
    }

    #[tokio::test]
    async fn an_empty_table_routes_nothing() {
        let up = Upstreams::empty(crate::identity::attestor());
        assert_eq!(up.len(), 0);
        assert!(up.at_group(FIRST, "one").is_err());
        assert!(up.place(SECOND, A).is_err());
    }

    /// A push declaring one group under one name, running `build`, with members
    /// at `ports`.
    fn group_running(build: &str, ports: &[u32]) -> String {
        format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{build}" }} }},
              "names": {{ "{FIRST}": {{ "one": [{}] }} }},
              {TUNING} }}"#,
            listed(ports)
        )
    }

    fn group_of(ports: &[u32]) -> String {
        group_running(A, ports)
    }

    /// A set of members survives a push, and is told only what changed.
    ///
    /// This is what keeps the legs open to api open across a push, and a member
    /// that is out, out. The alternative — rebuilding the set — drops every
    /// connection and spends requests learning again which members respond.
    #[tokio::test]
    async fn a_set_is_carried_across_a_push_and_told_the_difference() {
        let up =
            Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&group_of(&[1000])));
        let before = up.at_group(FIRST, "one").ok().unwrap().members;

        let next = up.replaced(&pushed(&group_of(&[1000, 2000])));
        let after = next.at_group(FIRST, "one").ok().unwrap().members;

        assert!(Arc::ptr_eq(&before, &after), "the same set, not a new one");
        assert_eq!(
            after.addresses(),
            set(&[1000, 2000]),
            "and it was told who arrived"
        );
    }

    /// But a set is NOT carried across a change of build, at the same
    /// addresses or any other.
    ///
    /// The legs parked in it proved the old build. Carrying the set would let
    /// one of them serve a request that named the new one — which is the single
    /// thing this role exists to make impossible. The old set is dropped whole,
    /// and dropping it closes them.
    #[tokio::test]
    async fn a_new_build_at_the_same_addresses_is_a_new_set() {
        let up = Upstreams::empty(crate::identity::attestor())
            .replaced(&pushed(&group_running(A, &[1000])));
        let before = up.at_group(FIRST, "one").ok().unwrap().members;

        let rolled = up.replaced(&pushed(&group_running(B, &[1000])));
        let after = rolled.at_group(FIRST, "one").ok().unwrap().members;

        assert!(
            !Arc::ptr_eq(&before, &after),
            "no leg proving the old build survives into the new one"
        );
        assert_eq!(after.proof().measurement, B);
    }

    /// A member a push stops declaring stops being in the set, which drops it
    /// and with it every leg open to it.
    #[tokio::test]
    async fn a_member_a_push_omits_leaves_the_set() {
        let up = Upstreams::empty(crate::identity::attestor())
            .replaced(&pushed(&group_of(&[1000, 2000])));
        let next = up.replaced(&pushed(&group_of(&[2000])));
        assert_eq!(
            next.at_group(FIRST, "one")
                .ok()
                .unwrap()
                .members
                .addresses(),
            set(&[2000])
        );
    }

    /// The host declares which instances form a group and never declares the
    /// part. So the first member to answer settles it, and one that proves
    /// another part is not in this group however it was declared — which is
    /// what stops two key domains being stapled under one label.
    #[tokio::test]
    async fn a_group_is_one_part_and_the_first_answer_settles_it() {
        let proof = Proof::new(
            A,
            "one",
            tls_client(crate::identity::attestor()),
            Arc::default(),
        );
        assert!(proof.agrees("chip-a"), "the first answer settles it");
        assert!(proof.agrees("chip-a"), "and agrees with itself after");
        assert!(!proof.agrees("chip-b"), "another part is another group");
    }

    /// And one key domain is one group: a second label on the same build on
    /// the same part is refused, however the host declared it — a label no
    /// other session shares would be a tag on the session placed there. The
    /// refusal settles nothing, so that label may still prove another part.
    #[tokio::test]
    async fn a_key_domain_is_one_labels() {
        let domains = Arc::new(Domains::default());
        let tls = tls_client(crate::identity::attestor());
        let one = Proof::new(A, "one", tls.clone(), domains.clone());
        let tag = Proof::new(A, "tag", tls.clone(), domains.clone());

        assert!(one.agrees("chip-a"));
        assert!(
            !tag.agrees("chip-a"),
            "the domain is held by the first label"
        );
        assert!(tag.agrees("chip-b"), "another part is another domain");

        // Another build on the same part is another domain as well.
        let rolled = Proof::new(B, "tag-b", tls, domains);
        assert!(rolled.agrees("chip-a"));
    }

    /// A domain is let go when its label is: removed, renamed, or rolled to
    /// another build — so the host can rename a group without stranding it.
    #[tokio::test]
    async fn a_domain_is_let_go_with_its_label() {
        let up = Upstreams::empty(crate::identity::attestor())
            .replaced(&pushed(&group_running(A, &[1000])));
        let held = up.at_group(FIRST, "one").ok().unwrap().members;
        assert!(held.proof().agrees("chip-a"));

        let renamed = group_running(A, &[1000]).replace("\"one\"", "\"uno\"");
        let next = up.replaced(&pushed(&renamed));
        let uno = next.at_group(FIRST, "uno").ok().unwrap().members;
        assert!(
            uno.proof().agrees("chip-a"),
            "the old label's claim went with it"
        );
        assert_eq!(next.domains().0.lock().unwrap().len(), 1);
    }

    /// But a domain stays held while its label is declared with its build:
    /// pushed again beside a new label on the same build, the new label still
    /// cannot take it. Pruning too much would let it.
    #[tokio::test]
    async fn a_domain_stays_held_while_its_label_is_declared() {
        let up = Upstreams::empty(crate::identity::attestor())
            .replaced(&pushed(&group_running(A, &[1000])));
        let held = up.at_group(FIRST, "one").ok().unwrap().members;
        assert!(held.proof().agrees("chip-a"));

        let with_tag = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }}, "tag": {{ "measurement": "{A}" }} }},
              "names": {{ "{FIRST}": {{ "one": [{}], "tag": [{}] }} }},
              {TUNING} }}"#,
            listed(&[1000]),
            listed(&[2000]),
        );
        let next = up.replaced(&pushed(&with_tag));
        let tag = next.at_group(FIRST, "tag").ok().unwrap().members;
        assert!(!tag.proof().agrees("chip-a"), "the domain is still one's");
    }

    /// A leg of a replaced table still mid-handshake when a push renamed its
    /// group claims nothing once it finishes — or its claim would outlive the
    /// prune, and the renamed group could never prove its own domain.
    #[tokio::test]
    async fn a_proof_a_push_did_not_carry_claims_nothing() {
        let up = Upstreams::empty(crate::identity::attestor())
            .replaced(&pushed(&group_running(A, &[1000])));
        let mid_handshake = up.at_group(FIRST, "one").ok().unwrap().members;

        let renamed = group_running(A, &[1000]).replace("\"one\"", "\"uno\"");
        let next = up.replaced(&pushed(&renamed));

        assert!(
            !mid_handshake.proof().agrees("chip-a"),
            "retired by the push"
        );
        let uno = next.at_group(FIRST, "uno").ok().unwrap().members;
        assert!(uno.proof().agrees("chip-a"), "free for the renamed group");
    }

    /// The proof travels with the set, chip and all, and the chip is settled
    /// again only when the set is built afresh.
    ///
    /// A group the host declares again is the same group on the same chip, so
    /// re-asking would let a host re-staple two key domains under one label by
    /// pushing. A group whose BUILD changed is a new set, and settles it again
    /// along with everything else about it.
    #[tokio::test]
    async fn the_proof_travels_with_the_set() {
        let up = Upstreams::empty(crate::identity::attestor())
            .replaced(&pushed(&group_running(A, &[1000])));
        let settled = up
            .at_group(FIRST, "one")
            .ok()
            .unwrap()
            .members
            .proof()
            .clone();

        let again = up.replaced(&pushed(&group_running(A, &[1000])));
        let kept = again
            .at_group(FIRST, "one")
            .ok()
            .unwrap()
            .members
            .proof()
            .clone();
        assert!(
            Arc::ptr_eq(&settled, &kept),
            "the same group keeps the answer, so it cannot be re-stapled by a push"
        );

        let rolled = again.replaced(&pushed(&group_running(B, &[1000])));
        let asked = rolled
            .at_group(FIRST, "one")
            .ok()
            .unwrap()
            .members
            .proof()
            .clone();
        assert!(
            !Arc::ptr_eq(&settled, &asked),
            "a new set asks the question again"
        );
    }

    /// A push that changes the upstream numbers builds every set afresh, since
    /// each member was built with the old ones — but carries the proof, since
    /// neither the build nor the part it settled has moved.
    #[tokio::test]
    async fn new_numbers_are_a_new_set_on_the_same_proof() {
        let up =
            Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&group_of(&[1000])));
        let before = up.at_group(FIRST, "one").ok().unwrap().members;

        let retuned = group_of(&[1000]).replace(r#""tries": 3"#, r#""tries": 2"#);
        let next = up.replaced(&pushed(&retuned));
        let after = next.at_group(FIRST, "one").ok().unwrap().members;

        assert!(
            !Arc::ptr_eq(&before, &after),
            "a new set, with the new numbers"
        );
        assert!(
            Arc::ptr_eq(before.proof(), after.proof()),
            "on the proof the old one settled"
        );

        // And the listener's numbers are not the set's: changing only them
        // carries the set as it is.
        let listener_only =
            retuned.replace(r#""idle_timeout_ms": 1000"#, r#""idle_timeout_ms": 2000"#);
        let again = next.replaced(&pushed(&listener_only));
        assert!(Arc::ptr_eq(
            &after,
            &again.at_group(FIRST, "one").ok().unwrap().members
        ));
    }

    #[tokio::test]
    async fn a_group_the_next_push_omits_stops_routing() {
        let up = table().await;
        let body = format!(
            r#"{{
              "groups": {{ "two": {{ "measurement": "{B}" }} }},
              "names": {{
                "{FIRST}": {{ "two": [{}] }},
                "{SECOND}":  {{ "two": [{}] }} }},
              {TUNING} }}"#,
            listed(&[3000]),
            listed(&[3001]),
        );
        let next = up.replaced(&pushed(&body));
        assert!(next.at_group(FIRST, "one").is_err());
        assert!(next.at_group(FIRST, "two").is_ok());
    }
}

/// What a leg checks once its attested handshake is done, over a pipe and on
/// the software backend — the check itself, with no hardware and no dial, in
/// either transport's build. The software backend proves an empty part, so the
/// part's two cases settle the group first and let the handshake disagree.
#[cfg(all(test, feature = "dev-attestation"))]
mod proving {
    use super::*;

    use enclavid_attestation::{Attestor, MockAttestor};

    /// Two builds, spelled as a real one is.
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A handshake with a server whose evidence says it runs `served`,
    /// checked by the verifier this role uses — which on this backend
    /// shares the server's key and nothing else — then handed to `prove`.
    async fn proved(served: &str, proof: &Proof) -> std::io::Result<()> {
        let attestor: Arc<dyn Attestor> = Arc::new(MockAttestor::from_seed([7; 32], served));
        let accepting = tokio_rustls::TlsAcceptor::from(Arc::new(
            enclavid_ra_tls::public_server_config(attestor.clone()).unwrap(),
        ));
        let connecting = tokio_rustls::TlsConnector::from(Arc::new(
            enclavid_ra_tls::public_client_config(
                attestor,
                enclavid_ra_tls::MeasurementPolicy::AcceptAny,
            )
            .unwrap(),
        ));
        let (ours, theirs) = tokio::io::duplex(64 << 10);
        let serving = tokio::spawn(async move { accepting.accept(theirs).await.map(drop) });
        let tls = connecting
            .connect(enclavid_ra_tls::server_name(), ours)
            .await
            .expect("the software backend attests itself");
        let proven = prove("a pipe", tls.get_ref().1, proof);
        drop(tls);
        let _ = serving.await;
        proven
    }

    /// The proof one group's legs are opened with, for the build `A`.
    fn declared(label: &str, domains: &Arc<Domains>) -> Proof {
        Proof::new(
            A,
            label,
            tls_client(Arc::new(MockAttestor::dev_fleet())),
            domains.clone(),
        )
    }

    /// The declared build, on the group's part, is taken — and settles
    /// the part, so a member on another is refused after it.
    #[tokio::test]
    async fn the_declared_build_is_taken_and_settles_the_part() {
        let proof = declared("one", &Arc::default());
        proved(A, &proof).await.expect("the declared build");
        assert!(!proof.agrees("another part"));
    }

    /// A peer proving another build than the one declared is refused,
    /// though its evidence is perfectly good.
    #[tokio::test]
    async fn another_build_is_refused() {
        let proof = declared("one", &Arc::default());
        assert!(proved(B, &proof).await.is_err());
    }

    /// The declared build on another part than the group's is refused:
    /// its sealed state is not this group's to open.
    #[tokio::test]
    async fn the_declared_build_on_another_part_is_refused() {
        let proof = declared("one", &Arc::default());
        assert!(proof.agrees("another part"));
        assert!(proved(A, &proof).await.is_err());
    }

    /// The declared build on a part whose key domain another label holds
    /// is refused: one domain is one group.
    #[tokio::test]
    async fn a_domain_another_label_holds_is_refused() {
        let domains = Arc::default();
        let other = declared("two", &domains);
        assert!(other.agrees(""), "the other label holds the domain");
        let proof = declared("one", &domains);
        assert!(proved(A, &proof).await.is_err());
    }
}
