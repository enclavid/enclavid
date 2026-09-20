//! Which api a request goes to, and how the connection to it is made.
//!
//! ## Two questions, two answers, and neither is a path
//!
//! **Which SURFACE** comes from the name the TLS handshake settled. api serves
//! two audiences on two ports, and both route tables live under the same
//! `/api/v1/sessions/...` prefix — deliberately, so the surface reads the same
//! to a consumer and to an applicant. They are separated by a route table, not
//! by a prefix, so a gateway routing by path would need a copy of that table in
//! a second measured role, where drift is silent and sends one audience's
//! request to the other audience's port.
//!
//! **Which INSTANCE** comes from a measurement the caller names. The gateway
//! holds no pin: it is the consumer that says which api build it is willing to
//! be served by, having first verified this role's own attestation. That is a
//! delegation — the consumer checks one party directly and lets it check the
//! next — and it is what lets api be upgraded without rebuilding this role, and
//! a consumer stay on a build it audited while others move on.
//!
//! So this role never parses a path at all, and the session id in one stays out
//! of its reach: the bytes pass through and nothing here derives anything from
//! them.
//!
//! ## The host says where, and never what
//!
//! Upstreams arrive from the host, each declaring an address and a measurement.
//! The address is an untrusted input rather than an assertion — it says where
//! this role MAY go, never what it will accept — and the declared measurement is
//! a routing hint that [`connect`] PROVES at the handshake before a byte of HTTP
//! crosses. A substituted address fails there; a lie about which build sits at
//! it fails there too.
//!
//! That is the division the design wants: the host keeps every lever it needs to
//! manage a fleet, and gains none over what a consumer ends up talking to.
//!
//! Each push produces a whole new [`Upstreams`], and a request routes against
//! whichever table was current when it arrived, so no request sees half of one
//! push and half of the next.
//!
//! ## A connection to api belongs to one public connection
//!
//! [`Legs`] is created per public connection and dropped with it, and every
//! connection to api is opened through one. Nothing is pooled across callers,
//! not even one after another.
//!
//! That is the whole defence against one caller degrading the others, and it is
//! structural rather than tuned. On a connection shared by everyone, a caller
//! that stops reading holds the shared HTTP/2 flow-control window and freezes
//! every other response; a request api refuses hard enough closes the connection
//! under every caller's in-flight request; and whoever triggered the one shared
//! connect decides for everyone waiting on it. Owned per public connection, each
//! of those lands on the caller who caused it. It is the same rule the widely
//! deployed proxies follow — they do not multiplex different callers on one
//! upstream connection either.
//!
//! The cost is one attested handshake per public connection, which a browser
//! holding one HTTP/2 connection pays about once per visit. The host learns
//! nothing new from it: it already carries every public connection in.
//!
//! ## The connection to api is attested, in the attested build
//!
//! Both guests may be anywhere, so the hop is guest → host → guest and a host
//! process splices every byte. Without TLS on this leg, everything the public
//! session protected on its first hop would be in the clear on its second, and
//! this role would move the exposure rather than remove it.
//!
//! api's inbound is a PUBLIC surface, so it asks this end for nothing — see
//! `enclavid_api::endorsement`. This end still verifies api, which is the
//! direction that carries the weight.
//!
//! A developer build dials plain TCP and verifies nothing, because there is no
//! host between the two processes to protect anything from — the same axis on
//! which api's own inbound chooses whether to terminate RA-TLS at all.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use hyper::body::Incoming;
use hyper::client::conn::http2::{self, SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use safe_logger::debug;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

/// How long opening a connection to api may take: the dial, the attested
/// handshake and the HTTP/2 preface together.
///
/// Without it a dial the host never answers holds the caller's request for as
/// long as the host likes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often an open connection to api is pinged while a request is on it, and
/// how long an unanswered ping is tolerated before the connection is treated as
/// dead. A leg the host stops carrying without closing then fails the request on
/// it instead of hanging it.
const PING_INTERVAL: Duration = Duration::from_secs(20);
const PING_TIMEOUT: Duration = Duration::from_secs(10);

/// How much of api's answers a connection may hold before api has to wait for
/// this role to pass them on.
///
/// This is the memory a caller can pin per connection, because the answer is
/// read from api only as fast as the caller takes it — so it is a bound and not
/// a tuning knob. hyper's defaults are 5 MiB and 2 MiB, which with a cap on
/// public connections would be the larger half of this role's memory. Uploads
/// are not affected: what a 16 MiB capture flows through is api's receive
/// window, not this one.
const CONNECTION_WINDOW: u32 = 1 << 20;
const STREAM_WINDOW: u32 = 256 << 10;

/// One api instance: a machine, the build on it, and the ports it serves.
struct Instance {
    /// What this machine is called in a link and in a token.
    node: String,
    /// The measurement this instance is DECLARED to have. A caller naming it is
    /// routed here; [`connect`] then proves the declaration before anything is
    /// sent.
    measurement: String,
    applicant: String,
    client: String,
    health: String,
    /// Whether this instance says it can take a NEW session. Shared with the
    /// poller, and carried across pushes — see [`Upstreams::replaced`].
    ready: Arc<Ready>,
}

/// What the health poller learns, and the only thing routing asks it.
///
/// A node that is not ready is skipped when a new session is placed, and
/// nothing else changes: a request that belongs to a session already on that
/// node still goes there, because there is nowhere else it could go.
#[derive(Debug)]
pub struct Ready(AtomicBool);

impl Default for Ready {
    /// A freshly declared node starts ready. The host has just said it is part
    /// of the fleet, the first poll is moments away, and the alternative —
    /// refusing every new session until a poll lands — turns each push into an
    /// outage.
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

/// Everywhere this role may forward to, as of one push.
pub struct Upstreams {
    applicant_name: String,
    client_name: String,
    /// Built once, at boot, and carried into every table after. It holds the
    /// attestor and the verifier, neither of which changes with the fleet.
    tls: Tls,
    instances: Vec<Instance>,
    /// What affinity tokens are signed with, as of this push. `None` only
    /// before the first one, when nothing is served yet.
    affinity: Option<crate::affinity::Keys>,
    /// Where the next new session goes, among the nodes that can take one.
    ///
    /// Round robin, and deliberately the dullest thing that spreads load: the
    /// gateway knows nothing about how much work a session is, and a cleverer
    /// rule would be guessing. It is not carried across pushes — after one, the
    /// table it counted over no longer exists.
    next: AtomicUsize,
}

/// Where one request goes: a machine, an address on it, and the build that must
/// be proved there.
pub struct Target<'a> {
    pub node: &'a str,
    pub addr: &'a str,
    pub measurement: &'a str,
}

/// Which surface a connection belongs to, settled by the name TLS agreed on.
///
/// The two differ in more than a port. An applicant arrives by following a link
/// this fleet wrote, so the machine is in that link and the build follows from
/// it. A consumer arrives with an integration of its own, names the build it
/// requires, and is told which machine it landed on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Surface {
    Applicant,
    Consumer,
}

/// Why a request could not be forwarded.
///
/// Separate variants because they are separate answers to the caller: one says
/// the name is wrong, one says nothing was asked for, one says what was asked
/// for is not here. Collapsing them would make a fleet with no matching build
/// indistinguishable from a caller who forgot the header.
pub enum NoRoute {
    /// The handshake settled a name this role does not serve.
    UnknownName,
    /// No measurement was named where one is required.
    Unspecified,
    /// A build was named and no node declares it, or none that could take a new
    /// session; a node was named and no upstream carries that label. One answer
    /// for all three: which machines exist and how they are is the host's
    /// business and changes under it.
    NoSuchBuild,
}

impl Upstreams {
    /// No api at all: what this role holds until the host's first push.
    pub fn empty(applicant_name: String, client_name: String) -> Upstreams {
        Upstreams {
            applicant_name,
            client_name,
            tls: tls_client(),
            instances: Vec::new(),
            affinity: None,
            next: AtomicUsize::new(0),
        }
    }

    /// The table a push declares, keeping what the poller has learned about the
    /// nodes it still declares.
    ///
    /// Health is carried by (label, health address): a push that only adds a
    /// machine must not make the gateway forget that another one is down, and a
    /// label pointed at a different address is a different machine.
    pub fn replaced(&self, declared: crate::config::ValidatedConfig) -> Upstreams {
        let declared = declared.into_inner();
        Upstreams {
            applicant_name: self.applicant_name.clone(),
            client_name: self.client_name.clone(),
            tls: self.tls.clone(),
            affinity: Some(crate::affinity::Keys::new(
                declared.affinity.key.0,
                declared.affinity.previous_key.map(|key| key.0),
                Duration::from_secs(declared.affinity.ttl_seconds),
            )),
            instances: declared
                .upstreams
                .into_iter()
                .map(|d| Instance {
                    ready: self
                        .instances
                        .iter()
                        .find(|i| i.node == d.node && i.health == d.health)
                        .map(|i| i.ready.clone())
                        .unwrap_or_default(),
                    node: d.node,
                    measurement: d.measurement,
                    applicant: d.applicant,
                    client: d.client,
                    health: d.health,
                })
                .collect(),
            next: AtomicUsize::new(0),
        }
    }

    /// Which surface this connection is, from the name the handshake settled.
    ///
    /// Matched without regard to case, because a host name has none: rustls
    /// hands back the bytes the peer sent, and an exact comparison would refuse
    /// a caller who spelled a correct name in capitals.
    pub fn surface(&self, server_name: Option<&str>) -> Result<Surface, NoRoute> {
        let name = server_name.ok_or(NoRoute::UnknownName)?;
        if name.eq_ignore_ascii_case(&self.applicant_name) {
            Ok(Surface::Applicant)
        } else if name.eq_ignore_ascii_case(&self.client_name) {
            Ok(Surface::Consumer)
        } else {
            Err(NoRoute::UnknownName)
        }
    }

    /// The machine a link or a token names.
    ///
    /// No health check: the session this request belongs to lives there and
    /// nowhere else, so a node that is unwell is still the only answer. It fails
    /// at the connection instead, which is the same 502 and the truth.
    pub fn at_node(&self, surface: Surface, node: &str) -> Result<Target<'_>, NoRoute> {
        let instance = self
            .instances
            .iter()
            .find(|i| i.node == node)
            .ok_or(NoRoute::NoSuchBuild)?;
        Ok(instance.target(surface))
    }

    /// Where a NEW session goes: a node running the build the caller named,
    /// among those that say they can take one.
    ///
    /// The caller does not choose. That is the whole point of placing it here:
    /// a consumer that picked its own node would pin every session to one
    /// machine, and under load a node that cannot take work would keep being
    /// handed it.
    pub fn assign(&self, surface: Surface, measurement: &str) -> Result<Target<'_>, NoRoute> {
        let candidates: Vec<&Instance> = self
            .instances
            .iter()
            .filter(|i| i.measurement == measurement && i.ready.get())
            .collect();
        if candidates.is_empty() {
            return Err(NoRoute::NoSuchBuild);
        }
        let turn = self.next.fetch_add(1, Ordering::Relaxed);
        Ok(candidates[turn % candidates.len()].target(surface))
    }

    /// What affinity tokens are signed with, as of this push.
    pub fn affinity(&self) -> Option<&crate::affinity::Keys> {
        self.affinity.as_ref()
    }

    /// Every node's label and health address, for the poller.
    pub fn to_poll(&self) -> Vec<(String, Arc<Ready>)> {
        self.instances
            .iter()
            .map(|i| (i.health.clone(), i.ready.clone()))
            .collect()
    }

    /// What a connection to any api in this table is secured with.
    pub fn tls(&self) -> &Tls {
        &self.tls
    }

    /// How many builds this table declares. For the line an accepted push writes.
    pub fn len(&self) -> usize {
        self.instances.len()
    }
}

impl Instance {
    /// This instance, as the surface in front of it sees it. The measurement is
    /// what the host DECLARED; the connection proves it before anything is sent.
    fn target(&self, surface: Surface) -> Target<'_> {
        Target {
            node: &self.node,
            addr: match surface {
                Surface::Applicant => &self.applicant,
                Surface::Consumer => &self.client,
            },
            measurement: &self.measurement,
        }
    }
}

/// The connections to api one public connection has opened.
///
/// Keyed by address AND measurement: a connection was proved against one build
/// at one address, and serves nothing else. Dropping this — which happens when
/// the public connection and every request still on it are done — aborts the
/// tasks driving those connections, and closes them.
#[derive(Default)]
pub struct Legs(Mutex<Open>);

#[derive(Default)]
struct Open {
    senders: HashMap<(String, String), SendRequest<Incoming>>,
    drivers: JoinSet<()>,
}

impl Legs {
    /// The connection to `target`, opened on first use or when the last one
    /// closed.
    ///
    /// The lock is held across opening one, so a public connection's concurrent
    /// first requests wait for a single handshake rather than each starting
    /// their own. Only that public connection's requests wait on it.
    pub async fn get(
        &self,
        target: Target<'_>,
        tls: &Tls,
    ) -> std::io::Result<SendRequest<Incoming>> {
        let mut open = self.0.lock().await;
        let key = (target.addr.to_owned(), target.measurement.to_owned());
        if let Some(sender) = open.senders.get(&key)
            && !sender.is_closed()
        {
            return Ok(sender.clone());
        }

        let (sender, driver) = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let io = connect(target.addr, target.measurement, tls).await?;
            http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .keep_alive_interval(PING_INTERVAL)
                .keep_alive_timeout(PING_TIMEOUT)
                // Pinged while idle too, not only while a request is on it. An
                // idle connection the host has stopped carrying would otherwise
                // sit here until the public connection ends, holding a
                // descriptor at both ends of the leg.
                .keep_alive_while_idle(true)
                .initial_connection_window_size(CONNECTION_WINDOW)
                .initial_stream_window_size(STREAM_WINDOW)
                .handshake(TokioIo::new(io))
                .await
                .map_err(std::io::Error::other)
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "opening the connection to api took too long",
            )
        })??;

        // What is finished is let go of before anything new is kept: a closed
        // leg's entry, and the task that drove it. `JoinSet` holds a finished
        // task until it is joined, and a public connection that reconnects —
        // because api restarted, or the host recycled the splice — would
        // otherwise accumulate both for as long as it lives.
        open.senders.retain(|_, sender| !sender.is_closed());
        while open.drivers.try_join_next().is_some() {}

        open.drivers.spawn(async move {
            if let Err(e) = driver.await {
                debug!("connection to api ended: {e}");
            }
        });
        open.senders.insert(key, sender.clone());
        Ok(sender)
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
/// api's inbound is a public surface — it asks no caller for a certificate, and
/// could not, because browsers and consumers' integrations have none. So this
/// end carries none either. The attestor is still required and still does the
/// work that matters: it is what VERIFIES api's quote during the handshake.
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

/// Open one connection to api and refuse it unless it is the declared build.
///
/// The connection then speaks HTTP/2 by prior knowledge — api's inbound
/// recognises the preface, so no ALPN is needed — and hyper's HTTP/2 codec strips
/// hop-by-hop headers from what is sent on it, so this role carries no protocol
/// translation of its own.
///
/// The server name is RA-TLS's fixed placeholder and settles nothing: an RA-TLS
/// certificate carries no name, and who the peer is comes from the quote the
/// verifier checks during the handshake. Which is also why nothing here needs
/// the public name the browser used.
///
/// The measurement check is here rather than at the routing table because this
/// is where it can be true. Routing picks by what the host DECLARED; the
/// handshake is what the peer PROVED, and the two must be the same value or the
/// connection does not exist.
#[cfg(feature = "vsock")]
async fn connect(addr: &str, expected: &str, tls: &Tls) -> std::io::Result<Upstream> {
    let stream = fleet_transport::dial(addr).await?;
    let tls = tls.connect(enclavid_ra_tls::server_name(), stream).await?;

    let proved = enclavid_ra_tls::peer_measurement(tls.get_ref().1).ok_or_else(|| {
        std::io::Error::other("the peer completed an attested handshake carrying no measurement")
    })?;
    if proved != expected {
        // The values are both this build's own configuration and a digest of a
        // published image, so neither is a secret. They still do not go to an
        // outward tier: the host chooses how often this happens, and a line whose
        // rate a caller picks is a channel.
        debug!("upstream at {addr} proved {proved}, declared {expected}");
        return Err(std::io::Error::other(
            "the upstream is not the build it was declared to be",
        ));
    }
    Ok(tls)
}

#[cfg(not(feature = "vsock"))]
async fn connect(addr: &str, _expected: &str, _tls: &Tls) -> std::io::Result<Upstream> {
    fleet_transport::dial(addr).await
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Two builds, spelled the way a real one is: what routing compares is the
    /// string, and the table refuses anything a quote could not carry.
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn declared(node: &str, measurement: &str, port: u16) -> crate::config::Upstream {
        crate::config::Upstream {
            node: node.into(),
            measurement: measurement.into(),
            applicant: format!("127.0.0.1:{port}"),
            client: format!("127.0.0.1:{}", port + 1),
            health: format!("127.0.0.1:{}", port + 2),
        }
    }

    /// A table as the host would have pushed one — through the same checks, so
    /// a fixture nothing could route is a failing test rather than a passing
    /// one.
    pub(crate) fn pushed(
        upstreams: Vec<crate::config::Upstream>,
    ) -> crate::config::ValidatedConfig {
        crate::config::RawConfig {
            upstreams,
            affinity: crate::config::Affinity {
                key: crate::config::Key([0; 32]),
                previous_key: None,
                ttl_seconds: 600,
            },
        }
        .try_into()
        .expect("the fixture declares a routable table")
    }

    fn upstreams() -> Upstreams {
        Upstreams::empty("verify.example.com".into(), "api.example.com".into()).replaced(pushed(
            vec![
                declared("one", A, 1000),
                declared("two", A, 2000),
                declared("three", B, 3000),
            ],
        ))
    }

    #[test]
    fn the_name_picks_the_surface() {
        let up = upstreams();
        assert_eq!(
            up.surface(Some("verify.example.com")).ok(),
            Some(Surface::Applicant)
        );
        assert_eq!(
            up.surface(Some("api.example.com")).ok(),
            Some(Surface::Consumer)
        );
        // A host name has no case, so capitals must not move a caller to the
        // other audience's door — or to none at all.
        assert_eq!(
            up.surface(Some("VERIFY.Example.CoM")).ok(),
            Some(Surface::Applicant)
        );
        assert!(matches!(
            up.surface(Some("elsewhere.example.com")),
            Err(NoRoute::UnknownName)
        ));
        assert!(matches!(up.surface(None), Err(NoRoute::UnknownName)));
    }

    /// A label picks the machine, and the surface picks which of its two ports.
    #[test]
    fn a_label_names_one_machine_on_either_surface() {
        let up = upstreams();
        let applicant = up.at_node(Surface::Applicant, "one").ok().unwrap();
        assert_eq!(
            (applicant.node, applicant.addr, applicant.measurement),
            ("one", "127.0.0.1:1000", A)
        );
        let consumer = up.at_node(Surface::Consumer, "one").ok().unwrap();
        assert_eq!(consumer.addr, "127.0.0.1:1001");
        assert!(up.at_node(Surface::Consumer, "nowhere").is_err());
    }

    /// A machine that has not been placed on before is placed on now: new
    /// sessions spread rather than pile onto whichever came first.
    #[test]
    fn new_sessions_go_round_the_machines_running_that_build() {
        let up = upstreams();
        let first = up
            .assign(Surface::Consumer, A)
            .ok()
            .unwrap()
            .node
            .to_owned();
        let second = up
            .assign(Surface::Consumer, A)
            .ok()
            .unwrap()
            .node
            .to_owned();
        assert_ne!(first, second);
        assert_eq!(
            up.assign(Surface::Consumer, A).ok().unwrap().node,
            first,
            "and then round again"
        );
        assert_eq!(up.assign(Surface::Consumer, B).ok().unwrap().node, "three");
    }

    /// A build nobody runs and a machine that cannot take work answer the same
    /// way: which machines exist and how they are is the host's business.
    #[test]
    fn nothing_to_place_on_is_one_answer() {
        let up = upstreams();
        assert!(matches!(
            up.assign(Surface::Consumer, "cc33"),
            Err(NoRoute::NoSuchBuild)
        ));

        for node in ["one", "two"] {
            up.instances
                .iter()
                .find(|i| i.node == node)
                .unwrap()
                .ready
                .set(false);
        }
        assert!(matches!(
            up.assign(Surface::Consumer, A),
            Err(NoRoute::NoSuchBuild)
        ));
        // And a request that belongs to a session already there still goes
        // there: unwell or not, it is the only machine that has it.
        assert!(up.at_node(Surface::Consumer, "one").is_ok());
    }

    /// Before the first push nothing routes, and it fails as an unavailable
    /// upstream rather than as anything that would say the table is empty.
    #[test]
    fn an_empty_table_routes_nothing() {
        let up = Upstreams::empty("verify.example.com".into(), "api.example.com".into());
        assert_eq!(up.len(), 0);
        assert!(up.affinity().is_none());
        assert!(matches!(
            up.assign(Surface::Consumer, A),
            Err(NoRoute::NoSuchBuild)
        ));
        assert!(matches!(
            up.at_node(Surface::Applicant, "one"),
            Err(NoRoute::NoSuchBuild)
        ));
    }

    /// A replacement is whole: what the new push leaves out stops routing.
    #[test]
    fn a_machine_the_next_push_omits_stops_routing() {
        let next = upstreams().replaced(pushed(vec![declared("two", A, 2000)]));
        assert_eq!(next.len(), 1);
        assert!(next.at_node(Surface::Applicant, "one").is_err());
        assert!(next.at_node(Surface::Applicant, "two").is_ok());
    }

    /// What the poller learned survives a push that still declares the machine,
    /// so adding one does not quietly make an unwell one placeable again.
    #[test]
    fn a_verdict_survives_a_push_that_keeps_the_machine() {
        let up = upstreams();
        up.instances
            .iter()
            .find(|i| i.node == "one")
            .unwrap()
            .ready
            .set(false);

        let next = up.replaced(pushed(vec![
            declared("one", A, 1000),
            declared("two", A, 2000),
        ]));
        assert_eq!(next.assign(Surface::Consumer, A).ok().unwrap().node, "two");

        // A label pointed at a different machine is a different machine, and
        // starts over.
        let moved = next.replaced(pushed(vec![declared("one", A, 5000)]));
        assert!(moved.assign(Surface::Consumer, A).is_ok());
    }
}
