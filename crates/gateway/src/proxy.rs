//! Which api a request goes to, what is said back, and what is never said.
//!
//! ## Legs are shared, and carry one request at a time
//!
//! What made a shared connection to api unusable was CONCURRENCY, not sharing:
//! HTTP/2's flow-control window belongs to the connection, so a caller that
//! stops reading freezes everyone else's answers on it; a `GOAWAY` takes down
//! whatever else was in flight; the reset budget is spent per connection. All
//! of that needs two callers on one connection AT ONCE.
//!
//! So a leg carries one request at a time and is returned to the pool between
//! them — [`STREAMS_PER_LEG`]. A caller that stops reading then holds up
//! nothing but itself, and a leg that dies takes one request with it. This is
//! what nginx does with its upstream keepalive pool, and what this library's
//! own default does.
//!
//! The alternative — a pool per public connection — isolates more and costs
//! what no fleet can pay: a leg per visitor means an attested session per
//! visitor AT API, so a thousand idle browsers hold a thousand connections on
//! the other side of the host. Shared, the number of legs follows the number of
//! requests in flight, which is the number that reflects actual work.
//!
//! ## And what a leg proved is checked again when it is taken
//!
//! Which leg a request gets is decided by a key the library hashes, so on its
//! own the binding between "this caller named build M" and "this connection
//! proved M" would rest on that key being built correctly for ever.
//! [`ProxyHttp::connected_to_upstream`] closes that: the measurement proved
//! when the leg was opened is written down against its descriptor, and read
//! back here after a leg has been chosen and before anything is sent.
//!
//! ## One rule, and no idea who is calling
//!
//! There is one way a request finds its group, with three inputs tried in
//! order: a label marked in the path, a signed token naming a group and the
//! build it was placed for, or — with neither — a build the caller names,
//! against which this role places it and says where. Nothing here knows what
//! kind of caller it is serving; a caller either knows its group or is given
//! one.
//!
//! The token's build is compared to what that label runs NOW, so the caller's
//! one choice binds every later request rather than only the first — see
//! `crate::affinity`. A path-marked label carries no build and nothing here can
//! check one; what protects a session reached that way is that its state is
//! sealed to the build that made it, so another cannot open it.
//!
//! The name the handshake settled decides only WHICH ADDRESS of that group to
//! use, because one api process serves two ports. It is a field on this
//! because a connection cannot change the name it agreed to.
//!
//! ## Why the label in a path is marked
//!
//! It is `/-<label>/...`, and the marker is not decoration. Without it the
//! label would be the first path segment, and api's own paths begin with
//! segments that are perfectly good labels — `api` is one. A role that has to
//! know api's path space to avoid the collision is a role that has a copy of
//! api's routes in a measured image, which is the thing this design refuses.
//!
//! ## What reaches api, and what stops here
//!
//! The path is never examined beyond the label a link carries, which is
//! stripped on the way through. The measurement header names a choice
//! this hop makes and is removed. The affinity token is this role's own
//! bookkeeping and is removed. Nothing about the caller's address is added,
//! because this role has none to add and api holds the session id: the two
//! together would link who to which session inside the enclave.

use std::sync::Arc;

use pingora_core::protocols::tls::ALPN;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use safe_logger::debug;
use tokio::sync::watch;

use crate::leg::Leg;
use crate::upstream::{NoRoute, Upstreams};
use crate::{affinity, attest};

/// The answer for anything that went wrong behind this role.
///
/// One status for every cause — no route, no machine that would take the work,
/// a leg that would not open, a leg that failed mid-answer. Which machines
/// exist, which builds they run and which can take work is the host's business
/// and changes under it, so telling those apart would report the fleet's shape
/// to whoever asked.
const UNAVAILABLE: u16 = 502;

/// The answer when the caller left out something only the caller can supply.
const INCOMPLETE: u16 = 400;

/// The answer for a name this role does not serve.
const MISDIRECTED: u16 = 421;

/// How long a leg may sit unused before it is closed.
///
/// Set rather than inherited: the library's default is to keep one for ever,
/// and a leg is an attested session through the host that should not outlive
/// the traffic that justified it.
const IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// How many requests may be on one leg at once.
///
/// One, which is what makes a shared pool safe — see the module docs. A leg is
/// taken for a request and returned after it, so the callers on a leg are
/// sequential and can neither freeze nor reset one another.
const STREAMS_PER_LEG: usize = 1;

/// One served name's proxy, built at boot and shared by every caller of it.
///
/// `name` is absent on the one built for names this role does not answer to: a
/// caller that reached such a name is answered rather than dropped, because the
/// request is well-formed and this role simply is not its server — see
/// [`MISDIRECTED`].
pub struct Hop {
    name: Option<String>,
    table: watch::Receiver<Arc<Upstreams>>,
    proof: attest::Proof,
    ledger: Arc<crate::leg::Ledger>,
}

impl Hop {
    pub fn new(
        name: Option<String>,
        table: watch::Receiver<Arc<Upstreams>>,
        proof: attest::Proof,
        ledger: Arc<crate::leg::Ledger>,
    ) -> Hop {
        Hop {
            name,
            table,
            proof,
            ledger,
        }
    }
}

/// What one request learned on its way in, and what its answer owes back.
#[derive(Default)]
pub struct Placed {
    /// The group this request went to, and a token to return by. Present only
    /// when this role chose the group: a caller that already knew it needs
    /// nothing said to it.
    told: Option<(String, String)>,
    /// The build this request requires, kept so that the leg it is actually
    /// given can be checked against it.
    named: Option<String>,
}

#[async_trait::async_trait]
impl ProxyHttp for Hop {
    type CTX = Placed;

    fn new_ctx(&self) -> Placed {
        Placed::default()
    }

    /// This role's own path, answered before anything is routed and without
    /// reaching api at all. It is the one path this build knows: what a request
    /// for anything else means is the host's configuration, never this file's.
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Placed,
    ) -> pingora_core::Result<bool> {
        if session.req_header().uri.path() != attest::PATH {
            return Ok(false);
        }

        let method = &session.req_header().method;
        if method != "GET" && method != "HEAD" {
            session.respond_error(405).await?;
            return Ok(true);
        }

        let mut head = ResponseHeader::build(200, Some(3))?;
        head.insert_header("content-type", attest::CONTENT_TYPE)?;
        // A quote is checked, not cached: a caller that keeps one and compares
        // it to a certificate from a later connection is checking a binding
        // that was true elsewhere.
        head.insert_header("cache-control", "no-store")?;
        head.insert_header("content-length", self.proof.len().to_string())?;
        session.write_response_header(Box::new(head), false).await?;
        session
            .write_response_body(Some(self.proof.clone()), true)
            .await?;
        Ok(true)
    }

    /// Which group, which address in it, and — when this role chose the group —
    /// a token to hand back so the next request of this session returns to it.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Placed,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        // 421 rather than 404: the request is well-formed and this role simply
        // is not the server for the name it was sent to.
        let Some(name) = self.name.as_deref() else {
            return Err(refuse(MISDIRECTED));
        };

        let table = self.table.borrow().clone();
        let (target, minted) = match route(&table, name, session) {
            Ok(routed) => routed,
            // 400, because the request is missing something only the caller can
            // supply. Naming a build is not a formality here — it is the whole
            // of what this role checks on the caller's behalf.
            Err(NoRoute::Unspecified) => return Err(refuse(INCOMPLETE)),
            Err(_) => return Err(refuse(UNAVAILABLE)),
        };
        if let Some(token) = minted {
            ctx.told = Some((target.group.to_owned(), token));
        }
        ctx.named = Some(target.measurement.to_owned());

        // The address is a placeholder the pool's own check waives, and the
        // leg is what actually dials and proves — see `crate::leg`.
        let mut peer = HttpPeer::new("0.0.0.0:0", false, String::new());
        peer.options.alpn = ALPN::H2;
        peer.options.max_h2_streams = STREAMS_PER_LEG;
        peer.options.idle_timeout = Some(IDLE);
        // One pool of legs per (address, build). A build the host re-declares
        // at the same address is a different leg, not the same one reused,
        // because what was proved of the old one was proved of the old build.
        // This is the only thing keeping the two apart in the pool, which is
        // why `connected_to_upstream` checks the answer rather than trusting it.
        peer.group_key = key(target.addr(), target.measurement);
        peer.options.custom_l4 = Some(Arc::new(Leg::new(
            target.addr().to_owned(),
            target.measurement.to_owned(),
            target.part.clone(),
            table.tls().clone(),
            self.ledger.clone(),
        )));
        Ok(Box::new(peer))
    }

    /// The leg this request was actually given, checked against the build the
    /// request requires.
    ///
    /// A leg opened moments ago and a leg taken from the pool are treated the
    /// same, deliberately: what matters is not how it was obtained but what it
    /// proved, and that was written down when it was opened — see
    /// `crate::leg::Ledger`. A leg this role did not open, or one that proved
    /// something else, fails the request here, before a byte of it is sent.
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        fd: std::os::fd::RawFd,
        _digest: Option<&pingora_core::protocols::Digest>,
        ctx: &mut Placed,
    ) -> pingora_core::Result<()> {
        let named = ctx.named.as_deref().unwrap_or_default();
        match self.ledger.proved(fd) {
            Some(proved) if proved == named => Ok(()),
            proved => {
                // Both values are a digest of a published image and neither is
                // a secret, but the rate of this line would be the host's to
                // pick, so it stays where only a debug build can read it.
                debug!(
                    "a leg proved {} and the request requires {named}",
                    proved.as_deref().unwrap_or("nothing this role opened")
                );
                Err(refuse(UNAVAILABLE))
            }
        }
    }

    /// Said on the way back whenever this role did the choosing: the group this
    /// request went to, and a token that returns the next one to it. Sliding
    /// rather than issued once, so a session outliving one token keeps its
    /// group.
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        answer: &mut ResponseHeader,
        ctx: &mut Placed,
    ) -> pingora_core::Result<()> {
        if let Some((group, token)) = ctx.told.take() {
            for (header, value) in [
                (affinity::GROUP_HEADER, group),
                (affinity::TOKEN_HEADER, token),
            ] {
                if let Err(e) = answer.insert_header(header, &value) {
                    debug!("could not write {header}: {e}");
                }
            }
        }
        Ok(())
    }

    /// A leg that would not open is noted and nothing else.
    ///
    /// Whether a member can take work is the checks' to say, and they ask it
    /// directly every interval — see `crate::balance`. Acting here as well
    /// would mean a flag this role has to clear, and clearing it would mean a
    /// timer racing the library's schedule.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        _ctx: &mut Placed,
        e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        debug!("a leg would not open");
        e
    }

    /// Every failure answers the same way, whatever the library would have made
    /// of it — see [`UNAVAILABLE`]. A status carried on an error this role
    /// raised is honoured; anything else is behind this role.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        _ctx: &mut Placed,
    ) -> FailToProxy {
        let error_code = match e.esource() {
            pingora_core::ErrorSource::Downstream => INCOMPLETE,
            _ => match e.etype() {
                pingora_core::ErrorType::HTTPStatus(code) => *code,
                _ => UNAVAILABLE,
            },
        };
        if session.response_written().is_none() {
            let _ = session.respond_error(error_code).await;
        }
        FailToProxy {
            error_code,
            can_reuse_downstream: false,
        }
    }

    /// Nothing derived from a request reaches a log line. The library builds
    /// this string from the method, the path and the host, and a path can carry
    /// the session id — the one value that turns the host's separate
    /// observations into one linked profile.
    fn request_summary(&self, _session: &Session, _ctx: &Placed) -> String {
        "a request".to_owned()
    }

    fn suppress_error_log(
        &self,
        _session: &Session,
        _ctx: &Placed,
        _e: &pingora_core::Error,
    ) -> bool {
        true
    }

    fn suppress_proxy_warn_log(
        &self,
        _session: &Session,
        _ctx: &Placed,
        _e: &pingora_core::Error,
        _context: pingora_proxy::ProxyWarnLogContext,
    ) -> bool {
        true
    }
}

/// An error carrying the status this role decided on, and nothing else.
fn refuse(status: u16) -> Box<pingora_core::Error> {
    pingora_core::Error::new(pingora_core::ErrorType::HTTPStatus(status))
}

/// The one rule: where this request goes, and whether a token goes back.
///
/// Three inputs, tried in order. A label marked in the path is what a link this
/// fleet wrote carries, and a browser can send nothing else on a navigation. A
/// label in a signed token is what a caller was handed last time. With neither,
/// the caller must name the build it requires, and this role chooses.
///
/// A token comes back only when this role did the choosing: a caller that
/// already knew its group needs nothing said to it.
fn route<'a>(
    table: &'a Upstreams,
    name: &str,
    session: &mut Session,
) -> Result<(crate::upstream::Target<'a>, Option<String>), NoRoute> {
    let keys = table.affinity().ok_or(NoRoute::NoSuchGroup)?;
    let now = std::time::SystemTime::now();

    if let Some(label) = marked_in_path(session) {
        return Ok((table.at_group(name, &label)?, None));
    }

    let head = session.req_header_mut();
    // Taken, not copied: both of these name a choice this hop makes, and api
    // has no use for either.
    let token = head
        .remove_header(affinity::TOKEN_HEADER)
        .and_then(|value| value.to_str().ok().map(str::to_owned));
    // A token that does not check out is treated as absent rather than refused:
    // it is this role's own bookkeeping, and the caller cannot do anything
    // about a key that rotated twice or a clock that moved.
    let placed = token
        .as_deref()
        .and_then(|token| keys.placement(token, now));
    if let Some(placed) = placed {
        // The build the caller was placed FOR, against what that label runs
        // now. A label is the host's to re-declare, so without this a caller
        // that named a build once would follow the label onto another — and a
        // request that creates something new would land there silently. An
        // older session would at least break loudly, its state being sealed to
        // the build that made it.
        //
        // A label that is gone and a label that now runs something else are one
        // case: the token is stale rather than forged, so it is treated as
        // absent. The caller names what it needs again and is placed again,
        // which is a recovery it can perform without being told how.
        let still = table
            .at_group(name, &placed.group)
            .ok()
            .filter(|target| target.measurement == placed.build);
        if let Some(target) = still {
            let token = keys.mint(&placed.group, &placed.build, now);
            return Ok((target, Some(token)));
        }
    }

    // Named once or not at all. Two values would route by whichever came first,
    // which is a choice made for the caller that this header exists to prevent.
    if head.headers.get_all(MEASUREMENT).iter().nth(1).is_some() {
        return Err(NoRoute::Unspecified);
    }
    let wanted = head
        .remove_header(MEASUREMENT)
        .and_then(|value| value.to_str().ok().map(str::to_owned))
        .ok_or(NoRoute::Unspecified)?;

    let target = table.place(name, &wanted)?;
    let token = keys.mint(target.group, target.measurement, now);
    Ok((target, Some(token)))
}

/// Which build the caller requires.
///
/// It does not name what that build IS — this role knows only that a group
/// declares it and a leg proves it. So the header does not either.
///
/// A header rather than anything in the path, and the difference is not
/// cosmetic. This value is FOR this hop — it selects an upstream and then stops
/// — so it is stripped before forwarding. A path would travel, and would also
/// mean reading paths, which this role does not do.
pub const MEASUREMENT: &str = "x-enclavid-measurement";

/// What marks a group's label in a path, so it can never be mistaken for a
/// segment api published.
///
/// api's own paths begin with ordinary words, and `api` is a perfectly good
/// label — an unmarked first segment would make `/api/v1/…` read as the group
/// `api`. The marker is what lets this role take a label out of a path without
/// holding any knowledge of what api's paths look like.
const MARK: char = '-';

/// The label a link carries, removed on the way through so api sees the path it
/// published.
///
/// A path with no marked label is not an error here — it is a caller that will
/// be routed by token or placed by the build it names.
fn marked_in_path(session: &mut Session) -> Option<String> {
    let head = session.req_header_mut();
    let rest = head.uri.path().strip_prefix('/')?.strip_prefix(MARK)?;
    let (label, rest) = rest.split_once('/').unwrap_or((rest, ""));
    if label.is_empty() {
        return None;
    }
    let label = label.to_owned();

    let query = head
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    // Only the path and query are replaced. Everything else the request
    // arrived with stays, because on HTTP/2 the authority is a field of its
    // own and a request that lost it is a request api cannot answer.
    let mut parts = head.uri.clone().into_parts();
    match format!("/{rest}{query}").parse() {
        Ok(stripped) => {
            parts.path_and_query = Some(stripped);
            match hyper::Uri::from_parts(parts) {
                Ok(uri) => {
                    head.set_uri(uri);
                    Some(label)
                }
                Err(e) => {
                    debug!("could not put the path back together: {e}");
                    None
                }
            }
        }
        Err(e) => {
            debug!("could not take the label out of the path: {e}");
            None
        }
    }
}

/// One number standing for an address and the build at it.
///
/// Legs are kept apart by it inside the pool. It is a hash, so two different
/// pairs could in principle land on one — which is why it is not what makes a
/// connection safe: that is the proof on every dial, checked again in
/// [`ProxyHttp::connected_to_upstream`].
fn key(addr: &str, measurement: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    addr.hash(&mut hasher);
    measurement.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_and_a_build_key_a_leg_together() {
        assert_ne!(
            key("a", "one"),
            key("a", "two"),
            "a rolled build is a new leg"
        );
        assert_ne!(key("a", "one"), key("b", "one"), "another machine is too");
        assert_eq!(key("a", "one"), key("a", "one"));
    }
}
