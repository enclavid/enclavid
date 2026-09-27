//! Which api a request goes to, what is said back, and what is never said.
//!
//! ## Legs are shared, and carry one request at a time
//!
//! What made a shared connection to api unusable was CONCURRENCY, not sharing:
//! HTTP/2's flow-control window belongs to the connection, so a caller that
//! stops reading freezes everyone else's responses on it; a `GOAWAY` takes down
//! whatever else was in flight; the reset budget is spent per connection. All
//! of that needs two callers on one connection AT ONCE.
//!
//! So a leg carries one request at a time and is returned between them — see
//! `crate::upstream::member`. A caller that stops reading then holds up nothing but
//! itself, and a leg that dies takes one request with it.
//!
//! The alternative — a leg per public connection — isolates more and costs what
//! no fleet can pay: a leg per visitor means an attested session per visitor AT
//! API, so a thousand idle browsers hold a thousand connections on the other
//! side of the host. Shared, the number of legs follows the number of requests
//! in flight, which is the number that reflects actual work.
//!
//! ## What was proved, and why nothing re-checks it here
//!
//! A leg is opened by `crate::upstream::member`, which dials and proves the build
//! in one call and returns only a connection that proved it. A leg that exists
//! is therefore a leg to the declared build, and the set it is parked in holds
//! only legs proving that set's own build — a set is never carried across a push
//! that changed it. So there is nothing for this file to verify after the fact:
//! the proof is structural rather than recorded and compared.
//!
//! ## One rule, and no idea who is calling
//!
//! There is one way a request finds its group, with three inputs tried in
//! order: a label and a build marked in the path, a signed token naming a group
//! and the build it was placed for, or — with neither — a build the caller
//! names, against which this role places it and says where. Nothing here knows
//! what kind of caller it is serving; a caller either knows its group or is
//! given one.
//!
//! Whichever way a request arrives, the build it carries is compared to what
//! its label runs NOW, so the caller's one choice binds every later request
//! rather than only the first — see `affinity`. A label is the host's to
//! re-declare; a build is not. Without the build beside it, a label in a link
//! would follow a push onto whatever the host declared under it, and the page,
//! the bearer and every upload would go there with it. That the state is sealed
//! to the build that made it protects the state, not the data still in flight.
//!
//! The name the handshake settled decides only WHICH ADDRESSES of that group to
//! use, because one api process listens on more than one port. It is read from
//! the CONNECTION rather than from the request, because a caller writes its own
//! `Host` and cannot change the name it agreed to — see `crate::listener`.
//!
//! ## Why the label in a path is marked
//!
//! It is `/-<label>.<build>/...`, and the marker is not decoration. Without it
//! the label would be the first path segment, and api's own paths begin with
//! segments that are perfectly good labels — `api` is one. A role that has to
//! know api's path space to avoid the collision is a role that has a copy of
//! api's routes in a measured image, which is the thing this design refuses.
//!
//! The build is the whole measurement, not a prefix of it: the same value a
//! caller names in a header and the host declares in a push, compared by
//! equality. The dot parses without doubt, because no label may contain one.
//!
//! ## What reaches api, and what stops here
//!
//! The path is never examined beyond the marker a link carries, which is
//! stripped on the way through. The target goes on as `https://` and the name
//! the connection agreed to, and the caller's own `Host` stops here, since the
//! handshake's name is the one routed by. A request that names a different
//! host than that one is not routed at all: it is refused with 421, as a
//! request on a connection this role does not serve is. The measurement header
//! names a choice this hop makes and is removed, whichever way the request is
//! routed. The affinity token is this role's own bookkeeping and is removed the
//! same way.
//!
//! Nothing about where the caller is reaches api either — not what the host's
//! first hop said, and not what the caller says itself. api holds the session
//! id, and an address beside it would link who to which session inside the
//! enclave. The source the first hop names stays in `crate::listener::source`,
//! as a keyed hash that counts a share. The headers in which a request gives an
//! account of its own origin are taken off — see [`FORWARDING`] — and so are
//! its trailers, where any header could travel instead — see
//! `crate::listener::body`.

pub mod affinity;

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use safe_logger::debug;
use tokio::sync::watch;

use crate::identity::attest;
use crate::upstream::member::Sent;
use crate::upstream::{NoRoute, Upstreams};

/// What this role responds with.
///
/// Boxed because two shapes leave here: a body arriving from api, still on the
/// leg it came in on, and a fixed one this role wrote itself. Everything after
/// this point treats them alike, which is what keeps the two paths one path.
pub type ResponseBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// The one hop this role runs, shared by every caller of every name.
///
/// One rather than one per name, because the name a request is routed by is a
/// property of its CONNECTION, not of this object: it is the one the handshake
/// settled, and `crate::listener` hands it in per request.
pub struct Hop {
    table: watch::Receiver<Arc<Upstreams>>,
    evidence: attest::Evidence,
}

impl Hop {
    pub fn new(table: watch::Receiver<Arc<Upstreams>>, evidence: attest::Evidence) -> Hop {
        Hop { table, evidence }
    }

    /// Respond to one request that arrived on a connection which agreed to
    /// `agreed`, its body already bounded by `crate::listener`.
    pub async fn respond(&self, agreed: &str, req: Request<Sent>) -> Response<ResponseBody> {
        if req.uri().path() == attest::PATH {
            return self.attestation(&req);
        }

        let table = self.table.borrow().clone();
        // 421 rather than 404: the request is well-formed and this role simply
        // is not the server for the name the connection agreed to.
        let Some(name) = served(agreed, &table) else {
            return refuse(StatusCode::MISDIRECTED_REQUEST);
        };
        let name = name.to_owned();
        // And the same response for a request asked of another name than its
        // connection's. One certificate covers every name, so a browser may
        // pool one connection for two of them; told 421, it asks again on a
        // connection of the right one, where routed as the first it would have
        // reached the wrong listener of api.
        match names_another(&req, &name) {
            Ok(false) => {}
            Ok(true) => return refuse(StatusCode::MISDIRECTED_REQUEST),
            Err(Unreadable) => return refuse(StatusCode::BAD_REQUEST),
        }

        let mut req = req;
        let (target, minted) = match route(&table, &name, &mut req) {
            Ok(routed) => routed,
            // 400, because the request is missing something only the caller can
            // supply. Naming a build is not a formality here — it is the whole
            // of what this role checks on the caller's behalf.
            Err(NoRoute::Unspecified) => return refuse(StatusCode::BAD_REQUEST),
            Err(_) => return refuse(StatusCode::BAD_GATEWAY),
        };
        let told = minted.map(|token| (marker(target.group, target.measurement), token));
        if addressed(&mut req, &name).is_none() {
            return refuse(StatusCode::BAD_REQUEST);
        }
        unforwarded(&mut req);

        let Ok(response) = target.members.send(req).await else {
            return refuse(StatusCode::BAD_GATEWAY);
        };

        let (mut head, body) = response.into_parts();
        // Said on the way back whenever this role did the choosing: the group
        // this request went to, in the form a link carries it, and a token that
        // returns the next one to it. Sliding rather than issued once, so a
        // session outliving one token keeps its group.
        if let Some((group, token)) = told {
            for (header, value) in [
                (affinity::GROUP_HEADER, group),
                (affinity::TOKEN_HEADER, token),
            ] {
                match value.parse() {
                    Ok(value) => {
                        head.headers.insert(header, value);
                    }
                    Err(e) => debug!("could not write {header}: {e}"),
                }
            }
        }
        Response::from_parts(head, body.boxed())
    }

    /// This role's own path, responded to without reaching api at all.
    ///
    /// It is the one path this build knows: what a request for anything else
    /// means is the host's configuration, never this file's.
    fn attestation<B>(&self, req: &Request<B>) -> Response<ResponseBody> {
        if req.method() != "GET" && req.method() != "HEAD" {
            let mut refused = refuse(StatusCode::METHOD_NOT_ALLOWED);
            refused.headers_mut().insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_static("GET, HEAD"),
            );
            return refused;
        }
        let mut response = Response::new(fixed(self.evidence.clone()));
        let headers = response.headers_mut();
        headers.insert(
            "content-type",
            attest::CONTENT_TYPE.parse().expect("a constant"),
        );
        // A quote is checked, not cached: a caller that keeps one and compares
        // it to a certificate from a later connection is checking a binding
        // that was true elsewhere.
        headers.insert("cache-control", "no-store".parse().expect("a constant"));
        response
    }
}

/// The name this connection agreed to, if it is one this table serves.
///
/// Read from the connection rather than from the request — see
/// `crate::listener` for why `Host` would be the wrong source.
fn served<'a>(agreed: &str, table: &'a Upstreams) -> Option<&'a str> {
    table
        .served()
        .iter()
        .find(|served| served.eq_ignore_ascii_case(agreed))
        .map(String::as_str)
}

/// Whether the request names a host other than `name` — in its target's
/// authority or in a `Host` header.
///
/// Compared without case, without a port and without a final dot: a port is
/// the one the caller dialled at the host's first hop, which this role never
/// learns, and a final dot is a spelling of the same name. A request naming
/// no host at all is asked of its connection's. Two `Host` headers, or one that
/// is not a host, are [`Unreadable`].
fn names_another<B>(req: &Request<B>, name: &str) -> Result<bool, Unreadable> {
    let another = |host: &str| {
        !host
            .strip_suffix('.')
            .unwrap_or(host)
            .eq_ignore_ascii_case(name)
    };
    if req
        .uri()
        .authority()
        .is_some_and(|target| another(target.host()))
    {
        return Ok(true);
    }
    let mut hosts = req.headers().get_all(hyper::header::HOST).iter();
    match (hosts.next(), hosts.next()) {
        (None, _) => Ok(false),
        (Some(host), None) => {
            let host: hyper::http::uri::Authority = host
                .to_str()
                .ok()
                .and_then(|host| host.parse().ok())
                .ok_or(Unreadable)?;
            Ok(another(host.host()))
        }
        (Some(_), Some(_)) => Err(Unreadable),
    }
}

/// A request whose host cannot be read.
struct Unreadable;

/// Write the request's target as `https://<name><path>`, and drop its `Host`.
///
/// The name is the one the handshake settled, which the caller's own, if it
/// wrote one, has already been found to agree with — see [`names_another`].
/// Written again rather than kept, so what goes on carries neither the port nor
/// the spelling the caller used. Written whole, because the leg is HTTP/2: a
/// request carrying a scheme and no authority is one the leg's client refuses,
/// and a caller that could send one could fail requests at will. `None` for a
/// target that cannot be written so, which is the caller's to fix.
fn addressed<B>(req: &mut Request<B>, name: &str) -> Option<()> {
    let mut parts = std::mem::take(req.uri_mut()).into_parts();
    parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
    parts.authority = Some(name.parse().ok()?);
    if parts.path_and_query.is_none() {
        parts.path_and_query = Some(hyper::http::uri::PathAndQuery::from_static("/"));
    }
    *req.uri_mut() = hyper::Uri::from_parts(parts).ok()?;
    req.headers_mut().remove(hyper::header::HOST);
    Some(())
}

/// The headers in which a request gives an account of its own origin: the
/// address it came from, the name, scheme, port or path it first asked for, and
/// the hops it passed on the way.
///
/// Each is a name that software reads AS a client's address, and none is this
/// role's to pass on — see the module docs. A caller can still write its
/// address anywhere else it likes, in a header of its own or in a body. What
/// this takes away is every name that something in api could take for a fact.
pub const FORWARDING: [&str; 12] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-real-ip",
    "x-client-ip",
    "client-ip",
    "true-client-ip",
    "x-cluster-client-ip",
    "via",
];

/// Take every [`FORWARDING`] header off `req`, each value of each.
fn unforwarded<B>(req: &mut Request<B>) {
    for name in FORWARDING {
        req.headers_mut().remove(name);
    }
}

/// A body this role wrote itself.
fn fixed(bytes: Bytes) -> ResponseBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

/// The response when responding to a request panicked: the one a request that
/// failed behind this role gets, so the caller cannot tell the two apart.
///
/// What the panic said is never read. It may quote the caller's own input, and
/// this role does not repeat that to anyone.
pub fn panicked(_: Box<dyn std::any::Any + Send>) -> Response<ResponseBody> {
    refuse(StatusCode::BAD_GATEWAY)
}

/// A response that carries a status and nothing else.
///
/// No body: what went wrong behind this role is not the caller's business, and
/// a sentence describing it is a sentence about the fleet.
///
/// For the same reason anything that went wrong behind this role is one status,
/// `502`, whatever the cause — no route, no machine that would take the work, a
/// leg that would not open, a leg that failed mid-response, a panic while
/// responding. Which machines exist, which builds they run and which can take
/// work is the host's business and changes under it, so telling those apart
/// would report the fleet's shape to whoever asked.
///
/// One status, not one moment. A build no group declares is refused at once; a
/// declared one whose members are down is refused after a dial or a wait for
/// one. So the clock tells a caller whether a build it named is declared here.
/// That is not padded: a build is a published digest, and which ones a fleet
/// runs is the one fact a caller is meant to act on — it names one, and a link
/// carries one. Padding the fast response to the slow one would hold a place
/// for every request that names nothing.
fn refuse(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::new(fixed(Bytes::new()));
    *response.status_mut() = status;
    response
}

/// The one rule: where this request goes, and whether a token goes back.
///
/// Three inputs, tried in order. A label and a build marked in the path are
/// what a link carries, and a browser can send nothing else on a navigation. A
/// label in a signed token is what a caller was handed last time. With neither,
/// the caller must name the build it requires, and this role chooses.
///
/// A token comes back only when this role did the choosing: a caller that
/// already knew its group needs nothing said to it.
fn route<'a, B>(
    table: &'a Upstreams,
    name: &str,
    req: &mut Request<B>,
) -> Result<(crate::upstream::Target<'a>, Option<String>), NoRoute> {
    let keys = table.affinity().ok_or(NoRoute::NoSuchGroup)?;
    let now = std::time::SystemTime::now();

    // Taken off the request FIRST, before any branch below can return — every
    // branch forwards the request, and both of these name a choice this hop
    // makes that api has no use for. Whether the build was named more than once
    // is noted before the header goes, because it cannot be counted after.
    let token = req
        .headers_mut()
        .remove(affinity::TOKEN_HEADER)
        .and_then(|value| value.to_str().ok().map(str::to_owned));
    let named_twice = req.headers().get_all(MEASUREMENT).iter().nth(1).is_some();
    let named = req
        .headers_mut()
        .remove(MEASUREMENT)
        .and_then(|value| value.to_str().ok().map(str::to_owned));
    // Named once or not at all, whichever way the request goes on. Two values
    // would route by whichever this role preferred, which is a choice made for
    // the caller that this header exists to prevent.
    if named_twice {
        return Err(NoRoute::Unspecified);
    }

    if let Some(marked) = marked_in_path(req)? {
        // A build named in a header as well must be the same one, for the same
        // reason.
        if named.as_deref().is_some_and(|named| named != marked.build) {
            return Err(NoRoute::Unspecified);
        }
        // What the label runs NOW, against the build the link was written for.
        // A label that is gone and a label that runs something else are one
        // response, as everywhere: which groups exist is the host's business.
        let target = table.at_group(name, &marked.label)?;
        if target.measurement != marked.build {
            return Err(NoRoute::NoSuchGroup);
        }
        return Ok((target, None));
    }

    // A token that does not check out is treated as absent rather than refused:
    // it is this role's own bookkeeping, and the caller cannot do anything
    // about a key that rotated twice or a clock that moved.
    //
    // And a token placed for another build than the one the caller names now is
    // treated as absent too. The header is the caller's current word and the
    // token its word from before: a caller that moved its pin and still sends
    // the old token asks for the new build, and is placed there — never kept on
    // the old one by a token that would then be minted afresh for it.
    let placed = token
        .as_deref()
        .and_then(|token| keys.placement(token, now))
        .filter(|placed| named.as_deref().is_none_or(|named| named == placed.build));
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

    let wanted = named.ok_or(NoRoute::Unspecified)?;

    let target = table.place(name, &wanted)?;
    let token = keys.mint(target.group, target.measurement, now);
    Ok((target, Some(token)))
}

/// Which build the caller requires.
///
/// It does not name what that build IS — this role knows only that a group
/// declares it and a leg proves it. So the header does not either.
///
/// A header for whoever can set one, and the value is FOR this hop — it
/// selects an upstream and then stops — so it is stripped before forwarding. A
/// navigation cannot set a header, so a link carries the same value in its
/// marker instead, which is stripped the same way — see [`marked_in_path`].
pub const MEASUREMENT: &str = "x-enclavid-measurement";

/// What marks a group's label in a path, so it can never be mistaken for a
/// segment api published.
///
/// api's own paths begin with ordinary words, and `api` is a perfectly good
/// label — an unmarked first segment would make `/api/v1/…` read as the group
/// `api`. The marker is what lets this role take a label out of a path without
/// holding any knowledge of what api's paths look like.
const MARK: char = '-';

/// What separates the label from the build inside a marker. No label may
/// contain one, so the first is the only one.
const BUILD_MARK: char = '.';

/// A group as a link carries it: its label and the build it runs.
///
/// What the placement response hands back, so a caller writing a link for
/// someone else writes exactly what this role will compare — see
/// [`marked_in_path`].
fn marker(label: &str, build: &str) -> String {
    format!("{label}{BUILD_MARK}{build}")
}

/// A label and the build it was written for, as a link carries them.
struct Marked {
    label: String,
    build: String,
}

/// The marker a link carries, removed on the way through so api sees the path
/// it published.
///
/// A path with no marker is not an error here — it is a caller that will be
/// routed by token or placed by the build it names. A marker WITHOUT a build
/// is: routing it would follow the label wherever the host declared it, which
/// is the one thing the build is there to stop.
fn marked_in_path<B>(req: &mut Request<B>) -> Result<Option<Marked>, NoRoute> {
    let Some(rest) = req
        .uri()
        .path()
        .strip_prefix('/')
        .and_then(|path| path.strip_prefix(MARK))
    else {
        return Ok(None);
    };
    let (segment, rest) = rest.split_once('/').unwrap_or((rest, ""));
    let Some((label, build)) = segment.split_once(BUILD_MARK) else {
        return Err(NoRoute::Unspecified);
    };
    if label.is_empty() || build.is_empty() {
        return Err(NoRoute::Unspecified);
    }
    let marked = Marked {
        label: label.to_owned(),
        build: build.to_owned(),
    };
    let rest = rest.to_owned();

    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    // Only the path and query are replaced, and the rest put back as it came,
    // so the target stays one `from_parts` accepts; the scheme and authority
    // are written afresh later anyway — see [`addressed`].
    //
    // A marker that cannot be taken out is refused rather than forwarded: api
    // would see a path it never published, and the marker would travel on.
    let mut parts = req.uri().clone().into_parts();
    match format!("/{rest}{query}").parse() {
        Ok(stripped) => {
            parts.path_and_query = Some(stripped);
            match hyper::Uri::from_parts(parts) {
                Ok(uri) => {
                    *req.uri_mut() = uri;
                    Ok(Some(marked))
                }
                Err(e) => {
                    debug!("could not put the path back together: {e}");
                    Err(NoRoute::Unspecified)
                }
            }
        }
        Err(e) => {
            debug!("could not take the marker out of the path: {e}");
            Err(NoRoute::Unspecified)
        }
    }
}

/// TCP arm only: the fixture declares TCP member addresses. Routing alone —
/// nothing here opens a leg.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use crate::config::testing::TUNING;
    use crate::upstream::tests::{A, FIRST, pushed};

    /// Which hosts a request may name and still be asked of its connection's,
    /// and which it may not name at all.
    #[test]
    fn a_request_names_its_connection_s_host_or_another() {
        let asked = |target: &str, hosts: &[&str]| {
            let mut request = Request::get(target);
            for host in hosts {
                request = request.header(hyper::header::HOST, *host);
            }
            names_another(&request.body(()).unwrap(), FIRST).map_err(|Unreadable| ())
        };
        let upper = FIRST.to_ascii_uppercase();
        let dotted = format!("{FIRST}.");
        let with_port = format!("{FIRST}:8443");
        for (target, hosts) in [
            ("/", vec![]),
            ("/", vec![FIRST]),
            ("/", vec![upper.as_str()]),
            ("/", vec![dotted.as_str()]),
            ("/", vec![with_port.as_str()]),
        ] {
            assert_eq!(asked(target, &hosts), Ok(false), "{target} {hosts:?}");
        }
        let here = format!("https://{upper}:8443/");
        assert_eq!(asked(&here, &[]), Ok(false));

        let there = "https://second.example.com/";
        assert_eq!(asked(there, &[]), Ok(true));
        assert_eq!(
            asked(there, &[FIRST]),
            Ok(true),
            "the target is not overruled"
        );
        assert_eq!(asked("/", &["second.example.com"]), Ok(true));

        assert_eq!(asked("/", &[FIRST, FIRST]), Err(()), "two hosts");
        assert_eq!(asked("/", &["not a host"]), Err(()));
    }

    /// Two groups running one build: two key domains a session must not move
    /// between, since its state opens in one of them only.
    fn two_groups_on_one_build() -> Upstreams {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }}, "two": {{ "measurement": "{A}" }} }},
              "names": {{ "{FIRST}": {{ "one": ["127.0.0.1:1000"], "two": ["127.0.0.1:2000"] }} }},
              "affinity": {{ "key": "{}", "ttl_seconds": 600 }}, {TUNING} }}"#,
            "1".repeat(64)
        );
        Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&body))
    }

    fn asking(token: Option<&str>, named: Option<&str>) -> Request<()> {
        let mut request = Request::get(format!("https://{FIRST}/api/v1/sessions/1"));
        if let Some(token) = token {
            request = request.header(affinity::TOKEN_HEADER, token);
        }
        if let Some(named) = named {
            request = request.header(MEASUREMENT, named);
        }
        request.body(()).unwrap()
    }

    /// A caller sending its pin and its token on every request keeps the group
    /// the token names — placed afresh each time, it would land on either, and
    /// its session opens on one only.
    #[tokio::test]
    async fn a_token_for_the_named_build_keeps_its_group() {
        let table = two_groups_on_one_build();
        let (placed, token) = route(&table, FIRST, &mut asking(None, Some(A)))
            .ok()
            .unwrap();
        let (group, token) = (placed.group.to_owned(), token.unwrap());

        for _ in 0..32 {
            let (target, _) = route(&table, FIRST, &mut asking(Some(&token), Some(A)))
                .ok()
                .unwrap();
            assert_eq!(target.group, group);
        }
    }
}
