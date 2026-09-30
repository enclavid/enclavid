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
//! There is one way a request finds its group, from one of two inputs: a label
//! and a build marked in the path, or — without one — a build the caller names,
//! against which this role places it and says where, in [`GROUP_HEADER`].
//! Nothing here knows what kind of caller it is serving; a caller either knows
//! its group or is given one, and then names it from there on.
//!
//! A browser typed at the bare name has neither, and reads no header. Where a
//! rule says so, it is sent to a page on another origin — never into a group,
//! whose build the host would then have chosen for it; see
//! [`Route::external_origin_redirect_307_to`].
//!
//! Whichever way a request arrives, the build it carries is compared to what
//! its label runs NOW, so the caller's one choice binds every later request
//! rather than only the first. A label is the host's to re-declare; a build is
//! not. Without the build beside it, a label in a link would follow a push onto
//! whatever the host declared under it, and the page, the bearer and every
//! upload would go there with it. That the state is sealed to the build that
//! made it protects the state, not the data still in flight.
//!
//! ## Where a request may name its group, and where it must
//!
//! Which of the two a request may use is api's business: only api knows which
//! requests create a session and which are about one. So it is the host's to
//! say, per name, in the push — see [`Rules`] — and not this file's, which would
//! otherwise hold a copy of api's routes in a measured image. A request that
//! creates a session is marked to be placed, so a caller cannot pile every
//! session into the group it prefers; a request about one is marked to name its
//! group, so one that forgot is refused rather than placed where its session is
//! not. A push that says nothing leaves both to the caller: what a rule governs
//! is balance, never what a leg proves.
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
//! The marker a link carries is stripped on the way through. The rest of the
//! path is matched against the name's [`Rules`], which say whether the request
//! may name its group, which builds take no new session there, and where one
//! naming nothing is sent instead, and goes on to api as it came; the query is
//! not read at all. The target goes on as `https://` and the name
//! the connection agreed to, and the caller's own `Host` stops here, since the
//! handshake's name is the one routed by. A request that names a different
//! host than that one is not routed at all: it is refused with 421, as a
//! request on a connection this role does not serve is. The measurement header
//! names a choice this hop makes and is removed, whichever way the request is
//! routed.
//!
//! Nothing about where the caller is reaches api either — not what the host's
//! first hop said, and not what the caller says itself. api holds the session
//! id, and an address beside it would link who to which session inside the
//! enclave. The source the first hop names stays in `crate::listener::source`,
//! as a keyed hash that counts a share. The headers in which a request gives an
//! account of its own origin are taken off — see [`FORWARDING`] — and so are
//! its trailers, where any header could travel instead — see
//! `crate::listener::body`.
//!
//! ## One origin, and no worker in it
//!
//! Every build this role reaches answers under the one origin of the name, a
//! group being a path rather than a name — so a page from any build a browser
//! is sent to stands beside every other build's pages in that browser. The one
//! thing a page can leave behind that goes on answering in their place, a
//! service worker, is refused here, whatever build it would come from: its
//! script is never fetched — see [`installs_a_worker`].

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use matchit::{InsertError, Router};
use safe_logger::debug;
use tokio::sync::watch;

use crate::config::{Naming, Route};
use crate::identity::{account, attest};
use crate::upstream::member::Sent;
use crate::upstream::{NoRoute, Upstreams};

/// Where a caller placed by this role is told which group it went to, in the
/// form a link carries it — `<label>.<build>` — so that it names that group
/// from then on, and writes links for others with exactly that.
pub const GROUP_HEADER: &str = "x-enclavid-group";

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
    /// The ACME account's public key, as a JWK — see `crate::identity::account`.
    account: Bytes,
}

impl Hop {
    pub fn new(
        table: watch::Receiver<Arc<Upstreams>>,
        evidence: attest::Evidence,
        account: Bytes,
    ) -> Hop {
        Hop {
            table,
            evidence,
            account,
        }
    }

    /// Respond to one request that arrived on a connection which agreed to
    /// `agreed`, its body already bounded by `crate::listener`.
    pub async fn respond(&self, agreed: &str, req: Request<Sent>) -> Response<ResponseBody> {
        // First, before any path this role answers itself: a worker's script is
        // refused wherever it would come from.
        if installs_a_worker(&req) {
            return refuse(StatusCode::FORBIDDEN);
        }
        if req.uri().path() == attest::PATH {
            return own(&req, self.evidence.clone(), attest::CONTENT_TYPE);
        }
        if req.uri().path() == account::PATH {
            return own(&req, self.account.clone(), account::CONTENT_TYPE);
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
        // A target whose path does not begin with `/` names a host alone or
        // is `*` — forms for opening a tunnel and for asking a server about
        // itself, and this role does neither. Refused before anything reads
        // the path, so the rules below match what api would be sent.
        if !req.uri().path().starts_with('/') {
            return refuse(StatusCode::BAD_REQUEST);
        }
        if let Some(slashed) = slashed(&req) {
            return redirected(&slashed);
        }

        let mut req = req;
        let (target, placed) = match route(&table, &name, &mut req) {
            Ok(Routed::Forward(target, placed)) => (target, placed),
            Ok(Routed::Away(location)) => return sent_away(&location),
            // 400, because the request is missing something only the caller can
            // supply, or carries what a rule says it may not. Naming a build is
            // not a formality here — it is the whole of what this role checks on
            // the caller's behalf.
            Err(NoRoute::Unspecified | NoRoute::AgainstRule) => {
                return refuse(StatusCode::BAD_REQUEST);
            }
            // 410: this build takes no new sessions here, so the caller names
            // another rather than trying again — which a 502 would invite, and
            // a 400 would not tell apart from a request it got wrong. It says
            // only that the build is declared and closed, which its links
            // answering already say. Not quite RFC 9110's "likely permanent":
            // a later push can reopen it, which is why it is not to be cached.
            Err(NoRoute::Refused) => {
                let mut gone = refuse(StatusCode::GONE);
                gone.headers_mut().insert(
                    hyper::header::CACHE_CONTROL,
                    hyper::header::HeaderValue::from_static("no-store"),
                );
                return gone;
            }
            Err(NoRoute::NoSuchGroup) => return refuse(StatusCode::BAD_GATEWAY),
            // 404: not a group's to answer, and not one of this role's paths.
            Err(NoRoute::Own) => return refuse(StatusCode::NOT_FOUND),
        };
        let told = placed.then(|| marker(target.group, target.measurement));
        if addressed(&mut req, &name).is_none() {
            return refuse(StatusCode::BAD_REQUEST);
        }
        unforwarded(&mut req);

        let Ok(response) = target.members.send(req).await else {
            return refuse(StatusCode::BAD_GATEWAY);
        };

        let (mut head, body) = response.into_parts();
        // Said on the way back whenever this role did the choosing: the group
        // this request went to, which the caller names from then on.
        if let Some(group) = told {
            match group.parse() {
                Ok(value) => {
                    head.headers.insert(GROUP_HEADER, value);
                }
                Err(e) => debug!("could not write {GROUP_HEADER}: {e}"),
            }
        }
        Response::from_parts(head, body.boxed())
    }
}

/// Whether `req` fetches a service worker's script: a browser marks that fetch
/// `Service-Worker: script`, and `Sec-Fetch-Dest: serviceworker` beside it,
/// which no page can write.
///
/// A worker outlives the page that registered it, may be scoped to the whole
/// origin by the header its script comes back with, and then stands between
/// the browser and every page of that origin — every group's, the sessions it
/// opens later with other consumers included. Refusing its script refuses the
/// worker, so no build this role reaches, a host's own among them, can leave
/// one behind.
fn installs_a_worker<B>(req: &Request<B>) -> bool {
    req.headers().contains_key("service-worker")
        || req
            .headers()
            .get_all("sec-fetch-dest")
            .iter()
            .any(|dest| dest.as_bytes().eq_ignore_ascii_case(b"serviceworker"))
}

/// The space this role keeps for what it says about itself: its two paths are
/// in it, and no request under it reaches api — not under a link's marker, not
/// spelled another way. A quote served there by a build the host declared
/// would carry that build's measurement, which a caller checking this role's
/// refuses; kept out, there is none to check.
pub const OWN: &str = "/.well-known/enclavid-";

/// One of this role's own paths — its quote, or its ACME account's key —
/// responded to with `body` without reaching api at all.
///
/// They are the only paths this build knows, and [`OWN`] the only space it
/// keeps: what a request for anything else means is the host's configuration,
/// never this file's.
fn own<B>(req: &Request<B>, body: Bytes, content_type: &'static str) -> Response<ResponseBody> {
    if req.method() != "GET" && req.method() != "HEAD" {
        let mut refused = refuse(StatusCode::METHOD_NOT_ALLOWED);
        refused.headers_mut().insert(
            hyper::header::ALLOW,
            hyper::header::HeaderValue::from_static("GET, HEAD"),
        );
        return refused;
    }
    let mut response = Response::new(fixed(body));
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        hyper::header::HeaderValue::from_static(content_type),
    );
    // Both are checked, not cached: a caller that keeps one and compares it to
    // a certificate from a later connection is checking a binding that was
    // true elsewhere.
    headers.insert("cache-control", "no-store".parse().expect("a constant"));
    response
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
///
/// The path is the caller's, as the rules read it: a target without one was
/// refused before routing.
fn addressed<B>(req: &mut Request<B>, name: &str) -> Option<()> {
    let mut parts = std::mem::take(req.uri_mut()).into_parts();
    parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
    parts.authority = Some(name.parse().ok()?);
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

/// Where a link's marker with nothing after it — `/-<label>.<build>` — is sent:
/// the same marker with a slash, the query kept.
///
/// The page served under a marker refers to what it loads relatively, and a
/// browser resolves those references against the path up to its last slash.
/// Without one that is the root, where nothing is routed, so the page would
/// load and nothing it needs would. A path of its own, never a host, so the
/// redirect leaves the caller where it was.
fn slashed<B>(req: &Request<B>) -> Option<String> {
    let path = req.uri().path();
    let marker = path.strip_prefix('/')?.strip_prefix(MARK)?;
    if marker.is_empty() || marker.contains('/') {
        return None;
    }
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    Some(format!("{path}/{query}"))
}

/// A permanent redirect to `location`, a path on this same name, keeping the
/// method — see [`slashed`].
fn redirected(location: &str) -> Response<ResponseBody> {
    redirect(StatusCode::PERMANENT_REDIRECT, location)
}

/// A temporary redirect to `location`, a page on another origin a rule names —
/// see [`Route::external_origin_redirect_307_to`].
///
/// Temporary and not to be stored: the page is the rule's as of this push, and
/// a later one may name another, while a redirect kept in a cache would go on
/// sending a browser there. No referrer, so the other site is told nothing of
/// where the browser came from.
fn sent_away(location: &str) -> Response<ResponseBody> {
    let mut response = redirect(StatusCode::TEMPORARY_REDIRECT, location);
    let headers = response.headers_mut();
    headers.insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        hyper::header::REFERRER_POLICY,
        hyper::header::HeaderValue::from_static("no-referrer"),
    );
    response
}

/// A redirect to `location` with `status`, and no body.
fn redirect(status: StatusCode, location: &str) -> Response<ResponseBody> {
    let Ok(location) = hyper::header::HeaderValue::from_str(location) else {
        return refuse(StatusCode::BAD_REQUEST);
    };
    let mut response = refuse(status);
    response
        .headers_mut()
        .insert(hyper::header::LOCATION, location);
    response
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

/// Where [`route`] sends a request.
enum Routed<'a> {
    /// On to a group — `true` beside it when this role did the choosing: that
    /// caller is told where it went, and a caller that already knew its group
    /// needs nothing said to it.
    Forward(crate::upstream::Target<'a>, bool),
    /// Off this origin, to this page — see
    /// [`Route::external_origin_redirect_307_to`].
    Away(String),
}

/// The one rule: where this request goes, and whether this role chose it.
///
/// Two inputs. A label and a build marked in the path are what a link carries,
/// and a browser can send nothing else on a navigation. Without one, the caller
/// must name the build it requires, and this role chooses among the groups
/// running it — or, where a rule sends a request naming nothing to a page
/// elsewhere, sends it there. Which the request may use is what the name's
/// rules say about its method and path — see [`Rules`].
fn route<'a, B>(
    table: &'a Upstreams,
    name: &str,
    req: &mut Request<B>,
) -> Result<Routed<'a>, NoRoute> {
    // Taken off the request FIRST, before any branch below can return — every
    // branch that forwards the request would carry it, and it names a choice
    // this hop makes that api has no use for. Whether the build was named at
    // all, and more than once, is noted before the header goes, because it
    // cannot be told after.
    let named_at_all = req.headers().contains_key(MEASUREMENT);
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

    let marked = marked_in_path(req)?;

    // This role's own paths were answered before routing; the rest of its
    // space is answered nowhere — see [`OWN`].
    if req.uri().path().starts_with(OWN) {
        return Err(NoRoute::Own);
    }

    // The name's rules, for the path as api will see it — the marker is out of
    // it by now.
    let terms = table
        .rules(name)
        .and_then(|rules| rules.terms(req.method(), req.uri().path()));
    let naming = terms.and_then(|terms| terms.naming);
    if marked.is_some() && naming == Some(Naming::Forbidden) {
        return Err(NoRoute::AgainstRule);
    }
    if marked.is_none() && naming == Some(Naming::Required) {
        return Err(NoRoute::AgainstRule);
    }
    // Named nothing, not even a build — one named in a form that cannot be
    // read is still named, and refused below: sent away if the rule says so.
    // The page is the rule's alone — nothing of this request goes into it, the
    // query included — and it carries a fragment, empty, so that the one this
    // request was made from does not travel on with it: a browser keeps a
    // fragment across a redirect whose target has none, and a link that lost
    // its marker would take its session id to another site.
    if marked.is_none()
        && !named_at_all
        && let Some(away) = terms.and_then(|terms| terms.away.as_deref())
    {
        return Ok(Routed::Away(format!("{away}#")));
    }

    if let Some(marked) = marked {
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
        return Ok(Routed::Forward(target, false));
    }

    let wanted = named.ok_or(NoRoute::Unspecified)?;
    // A build that takes no new sessions. The ones it holds carry their group
    // in their links, so they came in by the branch above and never reach this.
    if terms.is_some_and(|terms| terms.refused.contains(&wanted)) {
        return Err(NoRoute::Refused);
    }
    let target = table.place(name, &wanted)?;
    Ok(Routed::Forward(target, true))
}

/// What one name's requests are held to, by method and path, as the push
/// declared it — see [`crate::config::Route`].
///
/// A path is matched as api's own router matches it, by the same router: a
/// rule copied from api's route matches exactly the requests that route does,
/// on the same raw path, and which of two overlapping rules is the more
/// specific is decided the way api decides it. Nothing here parses a template
/// of its own.
///
/// One router per method a rule names, holding that method's rules and every
/// rule naming none, and one holding only those, for every other method. So a
/// request is matched only against the rules that could hold it, and the most
/// specific of THOSE decides — a rule for another method on a more specific
/// path does not hide one naming none on a broader path.
///
/// A `HEAD` is a `GET` without its body, and api serves it with the `GET` of
/// the route it matches. So where `GET` is named, `HEAD` is too, and on every
/// path no rule for `HEAD` names, it is held to the rule for `GET`.
#[derive(Clone)]
pub struct Rules {
    by_method: HashMap<Method, Router<Terms>>,
    otherwise: Router<Terms>,
}

/// What the rule matching a request holds it to: whether it must name its
/// group, the builds it places no new session on, and the page one naming
/// nothing is sent to.
#[derive(Clone)]
struct Terms {
    naming: Option<Naming>,
    refused: Vec<String>,
    away: Option<String>,
}

/// Rules as the push lists them: each beside its place in the list, for a
/// reason to point at.
type Listed<'a> = [(usize, &'a Route)];

impl Rules {
    /// The rules one name's routes declare, or why they cannot be held: a path
    /// that is not a template, or two rules a request could not choose between.
    /// The push has checked the rest — a path beginning with `/`, a method in
    /// capitals — before this is asked.
    ///
    /// A reason begins at the rule it is about, `[<index>]`, for the caller to
    /// put the name in front of.
    pub fn new(routes: &[Route]) -> Result<Rules, String> {
        // In the order the push first names each method, so which of two
        // faults is reported does not depend on a hash.
        let mut unnamed = Vec::new();
        let mut methods: Vec<(Method, Vec<(usize, &Route)>)> = Vec::new();
        for (i, route) in routes.iter().enumerate() {
            let Some(method) = &route.method else {
                unnamed.push((i, route));
                continue;
            };
            let method = Method::from_bytes(method.as_bytes())
                .map_err(|_| format!("[{i}].method: not a method"))?;
            match methods.iter_mut().find(|(named, _)| *named == method) {
                Some((_, own)) => own.push((i, route)),
                None => methods.push((method, vec![(i, route)])),
            }
        }
        let is_named = |wanted: &Method| methods.iter().any(|(method, _)| method == wanted);
        if is_named(&Method::GET) && !is_named(&Method::HEAD) {
            methods.push((Method::HEAD, Vec::new()));
        }

        let mut by_method = HashMap::new();
        for (method, own) in &methods {
            let get: &Listed = match *method == Method::HEAD {
                true => methods
                    .iter()
                    .find(|(named, _)| *named == Method::GET)
                    .map_or(&[], |(_, get)| get),
                false => &[],
            };
            by_method.insert(method.clone(), router(&[own, get, &unnamed])?);
        }
        Ok(Rules {
            by_method,
            otherwise: router(&[&unnamed])?,
        })
    }

    /// The terms of the most specific rule matching `method` and `path`, or
    /// none.
    fn terms(&self, method: &Method, path: &str) -> Option<&Terms> {
        self.by_method
            .get(method)
            .unwrap_or(&self.otherwise)
            .at(path)
            .ok()
            .map(|matched| matched.value)
    }

    /// Whether a group must be named, alone, for the tests that are about
    /// nothing else.
    #[cfg(test)]
    fn naming(&self, method: &Method, path: &str) -> Option<Naming> {
        self.terms(method, path).and_then(|terms| terms.naming)
    }
}

/// One router of rules in `tiers`, where a rule stands in for any in a later
/// tier on the same path: the method's own over one it takes from `GET`, and
/// either over one naming no method — the most specific wins, and naming the
/// method is the more specific. Two in one tier on one path are a clash.
fn router(tiers: &[&Listed]) -> Result<Router<Terms>, String> {
    let mut router = Router::new();
    let mut taken: Vec<&str> = Vec::new();
    for tier in tiers {
        let before = taken.len();
        for &(i, route) in *tier {
            if taken[..before].contains(&route.path.as_str()) {
                continue;
            }
            held(&mut router, i, route)?;
            taken.push(&route.path);
        }
    }
    Ok(router)
}

/// The most `{name}`s a rule's path may hold.
///
/// The router's own limit, not a choice made here: it renames each `{name}` to
/// a letter, from `a`, and panics once the next letter would be past `z` —
/// which it checks after taking one, so the 26th already panics. A panic in a
/// push drops the connection without a response, so a path past this is
/// refused before the router sees it, and the sender is told why.
const MOST_OPEN: usize = 25;

/// `route`, the `i`th of its name's, put into `router`, or why it cannot be.
fn held(router: &mut Router<Terms>, i: usize, route: &Route) -> Result<(), String> {
    // Every brace counts, an escaped one and a `{*rest}` as well. That only
    // refuses a path nobody writes.
    if route.path.matches('{').count() > MOST_OPEN {
        return Err(format!("[{i}].path: at most {MOST_OPEN} {{name}}s"));
    }
    router
        .insert(
            route.path.as_str(),
            Terms {
                naming: route.group,
                refused: route.refuse_measurements.clone(),
                away: route.external_origin_redirect_307_to.clone(),
            },
        )
        .map_err(|e| {
            let why = match e {
                InsertError::Conflict { with } => format!(
                    "overlaps {with}: a request matching both could not be told which \
                     holds — one path written twice, whatever its {{names}}, or one \
                     segment left open by {{name}} in one and {{*name}} in the other"
                ),
                InsertError::InvalidParam => {
                    "a {name} is closed and names something; a brace itself is {{ or }}".into()
                }
                InsertError::InvalidParamSegment => {
                    "one {name} to a segment, and nothing after it there".into()
                }
                InsertError::InvalidCatchAll => "a {*name} ends the path".into(),
                other => other.to_string(),
            };
            format!("[{i}].path: {why}")
        })
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
/// placed by the build it names, where the rules allow it. A marker WITHOUT a
/// build is: routing it would follow the label wherever the host declared it,
/// which is the one thing the build is there to stop.
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

/// Routing alone — nothing here opens a leg — so in every build.
#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::testing::TUNING;
    use crate::upstream::tests::{A, B, FIRST, at, pushed};

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

    /// Two groups running one build — two sets a session must not move
    /// between — under a name whose rules say that creating a session is placed
    /// and a request about one names its group.
    fn two_groups_on_one_build() -> Upstreams {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }}, "two": {{ "measurement": "{A}" }} }},
              "names": {{ "{FIRST}": {{ "one": ["{}"], "two": ["{}"] }} }},
              "routes": {{ "{FIRST}": [
                {{ "method": "POST", "path": "/api/v1/sessions", "group": "forbidden" }},
                {{ "path": "/api/v1/sessions/{{*rest}}", "group": "required" }} ] }},
              {TUNING} }}"#,
            at(1000),
            at(2000),
        );
        Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&body))
    }

    /// A request for `path` on the name, with `method`, naming `build` if any.
    fn asking(method: Method, path: &str, build: Option<&str>) -> Request<()> {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("https://{FIRST}{path}"));
        if let Some(build) = build {
            request = request.header(MEASUREMENT, build);
        }
        request.body(()).unwrap()
    }

    /// Creating a session is placed by this role, and told where it went; one
    /// that names its group is refused rather than let pile into it.
    #[test]
    fn a_creation_is_placed_and_may_not_name_its_group() {
        let table = two_groups_on_one_build();
        let placed = route(
            &table,
            FIRST,
            &mut asking(Method::POST, "/api/v1/sessions", Some(A)),
        );
        assert!(matches!(placed, Ok(Routed::Forward(_, true))));

        let named = route(
            &table,
            FIRST,
            &mut asking(Method::POST, &format!("/-one.{A}/api/v1/sessions"), None),
        );
        assert!(matches!(named, Err(NoRoute::AgainstRule)));
    }

    /// A request about a session goes to the group it names, and one that
    /// names none is refused rather than placed where that session is not.
    #[test]
    fn a_request_about_a_session_must_name_its_group() {
        let table = two_groups_on_one_build();
        let unnamed = route(
            &table,
            FIRST,
            &mut asking(Method::GET, "/api/v1/sessions/1", Some(A)),
        );
        assert!(matches!(unnamed, Err(NoRoute::AgainstRule)));

        for _ in 0..16 {
            let named = route(
                &table,
                FIRST,
                &mut asking(Method::GET, &format!("/-two.{A}/api/v1/sessions/1"), None),
            );
            assert!(matches!(named, Ok(Routed::Forward(target, false)) if target.group == "two"));
        }
    }

    /// Where no rule speaks, both are the caller's: placed by the build it
    /// names, or routed to the group it names.
    #[test]
    fn a_path_no_rule_matches_may_do_either() {
        let table = two_groups_on_one_build();
        let placed = route(
            &table,
            FIRST,
            &mut asking(Method::GET, "/elsewhere", Some(A)),
        );
        assert!(matches!(placed, Ok(Routed::Forward(_, true))));
        let named = route(
            &table,
            FIRST,
            &mut asking(Method::GET, &format!("/-one.{A}/elsewhere"), None),
        );
        assert!(matches!(named, Ok(Routed::Forward(target, false)) if target.group == "one"));
    }

    /// One group running a build that takes no new sessions, beside one running
    /// the build that replaced it.
    fn a_build_closed_beside_a_new_one() -> Upstreams {
        let body = format!(
            r#"{{
              "groups": {{ "old": {{ "measurement": "{A}" }}, "new": {{ "measurement": "{B}" }} }},
              "names": {{ "{FIRST}": {{ "old": ["{}"], "new": ["{}"] }} }},
              "routes": {{ "{FIRST}": [
                {{ "method": "POST", "path": "/api/v1/sessions", "group": "forbidden",
                   "refuse_measurements": ["{A}"] }},
                {{ "path": "/api/v1/sessions/{{*rest}}", "group": "required" }} ] }},
              {TUNING} }}"#,
            at(1000),
            at(2000),
        );
        Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&body))
    }

    /// A closed build takes no new session and the one beside it does, while
    /// the closed build's links still reach its group.
    #[test]
    fn a_closed_build_takes_no_new_session_and_keeps_its_links() {
        let table = a_build_closed_beside_a_new_one();
        let closed = route(
            &table,
            FIRST,
            &mut asking(Method::POST, "/api/v1/sessions", Some(A)),
        );
        assert!(matches!(closed, Err(NoRoute::Refused)));
        let open = route(
            &table,
            FIRST,
            &mut asking(Method::POST, "/api/v1/sessions", Some(B)),
        );
        assert!(matches!(open, Ok(Routed::Forward(target, true)) if target.group == "new"));

        for _ in 0..16 {
            let link = route(
                &table,
                FIRST,
                &mut asking(Method::GET, &format!("/-old.{A}/api/v1/sessions/1"), None),
            );
            assert!(matches!(link, Ok(Routed::Forward(target, false)) if target.group == "old"));
        }
        let marked = route(
            &table,
            FIRST,
            &mut asking(Method::POST, &format!("/-old.{A}/api/v1/sessions"), None),
        );
        assert!(
            matches!(marked, Err(NoRoute::AgainstRule)),
            "a marker is refused before the list is read"
        );
    }

    /// No other spelling of a closed build is placed: the list is compared as
    /// placement compares, and every build a push declares is lowercase hex.
    #[test]
    fn a_closed_build_has_no_other_spelling() {
        let table = a_build_closed_beside_a_new_one();
        for spelled in [A.to_ascii_uppercase(), format!(" {A} ")] {
            let placed = route(
                &table,
                FIRST,
                &mut asking(Method::POST, "/api/v1/sessions", Some(&spelled)),
            );
            assert!(matches!(placed, Err(NoRoute::NoSuchGroup)), "{spelled}");
        }
    }

    /// Closed only where its rule holds: a path no rule matches still places a
    /// request naming it.
    #[test]
    fn a_closed_build_is_closed_only_where_the_rule_says() {
        let table = a_build_closed_beside_a_new_one();
        let placed = route(
            &table,
            FIRST,
            &mut asking(Method::GET, "/elsewhere", Some(A)),
        );
        assert!(matches!(placed, Ok(Routed::Forward(target, true)) if target.group == "old"));
    }

    /// The builds a rule refuses go with the rule that holds the request: the
    /// most specific, and for a HEAD the GET's.
    #[test]
    fn a_rule_s_refused_builds_follow_the_most_specific_rule() {
        let refusing = |method: Option<&str>, path: &str| Route {
            refuse_measurements: vec![A.to_owned()],
            ..rule(method, path, Naming::Forbidden)
        };
        let rules = Rules::new(&[
            refusing(Some("POST"), "/a/{*rest}"),
            rule(Some("POST"), "/a/b", Naming::Forbidden),
            refusing(Some("GET"), "/c"),
        ])
        .unwrap();
        let refused = |method: Method, path| {
            rules
                .terms(&method, path)
                .map(|terms| terms.refused.clone())
        };
        assert_eq!(refused(Method::POST, "/a/x"), Some(vec![A.to_owned()]));
        assert_eq!(refused(Method::POST, "/a/b"), Some(vec![]));
        assert_eq!(refused(Method::HEAD, "/c"), Some(vec![A.to_owned()]));
    }

    /// Where the bare name sends a page load that names nothing.
    const ELSEWHERE: &str = "https://elsewhere.example.org/from-verify";

    /// The bare name, where a page load that names nothing is sent to
    /// [`ELSEWHERE`]: two groups on two builds, and every other request to the
    /// name naming its group.
    fn page_loads_sent_elsewhere() -> Upstreams {
        let body = format!(
            r#"{{
              "groups": {{ "old": {{ "measurement": "{A}" }}, "new": {{ "measurement": "{B}" }} }},
              "names": {{ "{FIRST}": {{ "old": ["{}"], "new": ["{}"] }} }},
              "routes": {{ "{FIRST}": [
                {{ "method": "GET", "path": "/", "external_origin_redirect_307_to": "{ELSEWHERE}" }},
                {{ "path": "/", "group": "required" }},
                {{ "path": "/{{*rest}}", "group": "required" }} ] }},
              {TUNING} }}"#,
            at(1000),
            at(2000),
        );
        Upstreams::empty(crate::identity::attestor()).replaced(&pushed(&body))
    }

    /// Where `req` is sent away to, if it is.
    fn sent_to(table: &Upstreams, mut req: Request<()>) -> Option<String> {
        match route(table, FIRST, &mut req) {
            Ok(Routed::Away(location)) => Some(location),
            _ => None,
        }
    }

    /// A page load naming nothing is sent to the rule's page, and only to it:
    /// nothing of the request goes with it, its query included, and it carries
    /// a fragment of its own, so none the browser holds travels on. A `HEAD`
    /// is sent as its `GET` is.
    #[test]
    fn a_page_load_naming_nothing_is_sent_to_the_page_alone() {
        let table = page_loads_sent_elsewhere();
        let there = format!("{ELSEWHERE}#");
        for path in ["/", "/?session=1"] {
            assert_eq!(
                sent_to(&table, asking(Method::GET, path, None)).as_deref(),
                Some(there.as_str()),
                "{path}"
            );
        }
        assert_eq!(
            sent_to(&table, asking(Method::HEAD, "/", None)),
            Some(there)
        );
    }

    /// A link is routed by its marker, to whichever group it names, and a
    /// caller naming a build is placed by it: the rule sends only what names
    /// nothing at all.
    #[test]
    fn what_names_a_group_or_a_build_is_not_sent_away() {
        let table = page_loads_sent_elsewhere();
        for (label, build) in [("new", B), ("old", A)] {
            let linked = route(
                &table,
                FIRST,
                &mut asking(Method::GET, &format!("/-{label}.{build}/"), None),
            );
            assert!(
                matches!(linked, Ok(Routed::Forward(target, false)) if target.group == label),
                "{label}"
            );
        }
        let named = route(&table, FIRST, &mut asking(Method::GET, "/", Some(B)));
        assert!(matches!(named, Ok(Routed::Forward(target, true)) if target.group == "new"));

        // A build named in a form that cannot be read is named all the same,
        // and refused as it is anywhere a build must be named.
        let mut unreadable = asking(Method::GET, "/", None);
        unreadable.headers_mut().insert(
            MEASUREMENT,
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        let unreadable = route(&table, FIRST, &mut unreadable);
        assert!(matches!(unreadable, Err(NoRoute::Unspecified)));
    }

    /// Only the page load the rule names is sent: another method on the same
    /// path, and a page load on another, are held to the rules beside it.
    #[test]
    fn only_the_page_load_the_rule_names_is_sent() {
        let table = page_loads_sent_elsewhere();
        let posted = route(&table, FIRST, &mut asking(Method::POST, "/", None));
        assert!(matches!(posted, Err(NoRoute::AgainstRule)));
        let elsewhere = route(
            &table,
            FIRST,
            &mut asking(Method::GET, "/assets/x.js", None),
        );
        assert!(matches!(elsewhere, Err(NoRoute::AgainstRule)));
    }

    /// The page goes out as a temporary redirect nothing may keep, telling the
    /// other site nothing of where it came from, with no body.
    #[test]
    fn the_page_goes_out_as_a_redirect_nothing_keeps() {
        let location = format!("{ELSEWHERE}#");
        let response = sent_away(&location);
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers()[hyper::header::LOCATION],
            location.as_str()
        );
        assert_eq!(response.headers()[hyper::header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[hyper::header::REFERRER_POLICY],
            "no-referrer"
        );
        assert!(hyper::body::Body::is_end_stream(response.body()));
    }

    /// This role's own space reaches no group: under a link's marker, spelled
    /// another way, or at a path in it that is not one of this role's.
    #[test]
    fn this_role_s_own_space_reaches_no_group() {
        let table = two_groups_on_one_build();
        for path in [
            format!("/-one.{A}{}", attest::PATH),
            format!("/-one.{A}{}", account::PATH),
            format!("{}/", attest::PATH),
            format!("{OWN}anything"),
        ] {
            let routed = route(&table, FIRST, &mut asking(Method::GET, &path, Some(A)));
            assert!(matches!(routed, Err(NoRoute::Own)), "{path}");
        }
    }

    /// Both of this role's paths are in the space it keeps, where a push
    /// cannot send a request anywhere else.
    #[test]
    fn this_role_s_paths_are_in_its_own_space() {
        assert!(attest::PATH.starts_with(OWN));
        assert!(account::PATH.starts_with(OWN));
    }

    /// A worker's script is known by either mark a browser puts on its fetch,
    /// and nothing else is taken for one.
    #[test]
    fn a_worker_s_script_is_known_by_either_mark() {
        let fetched = |headers: &[(&str, &str)]| {
            let mut request = Request::get(format!("https://{FIRST}/sw.js"));
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            installs_a_worker(&request.body(()).unwrap())
        };
        assert!(fetched(&[("service-worker", "script")]));
        assert!(fetched(&[("sec-fetch-dest", "serviceworker")]));
        assert!(fetched(&[("sec-fetch-dest", "ServiceWorker")]));
        assert!(fetched(&[
            ("sec-fetch-dest", "script"),
            ("sec-fetch-dest", "serviceworker")
        ]));
        assert!(!fetched(&[]));
        assert!(!fetched(&[("sec-fetch-dest", "script")]));
        assert!(!fetched(&[("sec-fetch-dest", "worker")]));
    }

    /// A rule for the tests: `naming` on requests to `path`, made with `method`
    /// if one is named.
    fn rule(method: Option<&str>, path: &str, naming: Naming) -> Route {
        Route {
            method: method.map(str::to_owned),
            path: path.to_owned(),
            group: Some(naming),
            refuse_measurements: Vec::new(),
            external_origin_redirect_307_to: None,
        }
    }

    /// The most specific rule decides: a segment spelled out over one left
    /// open, and among rules with one path, the one naming its method.
    #[test]
    fn the_most_specific_rule_decides() {
        use Naming::{Forbidden, Required};
        let rules = Rules::new(&[
            rule(None, "/a/{*rest}", Required),
            rule(None, "/a/b/{*rest}", Forbidden),
            rule(None, "/a/b/c", Required),
            rule(None, "/u/{id}", Required),
            rule(None, "/u/me", Forbidden),
            rule(Some("POST"), "/a/{*rest}", Forbidden),
        ])
        .unwrap();
        let get = |path| rules.naming(&Method::GET, path);
        assert_eq!(get("/a/x"), Some(Required), "the path left open");
        assert_eq!(
            get("/a/b/x"),
            Some(Forbidden),
            "one more segment spelled out"
        );
        assert_eq!(get("/a/b/c"), Some(Required), "every segment spelled out");
        assert_eq!(get("/u/7"), Some(Required), "a segment left open");
        assert_eq!(
            get("/u/me"),
            Some(Forbidden),
            "the same segment spelled out"
        );
        assert_eq!(get("/u/7/x"), None, "one segment is not two");
        assert_eq!(get("/a"), None, "what follows is not nothing");
        assert_eq!(get("/b"), None, "no rule");

        let post = |path| rules.naming(&Method::POST, path);
        assert_eq!(post("/a/x"), Some(Forbidden), "the rule naming the method");
        assert_eq!(
            post("/a/b/c"),
            Some(Required),
            "a more specific path over the method"
        );
        assert_eq!(
            post("/u/7"),
            Some(Required),
            "the rules naming none still hold"
        );
    }

    /// A rule for another method on a more specific path does not hide one
    /// naming none on a broader path.
    #[test]
    fn a_rule_for_another_method_hides_nothing() {
        use Naming::{Forbidden, Required};
        let rules = Rules::new(&[
            rule(None, "/a/{*rest}", Required),
            rule(Some("POST"), "/a/b", Forbidden),
        ])
        .unwrap();
        assert_eq!(rules.naming(&Method::GET, "/a/b"), Some(Required));
        assert_eq!(rules.naming(&Method::POST, "/a/b"), Some(Forbidden));
        assert_eq!(rules.naming(&Method::DELETE, "/a/b"), Some(Required));
    }

    /// A `HEAD` is held to the rules for `GET`, unless a rule names it.
    #[test]
    fn a_head_is_held_as_a_get() {
        use Naming::{Forbidden, Required};
        let only_get = Rules::new(&[rule(Some("GET"), "/a", Required)]).unwrap();
        assert_eq!(only_get.naming(&Method::HEAD, "/a"), Some(Required));

        let rules = Rules::new(&[
            rule(Some("GET"), "/a", Required),
            rule(Some("GET"), "/b", Required),
            rule(Some("HEAD"), "/b", Forbidden),
            rule(Some("GET"), "/c", Required),
            rule(None, "/c", Forbidden),
            rule(None, "/d", Forbidden),
        ])
        .unwrap();
        assert_eq!(
            rules.naming(&Method::HEAD, "/b"),
            Some(Forbidden),
            "its own rule"
        );
        assert_eq!(
            rules.naming(&Method::HEAD, "/a"),
            Some(Required),
            "a rule for HEAD elsewhere leaves GET's here"
        );
        assert_eq!(
            rules.naming(&Method::HEAD, "/c"),
            Some(Required),
            "GET's over one naming none"
        );
        assert_eq!(
            rules.naming(&Method::HEAD, "/d"),
            Some(Forbidden),
            "one naming none"
        );
    }

    /// Two rules a request could not choose between are refused, whichever
    /// method they come under, and so is a path that is not a template.
    #[test]
    fn rules_a_request_could_not_choose_between_are_refused() {
        let refused = |routes: &[Route]| Rules::new(routes).err().expect("refused");
        let naming = Naming::Required;
        for (routes, says) in [
            (
                vec![rule(None, "/x", naming), rule(None, "/x", naming)],
                "[1].path: overlaps /x",
            ),
            (
                vec![rule(None, "/x/{a}", naming), rule(None, "/x/{b}", naming)],
                "[1].path: overlaps /x/{a}",
            ),
            (
                vec![
                    rule(None, "/x/{id}", naming),
                    rule(None, "/x/{*rest}", naming),
                ],
                "[1].path: overlaps /x/{id}",
            ),
            (
                vec![
                    rule(Some("POST"), "/x", naming),
                    rule(Some("POST"), "/x", naming),
                ],
                "[1].path: overlaps /x",
            ),
            (
                vec![
                    rule(Some("POST"), "/q/{a}", naming),
                    rule(None, "/q/{b}", naming),
                ],
                "[1].path: overlaps /q/{a}",
            ),
            (
                vec![rule(None, "/x/{bad", naming)],
                "[0].path: a {name} is closed",
            ),
            (
                vec![rule(None, "/x/{a}-b", naming)],
                "[0].path: one {name} to a segment",
            ),
            (
                vec![rule(None, "/x/{*a}/b", naming)],
                "[0].path: a {*name} ends",
            ),
        ] {
            let err = refused(&routes);
            assert!(err.starts_with(says), "{says}: {err}");
        }

        // One path under a method and under none is not a clash: the method's
        // stands in for the other where it applies.
        Rules::new(&[rule(Some("POST"), "/x", naming), rule(None, "/x", naming)]).unwrap();
    }
}
