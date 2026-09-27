//! One api instance: the connections open to it, and whether it can take work.
//!
//! ## Why connections live here and not beside the requests
//!
//! A leg is expensive to open — a dial through the host and an attested
//! handshake — and cheap to keep. So it is opened on demand, used by one request,
//! and parked here until the next one wants it. What follows from that is the
//! property the whole design turns on: **the number of connections to api
//! follows the number of requests IN FLIGHT, not the number of callers** — give
//! or take the legs parked since the last request, which are closed once they
//! have sat `leg_idle`, and of which there are never more than `parked_legs`
//! across every member — see [`PARKED_NOW`]. A thousand idle browsers hold a
//! thousand connections on the public side and none here.
//!
//! Every number here is the member's own `UpstreamTuning`, which it was built
//! with — see `crate::config`.
//!
//! The alternative — a leg per public connection — is what this role did
//! before, and it puts a caller's idleness on api's connection table.
//!
//! ## One request at a time on a leg
//!
//! A parked leg is taken, not shared. HTTP/2 would happily carry both requests
//! at once, and that is exactly what must not happen: the flow-control window
//! belongs to the CONNECTION, so a caller that stops reading freezes the other
//! responses on it; a `GOAWAY` takes down whatever else is in flight; the reset
//! budget is spent per connection. All of that needs two callers on one leg at
//! once, and taking the leg out of the stack is what prevents it.
//!
//! So the leg comes back when the RESPONSE BODY ends — see [`Returning`] — not
//! when the response head arrives. Returning it any earlier would put the next
//! request on a connection still streaming the last one. A request that never
//! gets a response — cancelled, timed out, or failed on its own stream — gives
//! its leg back too, unless the connection went with it — see [`Lent`].
//!
//! ## Nothing one caller sends is remembered for the next
//!
//! HTTP/2 compresses headers against a table each end keeps for the life of
//! the connection: a value goes in the first time it is sent, and after that it
//! is a reference of a byte or two. A leg carries one caller's request and then
//! another's, and the host, which carries the leg's bytes, sees how long each
//! one is. So a request shorter than it would have been alone says that an
//! earlier caller on the leg sent one of its values — a session token, which
//! links two requests to one session, or a language or a browser, which a
//! caller can guess at in its own request and read the answer off the length.
//!
//! So neither table is used. Every header a request carries goes over as one
//! never to be indexed — see [`unremembered`] — and the leg tells api it keeps
//! no table for responses, so api's responses cannot shape each other either.
//! What the table still takes is the request line: the name the connection
//! agreed to, which every request on one leg shares, and the method. The
//! library never indexes a path.
//!
//! ## Warmest first
//!
//! Legs are taken from the end of the stack, so a small working set stays hot
//! and the rest age out: every request closes the legs that have sat past
//! `leg_idle`, whichever one it takes — see [`take`] — and so does a timer, for
//! a member no request comes to — see [`sweep`]. Taking from the front would
//! keep every leg just barely alive and hold connections at api that nothing
//! needs.
//!
//! What that costs is said by the clock. A request that finds a parked leg
//! skips the dial and the attested handshake, so how long it takes tells its
//! caller whether some request used that member within the last `leg_idle`.
//! That is accepted. It says a member was busy, never whose request made it
//! so; and a pool that always dialled, or always waited out a dial, would pay
//! an attested handshake per request to hide it.
//!
//! ## Nothing asks a member whether it is well
//!
//! Requests are the only question. A member takes work from the moment a push
//! declares it, and the first request that picks it opens a leg through
//! [`connect`], which proves the build and the part — so a member the host
//! declared wrongly, or one that is not there, opens no leg for that request,
//! hands it back, and is left out for `cooldown` — long enough that a member
//! which is down is not asked by every request meanwhile, short enough that
//! one which has come back takes work again soon. After it, the next request
//! that picks it asks again.
//!
//! Opening is bounded whole by `open_timeout` — the dial and the handshake —
//! because either can hang, and it is the handshake that does the work.
//!
//! A probe dialling every member on a timer was the alternative. It paid an
//! attested handshake per member per turn for what traffic already proves, and
//! paid most when the set was busiest; and it still left a member that failed
//! real legs in rotation, because only its own response counted.
//!
//! Asking by request costs the caller nothing while another member is up. A
//! request whose leg would not open has not been sent anywhere, so the member
//! hands it back as [`NotSent`] and the set offers it again — see
//! `crate::upstream::balance`. A request that reached api is never sent again.
//!
//! Two things count against a member. One is a leg that would not OPEN. The
//! other is a response that did not START within `response_timeout` — counted
//! from when the body had all been sent, or from when it was due, for a body
//! api would not take; see [`BodyDue`]. Neither can be the caller's doing: the
//! first is a member that is not there, the second one that is there and
//! sends no response — whose legs stay open, and so would never come to be
//! opened again, which is what would have found it out. So a leg whose
//! response did not start in time is closed rather than parked, and the next
//! request to its member, after the cooldown, opens one afresh.
//!
//! Nothing else does. A request that fails sooner, on a leg that did open, may
//! have failed on its caller's account — a body that broke off — and its leg
//! goes back through [`Lent`].
//!
//! A request the HTTP library has taken is not handed back even when api never
//! acted on it — a stream api refused, or one past the last a closing api said
//! it would serve. By then the library holds the request and keeps no copy, and
//! its body may be streaming from the caller already, so there is nothing whole
//! to offer another member. Such a request fails as any other that reached a
//! leg. It happens when api restarts under a leg, and a restart is rare.
//!
//! And only when the member is why it would not open. A dial that fails because
//! THIS process is out of descriptors or memory says nothing about the member —
//! and counted against it, one such moment would leave every member of every
//! group out at once, responding to nobody long after the moment passed. So
//! such a request is handed back without leaving the member out — see
//! [`Unopened`].
//!
//! ## Out is pending, never an error
//!
//! While a member is out, [`tower::Service::poll_ready`] answers `Pending`, with
//! a timer for the end of the cooldown — never `Err`. The balancer discards a
//! service whose readiness FAILS and only discovery can put it back, so an error
//! here would turn a member that is briefly down into a member that is gone
//! until the next push.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use safe_logger::debug;

use super::{Proof, connect};
use crate::config::UpstreamTuning;

/// How many legs are parked right now, across every member — held under
/// `parked_legs`.
///
/// Legs in flight are bounded by the public ceilings, one per stream. Parked
/// ones are not: each member keeps its own stack, a caller steers requests into
/// whichever set it likes by the name it asks for and the label it writes, and
/// a burst leaves its legs parked where it ran. Bursts into one set after
/// another would pile them up until the process ran out of descriptors. So a
/// leg that would park past the ceiling is closed instead. Parking only saves
/// the next request a dial, so the ceiling costs latency, never a request.
static PARKED_NOW: AtomicUsize = AtomicUsize::new(0);

/// A parked leg's place under a ceiling, given back when the leg leaves its
/// stack — taken, aged out, or dropped with its member.
struct Place(&'static AtomicUsize);

impl Place {
    fn take(count: &'static AtomicUsize, ceiling: usize) -> Option<Place> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |now| {
                (now < ceiling).then_some(now + 1)
            })
            .ok()
            .map(|_| Place(count))
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How much of a response api may send on a leg before this role has read it.
///
/// A caller that stops reading stops this role reading too, so this is what one
/// such caller can leave in memory per stream, besides what waits on the public
/// side. Far below the HTTP library's default, which suits a slow network: the
/// leg crosses one machine, and a small window costs it nothing.
const WINDOW: u32 = 128 << 10;

/// What a request carries to api.
///
/// Boxed, so a leg does not name where a body came from. In service it is a
/// caller's own, streaming as it arrived under the bounds `crate::listener`
/// puts on it — and hyper offers no way to build one of those, so anything else
/// that sends over a leg, as the tests do, needs a body type it can build.
pub type Sent = BoxBody<Bytes, tower::BoxError>;

/// One attested HTTP/2 connection to a member, carrying one request at a time.
pub type Leg = SendRequest<Sent>;

/// When a request's body must have arrived whole, set by `crate::listener` as
/// the request's head arrives.
///
/// The body's own bounds are checked as it is read, and a leg reads it only as
/// fast as api takes it: once api stops taking it, nothing reads it and none of
/// those bounds is ever checked. So a member bounds that from outside the body,
/// with `response_timeout` counted from here. A request without one — a
/// test's — has only the wait from when its body was sent.
#[derive(Clone, Copy)]
pub struct BodyDue(pub tokio::time::Instant);

/// Why a request could not be carried to a member.
///
/// One variant, because the answer to the caller is one answer: which machines
/// exist and which of them are reachable is the host's business and changes
/// under it, so telling the causes apart would report the fleet's shape to
/// whoever asked. What the caller is told is `crate::route`'s to decide.
///
/// One in what it says, not in when it comes: a member that is down costs a
/// dial or a wait before this is returned, and a member that responded costs
/// nothing. The time is not padded — see `crate::route`.
#[derive(Debug)]
pub struct Unreachable;

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the member did not take the request")
    }
}

impl std::error::Error for Unreachable {}

/// Why a leg would not open, as far as it decides whether the member is out.
enum Unopened {
    /// The member, or the way to it: it is left out for `cooldown`.
    There,
    /// This process: out of descriptors — its own count or the kernel's — or
    /// memory. Nothing is learned about the member.
    Here,
}

impl Unopened {
    fn of(e: &std::io::Error) -> Unopened {
        match e.raw_os_error() {
            Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS) => Unopened::Here,
            _ => Unopened::There,
        }
    }
}

/// A request that never left: its leg would not open, so no byte of it reached
/// any api, and it can be given to another member unchanged.
///
/// The one outcome that hands the request back. Once any of it has been
/// written, whether api acted on it is unknown, and sending it again could do
/// twice what the caller asked for once.
pub struct NotSent(pub Request<Sent>);

/// Says nothing of the request it holds: its headers and path are the caller's,
/// and this is what a log line would print.
impl std::fmt::Debug for NotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NotSent")
    }
}

/// What a member does with a request it is offered: starts a response, or hands
/// the request back unsent.
///
/// A value rather than an error, so that giving the request to another member
/// is a match the compiler checks — see `crate::upstream::balance` — and not an
/// error inspected for a type it might hold.
pub type Offered = Result<Response<Returning>, NotSent>;

/// One member, as everything that deals with it shares it: the handle the
/// balancer holds, every request under way to it, and every body still arriving
/// from it.
struct Inner {
    addr: String,
    /// What a leg to this member must prove, shared with its group. The build in
    /// it is the CALLER's value, carried here from the table — see
    /// `crate::upstream`.
    proof: Arc<Proof>,
    /// The numbers this member runs by, from the push that built its set.
    tuning: UpstreamTuning,
    /// Legs that proved the build, waiting for the next request.
    idle: Mutex<Vec<Parked>>,
    /// Until when this member is out: set by a request whose leg would not
    /// open, and read by readiness.
    out: Mutex<Option<tokio::time::Instant>>,
    /// Whether [`sweep`] runs for this member. Started by the first request,
    /// because that is the first moment there can be a leg to close.
    swept: AtomicBool,
}

/// A leg that proved its build, waiting for the next request.
struct Parked {
    leg: Leg,
    since: Instant,
    _place: Place,
}

/// One api instance, as something a request can be handed to.
pub struct Member {
    inner: Arc<Inner>,
    /// While out: the timer that wakes the balancer when the cooldown ends.
    /// This handle's own, because readiness is asked through it alone; held
    /// rather than made per poll, because a timer made afresh each time would
    /// register a waker and drop it.
    cooling: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Member {
    /// A member, ready to take work — see the module docs for why nothing
    /// checks it first.
    pub fn new(addr: String, proof: Arc<Proof>, tuning: UpstreamTuning) -> Member {
        Member {
            inner: Arc::new(Inner {
                addr,
                proof,
                tuning,
                idle: Mutex::new(Vec::new()),
                out: Mutex::new(None),
                swept: AtomicBool::new(false),
            }),
            cooling: None,
        }
    }

    /// How many legs are parked. For the tests that pin the mapping between
    /// requests in flight and connections to api.
    #[cfg(all(test, not(feature = "vsock")))]
    pub fn parked(&self) -> usize {
        held(&self.inner.idle).len()
    }
}

/// A request handed back unsent is an [`Offered`] value; the one error is
/// [`Unreachable`], a request that may have reached api and is not sent again.
impl tower::Service<Request<Sent>> for Member {
    type Response = Offered;
    type Error = Unreachable;
    type Future = Pin<Box<dyn Future<Output = Result<Offered, Unreachable>> + Send>>;

    /// Ready unless a leg to this member would not open within the last
    /// `cooldown`; then pending, with a timer for the end of it. Never an
    /// error — see the module docs for what an error here would cost.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Unreachable>> {
        let out = *held(&self.inner.out);
        let Some(until) = out.filter(|until| *until > tokio::time::Instant::now()) else {
            self.cooling = None;
            return Poll::Ready(Ok(()));
        };
        let cooling = self
            .cooling
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(until)));
        // A later failure moves the end, and the timer follows it.
        if cooling.deadline() != until {
            cooling.as_mut().reset(until);
        }
        match cooling.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.cooling = None;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, mut req: Request<Sent>) -> Self::Future {
        let member = self.inner.clone();
        if !member.swept.swap(true, Ordering::Relaxed) {
            tokio::spawn(sweep(Arc::downgrade(&member)));
        }
        unremembered(&mut req);
        Box::pin(async move {
            // The response's deadline starts when the body has all been sent —
            // see `sent_whole` — and holds across every leg tried below. A body
            // api will not take is never sent, so it has a ceiling too: the
            // same wait, from when the body was due — see [`BodyDue`].
            let due = req.extensions().get::<BodyDue>().map(|due| due.0);
            let (mut req, sent) = sent_whole(req);
            let response_timeout = member.tuning.response_timeout;
            let responding = async move {
                let started = async move {
                    let _ = sent.await;
                    tokio::time::sleep(response_timeout).await;
                };
                match due {
                    Some(due) => tokio::select! {
                        () = started => {}
                        () = tokio::time::sleep_until(due + response_timeout) => {}
                    },
                    None => started.await,
                }
            };
            tokio::pin!(responding);

            loop {
                let (leg, opened) = match take(&member) {
                    Some(leg) => (leg, false),
                    None => match open(&member).await {
                        Ok(leg) => (leg, true),
                        Err(unopened) => {
                            // The one thing that counts against a member — see
                            // the module docs — and only when the member is
                            // the reason.
                            if let Unopened::There = unopened {
                                cool(&member);
                            }
                            // Either way nothing of the request has left, so it
                            // goes back whole, for the set to give to another
                            // member.
                            return Ok(Err(NotSent(req)));
                        }
                    },
                };
                let mut lent = Lent {
                    leg: Some(leg),
                    member: member.clone(),
                };
                let asked = lent
                    .leg
                    .as_mut()
                    .expect("lent until the head is back")
                    .try_send_request(req);
                let responded = tokio::select! {
                    responded = asked => responded,
                    () = &mut responding => {
                        // api's to answer for, either way: the body was all
                        // sent, or api would not take it. So the member is out,
                        // and the leg is closed rather than parked — a
                        // connection that carried no response may carry none
                        // again, and only a leg opened afresh finds that out.
                        debug!("a request to {} got no response in time", member.addr);
                        drop(lent.leg.take());
                        cool(&member);
                        return Err(Unreachable);
                    }
                };
                match responded {
                    Ok(response) => {
                        let leg = lent.leg.take().expect("lent until the head is back");
                        let (head, body) = response.into_parts();
                        return Ok(Ok(Response::from_parts(
                            head,
                            Returning {
                                body,
                                leg: Some(leg),
                                member,
                            },
                        )));
                    }
                    // Handed back: the leg's connection had gone before any of
                    // the request reached it — a leg parked a moment before its
                    // connection died, which the connection had not yet said.
                    // The leg is let go, and the request tries the next one.
                    Err(mut failed) => match failed.take_message() {
                        Some(back) => {
                            drop(lent.leg.take());
                            if opened {
                                // A leg that died as it was opened is the
                                // member's failure, as a leg that would not
                                // open is.
                                cool(&member);
                                return Ok(Err(NotSent(back)));
                            }
                            req = back;
                        }
                        None => {
                            debug!(
                                "a request to {} failed on its leg: {}",
                                member.addr,
                                failed.error()
                            );
                            return Err(Unreachable);
                        }
                    },
                }
            }
        })
    }
}

/// Mark every header `req` carries as one a leg's compression never indexes —
/// see the module docs.
fn unremembered(req: &mut Request<Sent>) {
    for value in req.headers_mut().values_mut() {
        value.set_sensitive(true);
    }
}

/// Leave `member` out for its cooldown.
fn cool(member: &Inner) {
    *held(&member.out) = Some(tokio::time::Instant::now() + member.tuning.cooldown);
}

/// The request, and what says its body has all been sent.
///
/// The response's deadline counts from there, not from when the request was
/// handed over: api reads a body whole before it responds, so a deadline that
/// counted the upload would cut off a large one arriving slowly — and the
/// upload has bounds of its own, in `crate::listener`. A body that fails, or
/// that the connection drops, counts as sent: nothing more of it is coming.
fn sent_whole(req: Request<Sent>) -> (Request<Sent>, tokio::sync::oneshot::Receiver<()>) {
    let (tell, told) = tokio::sync::oneshot::channel();
    let req = req.map(|body| {
        let mut watched = Watched {
            body,
            tell: Some(tell),
        };
        if watched.body.is_end_stream() {
            watched.done();
        }
        watched.boxed()
    });
    (req, told)
}

/// A request body that says when it is done.
struct Watched {
    body: Sent,
    tell: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Watched {
    fn done(&mut self) {
        if let Some(tell) = self.tell.take() {
            let _ = tell.send(());
        }
    }
}

impl Body for Watched {
    type Data = Bytes;
    type Error = tower::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, tower::BoxError>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.body).poll_frame(cx);
        if matches!(polled, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            this.done();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// A leg on loan to one request until its response's head is back.
///
/// Parked again if the request never gets that far — its caller went away, or
/// the request failed on its own stream — unless the connection went with it.
/// Dropped instead, it would close a connection that is still good, and a
/// caller cancelling request after request would have this role open an
/// attested leg for every one. The one leg that is taken back and closed is
/// one whose response did not start in time — see the module docs.
struct Lent {
    leg: Option<Leg>,
    member: Arc<Inner>,
}

impl Drop for Lent {
    fn drop(&mut self) {
        if let Some(leg) = self.leg.take() {
            park(&self.member, leg);
        }
    }
}

/// Put a leg back on its member's stack — or close it, if its connection has
/// gone or `parked_legs` are parked already.
fn park(member: &Inner, leg: Leg) {
    if leg.is_closed() {
        return;
    }
    let Some(place) = Place::take(&PARKED_NOW, member.tuning.parked_legs) else {
        return;
    };
    held(&member.idle).push(Parked {
        leg,
        since: Instant::now(),
        _place: place,
    });
}

/// One of a member's locks, taken whether or not a panic poisoned it.
///
/// What they guard — a stack of parked legs, the end of a cooldown — is whole
/// after every step that touches it, so a panic that poisoned one left nothing
/// half done behind it. Refusing it would be worse: [`park`] runs in the drops
/// of [`Lent`] and [`Returning`], and a drop that panics while another panic is
/// unwinding aborts the process, and every caller's connection with it.
fn held<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Take a usable parked leg — and close every leg that has sat past `leg_idle`
/// or whose connection has gone, whichever one is taken.
///
/// From the end: the most recently returned leg is the one most likely to still
/// be alive. The aged ones are closed across the whole stack rather than only
/// as they are popped past, because a request that finds a good leg on top
/// looks no further — without that, the legs beneath it would never go.
fn take(member: &Inner) -> Option<Leg> {
    let mut idle = held(&member.idle);
    close_aged(&mut idle, member.tuning.leg_idle);
    while let Some(parked) = idle.pop() {
        if parked.leg.is_ready() {
            return Some(parked.leg);
        }
    }
    None
}

/// Close the legs that have sat `idle` or whose connection has gone.
fn close_aged(parked: &mut Vec<Parked>, idle: Duration) {
    parked.retain(|parked| parked.since.elapsed() < idle && !parked.leg.is_closed());
}

/// Close aged legs on a timer, for as long as the member exists — every
/// `leg_idle`, so a leg nobody takes is gone within two of them.
///
/// [`take`] closes them too, but only when a request comes; without this, a
/// member that stops being asked keeps the legs of its last burst open at api
/// for good. Holds the member weakly, so a member a push has dropped takes its
/// sweep with it.
async fn sweep(member: Weak<Inner>) {
    let Some(idle) = member.upgrade().map(|member| member.tuning.leg_idle) else {
        return;
    };
    loop {
        tokio::time::sleep(idle).await;
        let Some(member) = member.upgrade() else {
            return;
        };
        close_aged(&mut held(&member.idle), idle);
    }
}

/// Open a leg: dial, prove the build, and speak HTTP/2 over what comes back.
///
/// [`connect`] is where the measurement is proved, and it returns only a
/// connection that proved it. So nothing below this line has to check anything:
/// a leg that exists is a leg to the declared build.
async fn open(member: &Inner) -> Result<Leg, Unopened> {
    // Its descriptor, counted for as long as the leg exists — see
    // `crate::budget`. None to spare is this process's shortage, not the
    // member's.
    let Some(descriptor) = crate::budget::take() else {
        debug!(
            "a leg to {} was not opened: no descriptor to spare",
            member.addr
        );
        return Err(Unopened::Here);
    };
    let reached = tokio::time::timeout(
        member.tuning.open_timeout,
        connect(&member.addr, &member.proof),
    )
    .await;
    let attested = match reached {
        Ok(Ok(attested)) => attested,
        Ok(Err(e)) => {
            debug!("a leg to {} could not be opened: {e}", member.addr);
            return Err(Unopened::of(&e));
        }
        Err(_) => {
            debug!("a leg to {} did not open in time", member.addr);
            return Err(Unopened::There);
        }
    };
    let (leg, driving) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(WINDOW)
        .initial_connection_window_size(WINDOW)
        // No table for api's responses — see the module docs.
        .header_table_size(0)
        .handshake(TokioIo::new(attested))
        .await
        .map_err(|e| {
            debug!("a leg to {} refused the HTTP/2 handshake: {e}", member.addr);
            Unopened::There
        })?;
    // The connection does the reading and writing; the handle above only asks
    // it for streams. It ends when the last handle is dropped, which is what
    // closes a leg that has aged out of the stack — and gives its descriptor
    // back with it.
    tokio::spawn(async move {
        let _ = driving.await;
        drop(descriptor);
    });
    Ok(leg)
}

/// The response body, and the leg it is still arriving on.
///
/// The leg goes back to the stack when this ends — whether it ended because the
/// body finished or because the caller stopped reading. Both leave the
/// connection usable: dropping a half-read body resets that HTTP/2 stream and
/// nothing else. What neither does is hand the leg to a second request while the
/// first is still on it, which is the whole reason the leg travels with the
/// body rather than being returned when the head arrives.
pub struct Returning {
    body: Incoming,
    leg: Option<Leg>,
    /// Whose stack the leg goes back to.
    member: Arc<Inner>,
}

impl Returning {
    /// Park the leg, once. A body is polled after it ends and is then dropped,
    /// so this runs twice and must mean the same thing both times.
    fn park(&mut self) {
        if let Some(leg) = self.leg.take() {
            park(&self.member, leg);
        }
    }
}

impl Body for Returning {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.body).poll_frame(cx);
        if let Poll::Ready(None) = polled {
            this.park();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl Drop for Returning {
    fn drop(&mut self) {
        self.park();
    }
}

/// TCP arm only, because these stand an api up on a socket. What the attested
/// build changes is what `connect` returns; everything above it is this file.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::{BodyExt, Empty, Full};
    use tower::{Service, ServiceExt};

    use crate::config::testing::{COOLDOWN, LEG_IDLE as IDLE, RESPONSE};

    /// An api stand-in that responds to everything, and counts the connections
    /// it accepted — each one a leg a member opened.
    async fn api() -> (String, Arc<AtomicUsize>) {
        responding_after(Duration::ZERO).await
    }

    /// A stand-in that reads each request's body whole before it responds, as
    /// api does.
    async fn reading_whole() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            hyper::service::service_fn(|req: Request<Incoming>| async move {
                                let _ = req.into_body().collect().await;
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::from_static(b"served"),
                                )))
                            }),
                        )
                        .await;
                });
            }
        });
        addr
    }

    /// A stand-in whose open connections a test can cut, as an api restarting
    /// would.
    async fn restartable() -> (String, Arc<Mutex<Vec<tokio::task::AbortHandle>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let open: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let tracked = open.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let serving = tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            hyper::service::service_fn(|_| async {
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::from_static(b"served"),
                                )))
                            }),
                        )
                        .await;
                });
                tracked.lock().unwrap().push(serving.abort_handle());
            }
        });
        (addr, open)
    }

    /// The same stand-in, starting each response only after `delay`.
    async fn responding_after(delay: Duration) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let opened = Arc::new(AtomicUsize::new(0));
        let counting = opened.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                counting.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            hyper::service::service_fn(move |_| async move {
                                tokio::time::sleep(delay).await;
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::from_static(b"served"),
                                )))
                            }),
                        )
                        .await;
                });
            }
        });
        (addr, opened)
    }

    /// What each leg sent a stand-in, byte for byte, one record per connection.
    type Wire = Arc<Mutex<Vec<Vec<u8>>>>;

    /// A stand-in that responds to everything and keeps what each leg sent it —
    /// which is how a test sees what went over the wire, rather than what came
    /// out of it.
    async fn recording() -> (String, Wire) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let wire = Wire::default();
        let kept = wire.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let leg = {
                    let mut kept = kept.lock().unwrap();
                    kept.push(Vec::new());
                    kept.len() - 1
                };
                let recorded = Recorded {
                    stream,
                    wire: kept.clone(),
                    leg,
                };
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(recorded),
                            hyper::service::service_fn(|_| async {
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::from_static(b"served"),
                                )))
                            }),
                        )
                        .await;
                });
            }
        });
        (addr, wire)
    }

    /// A socket that keeps what it reads.
    struct Recorded {
        stream: tokio::net::TcpStream,
        wire: Wire,
        leg: usize,
    }

    impl tokio::io::AsyncRead for Recorded {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            let polled = Pin::new(&mut this.stream).poll_read(cx, buf);
            this.wire.lock().unwrap()[this.leg].extend_from_slice(&buf.filled()[before..]);
            polled
        }
    }

    impl tokio::io::AsyncWrite for Recorded {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
        }
    }

    const HEADERS: u8 = 0x1;
    const SETTINGS: u8 = 0x4;

    /// The frames a leg sent, each as its type and payload, after the preface
    /// every HTTP/2 client opens with.
    fn frames(wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut rest = wire
            .strip_prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .expect("an HTTP/2 client's preface");
        let mut frames = Vec::new();
        while let [a, b, c, kind, _, _, _, _, _, tail @ ..] = rest {
            let len = usize::from(*a) << 16 | usize::from(*b) << 8 | usize::from(*c);
            let Some((payload, after)) = tail.split_at_checked(len) else {
                break;
            };
            frames.push((*kind, payload.to_vec()));
            rest = after;
        }
        frames
    }

    /// A member of a group whose declared build nothing here checks — the dev
    /// arm proves nothing, which is the point of it.
    fn member(addr: &str) -> Member {
        Member::new(
            addr.to_owned(),
            Arc::new(Proof::new(
                "a build",
                "one",
                crate::upstream::Tls,
                Arc::default(),
            )),
            crate::config::testing::tuning().upstream,
        )
    }

    fn asking() -> Request<Sent> {
        Request::builder()
            .uri("/")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }

    /// Read a body to its end, which is what parks the leg it arrived on.
    /// Offer `req` to `member` and take the response it starts, which the test
    /// expects it to.
    async fn responded(member: &mut Member, req: Request<Sent>) -> Response<Returning> {
        member
            .ready()
            .await
            .unwrap()
            .call(req)
            .await
            .expect("reached the member")
            .expect("and was sent")
    }

    async fn drain(response: Response<Returning>) -> Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }

    /// The whole property in one test: a request opens a leg, the leg comes
    /// back when the body ends, and the next request takes the same one.
    #[tokio::test]
    async fn a_leg_is_opened_once_and_reused() {
        let (addr, opened) = api().await;
        let mut member = member(&addr);

        assert_eq!(
            member.parked(),
            0,
            "nothing is open before anything is asked"
        );

        let response = responded(&mut member, asking()).await;
        assert_eq!(
            member.parked(),
            0,
            "the leg is out while the body is arriving"
        );
        assert_eq!(&drain(response).await[..], b"served");
        assert_eq!(member.parked(), 1, "and back once the body has ended");

        let response = responded(&mut member, asking()).await;
        drain(response).await;
        assert_eq!(member.parked(), 1, "the second request took the same leg");
        assert_eq!(
            opened.load(Ordering::Relaxed),
            1,
            "so api saw one connection carry both"
        );
    }

    /// Two responses in flight at once cannot share a leg, because sharing one
    /// is what puts two callers on one flow-control window.
    #[tokio::test]
    async fn two_requests_in_flight_take_two_legs() {
        let (addr, opened) = api().await;
        let mut member = member(&addr);

        // Neither body is read, so neither leg is back in the stack.
        let first = responded(&mut member, asking()).await;
        let second = responded(&mut member, asking()).await;
        assert_eq!(member.parked(), 0);
        assert_eq!(
            opened.load(Ordering::Relaxed),
            2,
            "the second request could not have the first's leg"
        );

        drain(first).await;
        drain(second).await;
        assert_eq!(member.parked(), 2, "both come back once both bodies end");
    }

    /// A parked leg whose connection api cut is not the next request's
    /// failure: the request goes on over a fresh leg and gets a response.
    ///
    /// Given a moment for the cut to arrive. A request written into a
    /// connection at the very instant it dies cannot be sent again — api may
    /// have acted on it — and is not what this pins.
    #[tokio::test]
    async fn a_leg_cut_while_parked_does_not_fail_the_next_request() {
        let (addr, open) = restartable().await;
        let mut member = member(&addr);
        for _ in 0..5 {
            let response = responded(&mut member, asking()).await;
            drain(response).await;
            assert_eq!(member.parked(), 1);

            for serving in open.lock().unwrap().drain(..) {
                serving.abort();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            let again = responded(&mut member, asking()).await;
            assert_eq!(&drain(again).await[..], b"served", "over a fresh leg");
        }
    }

    /// The response's deadline starts when the body has all been sent: a body
    /// arriving for longer than the response may take is still responded to,
    /// where a deadline counting the upload would have cut it off.
    #[tokio::test]
    async fn the_response_is_timed_from_the_end_of_the_body() {
        let addr = reading_whole().await;
        let mut member = member(&addr);
        let (mut tx, body) = http_body_util::channel::Channel::<Bytes, tower::BoxError>::new(1);
        tokio::spawn(async move {
            for _ in 0..5 {
                tokio::time::sleep(RESPONSE / 3).await;
                tx.send_data(Bytes::from_static(b"part")).await.unwrap();
            }
        });
        let slow = Request::builder().uri("/").body(body.boxed()).unwrap();
        let response = responded(&mut member, slow).await;
        assert_eq!(
            &drain(response).await[..],
            b"served",
            "responded after an upload longer than RESPONSE"
        );
    }

    /// A member that takes a request and starts no response in time is left
    /// out, and the leg that carried it is closed rather than parked — so the
    /// next request to it, after the cooldown, opens a leg afresh, and a member
    /// whose connections went silent is found out by that.
    #[tokio::test]
    async fn a_member_that_does_not_respond_in_time_is_left_out_and_its_leg_closed() {
        let (addr, opened) = responding_after(RESPONSE * 10).await;
        let mut member = member(&addr);

        let failed = member.ready().await.unwrap().call(asking()).await;
        assert!(failed.is_err(), "no response within RESPONSE");
        assert_eq!(member.parked(), 0, "the leg is closed, not parked");
        assert!(
            tokio::time::timeout(COOLDOWN / 2, member.ready())
                .await
                .is_err(),
            "and the member is out"
        );

        tokio::time::timeout(COOLDOWN * 2, member.ready())
            .await
            .expect("back after the cooldown")
            .unwrap();
        // Left to miss its deadline as the first did: the leg it went out on
        // has been opened long before, however loaded the machine running this.
        let _ = member.call(asking()).await;
        assert_eq!(
            opened.load(Ordering::Relaxed),
            2,
            "the next request opened a leg of its own"
        );
    }

    /// A body api will not take is never sent whole, and so never starts the
    /// response's clock — and none of the body's own bounds is checked while
    /// nothing reads it. The member bounds it from when it was due.
    #[tokio::test]
    async fn a_body_api_will_not_take_is_bounded_from_when_it_was_due() {
        // Takes a stream with a window of a kilobyte, and never reads a byte of
        // it nor responds: the rest of any larger body can never be sent.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .initial_stream_window_size(1024)
                        .serve_connection(
                            TokioIo::new(stream),
                            hyper::service::service_fn(|_: Request<Incoming>| {
                                std::future::pending::<
                                    Result<Response<Full<Bytes>>, std::convert::Infallible>,
                                >()
                            }),
                        )
                        .await;
                });
            }
        });
        let mut member = member(&addr);

        // Frame by frame, as a caller's upload arrives: once the window and the
        // library's send buffer are full, nothing asks this body for more.
        let (mut sending, body) =
            http_body_util::channel::Channel::<Bytes, tower::BoxError>::new(1);
        tokio::spawn(async move {
            while sending
                .send_data(Bytes::from(vec![0u8; 64 << 10]))
                .await
                .is_ok()
            {}
        });
        let due = tokio::time::Instant::now() + RESPONSE;
        let mut big = Request::builder().uri("/").body(body.boxed()).unwrap();
        big.extensions_mut().insert(BodyDue(due));

        let asked = member.ready().await.unwrap().call(big);
        let failed = tokio::time::timeout(RESPONSE * 10, asked)
            .await
            .expect("bounded, though the body is never sent whole");
        assert!(failed.is_err());
        assert!(
            tokio::time::Instant::now() >= due + RESPONSE,
            "and not before the body was due and the response's wait had passed"
        );
        assert!(
            tokio::time::timeout(COOLDOWN / 2, member.ready())
                .await
                .is_err(),
            "and the member is out"
        );
    }

    /// A request its caller gives up on before the response starts leaves its
    /// leg to the next one, rather than closing a connection that is still
    /// good — or a caller cancelling request after request would have this role
    /// open an attested leg for every one.
    #[tokio::test]
    async fn a_cancelled_request_leaves_its_leg_to_the_next() {
        let (addr, opened) = responding_after(Duration::from_secs(10)).await;
        let mut member = member(&addr);
        for _ in 0..5 {
            let asked = member.ready().await.unwrap().call(asking());
            assert!(
                tokio::time::timeout(Duration::from_millis(50), asked)
                    .await
                    .is_err(),
                "the stand-in does not respond in time"
            );
        }
        assert_eq!(
            opened.load(Ordering::Relaxed),
            1,
            "one leg carried every attempt"
        );
        assert_eq!(member.parked(), 1, "and is parked for the next");
    }

    /// A caller that goes away mid-response costs the connection it was on
    /// nothing: dropping a half-read body resets that stream and no more.
    #[tokio::test]
    async fn a_leg_comes_back_when_a_caller_stops_reading() {
        let (addr, _opened) = api().await;
        let mut member = member(&addr);

        let response = responded(&mut member, asking()).await;
        drop(response);
        assert_eq!(member.parked(), 1, "the leg is parked, not spent");
    }

    /// A member whose leg would not open is out for the cooldown — pending, and
    /// never an error — and takes work again after it.
    ///
    /// Never an error, and the difference is not cosmetic: the balancer
    /// discards a service whose readiness fails and only discovery puts it
    /// back, so an error here would turn a member that is briefly down into one
    /// that is gone until the next push.
    #[tokio::test]
    async fn a_member_whose_leg_would_not_open_is_out_for_the_cooldown() {
        // A port nothing listens on. Bound and dropped, so it is free and this
        // test is not guessing at one.
        let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nowhere = taken.local_addr().unwrap().to_string();
        drop(taken);

        let mut member = member(&nowhere);
        // Nothing checked it first, so it is ready, and the request finds out —
        // and is handed back, since none of it was sent.
        let asked = member.ready().await.unwrap().call(asking()).await;
        assert!(
            matches!(asked, Ok(Err(NotSent(_)))),
            "the leg would not open, and the request comes back"
        );

        let waited = tokio::time::timeout(COOLDOWN / 2, member.ready()).await;
        assert!(
            waited.is_err(),
            "out: readiness stays pending rather than resolving either way"
        );
        tokio::time::timeout(COOLDOWN * 2, member.ready())
            .await
            .expect("ready again once the cooldown is over")
            .expect("and never an error");
    }

    /// Legs that sat past IDLE are closed by the next request rather than
    /// reused — so the legs to a member fall back after a burst instead of
    /// staying at the most that were ever in flight.
    #[tokio::test]
    async fn legs_parked_past_idle_are_closed_by_the_next_request() {
        let (addr, opened) = api().await;
        let mut member = member(&addr);

        let first = responded(&mut member, asking()).await;
        let second = responded(&mut member, asking()).await;
        drain(first).await;
        drain(second).await;
        assert_eq!(member.parked(), 2, "both parked after the burst");

        tokio::time::sleep(IDLE + Duration::from_millis(100)).await;
        let response = responded(&mut member, asking()).await;
        drain(response).await;
        assert_eq!(
            member.parked(),
            1,
            "the two aged legs are gone, and the one just used is parked"
        );
        assert_eq!(
            opened.load(Ordering::Relaxed),
            3,
            "and it was a fresh one, not an aged one taken again"
        );
    }

    /// With no request after a burst, a timer closes its legs all the same —
    /// otherwise a member nobody asks keeps them open at api for good.
    #[tokio::test]
    async fn legs_parked_past_idle_are_closed_with_no_request_at_all() {
        let (addr, _opened) = api().await;
        let mut member = member(&addr);

        let first = responded(&mut member, asking()).await;
        let second = responded(&mut member, asking()).await;
        drain(first).await;
        drain(second).await;
        assert_eq!(member.parked(), 2, "both parked after the burst");

        // The sweep runs every IDLE and closes what has sat a whole IDLE, so a
        // leg is gone within two of them.
        tokio::time::sleep(IDLE * 2 + Duration::from_millis(100)).await;
        assert_eq!(member.parked(), 0, "closed with nothing asked");
    }

    /// A value one request carried goes over in full again on the next request
    /// on that leg, rather than as a reference into the table the first one
    /// left — which would make the second shorter, and the difference something
    /// the host reads.
    #[tokio::test]
    async fn a_leg_remembers_no_header_from_one_request_to_the_next() {
        let (addr, wire) = recording().await;
        let mut member = member(&addr);
        let carrying = || {
            let mut req = asking();
            let headers = req.headers_mut();
            headers.insert(
                "x-session-token",
                hyper::header::HeaderValue::from_static(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ),
            );
            headers.insert(
                hyper::header::ACCEPT_LANGUAGE,
                hyper::header::HeaderValue::from_static("de-CH"),
            );
            req
        };

        // The first request on a leg may open with a change to the table's
        // size, so it is not one of the two compared.
        for req in [asking(), carrying(), carrying()] {
            drain(responded(&mut member, req).await).await;
        }

        let wire = wire.lock().unwrap();
        assert_eq!(wire.len(), 1, "all three went over one leg");
        let heads: Vec<usize> = frames(&wire[0])
            .into_iter()
            .filter(|(kind, _)| *kind == HEADERS)
            .map(|(_, payload)| payload.len())
            .collect();
        assert_eq!(heads.len(), 3);
        assert_eq!(
            heads[1], heads[2],
            "the second carried in full everything the first did"
        );
    }

    /// A leg tells api it keeps no table for responses, so no response api
    /// sends on it can come out shorter for one it sent before.
    #[tokio::test]
    async fn a_leg_keeps_no_table_for_responses() {
        let (addr, wire) = recording().await;
        let mut member = member(&addr);
        drain(responded(&mut member, asking()).await).await;

        let wire = wire.lock().unwrap();
        let (_, settings) = frames(&wire[0])
            .into_iter()
            .find(|(kind, _)| *kind == SETTINGS)
            .expect("a leg opens with its settings");
        // Six bytes a setting: two of identifier, four of value.
        let table = settings
            .chunks_exact(6)
            .find(|setting| setting[..2] == [0, 1])
            .expect("the size of the table is said");
        assert_eq!(table[2..], [0, 0, 0, 0]);
    }

    /// A ceiling on parked legs holds across everything that parks under it,
    /// and a place comes back when its leg leaves.
    #[test]
    fn parked_legs_stay_under_their_ceiling() {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let first = Place::take(&COUNT, 2).unwrap();
        let _second = Place::take(&COUNT, 2).unwrap();
        assert!(Place::take(&COUNT, 2).is_none(), "one past the ceiling");
        drop(first);
        assert!(Place::take(&COUNT, 2).is_some(), "a place given back");
    }

    /// A dial that fails for want of descriptors or memory HERE says nothing
    /// about the member, and must not leave it out; anything else does.
    #[test]
    fn only_a_failure_of_the_member_counts_against_it() {
        for here in [libc::EMFILE, libc::ENFILE, libc::ENOMEM, libc::ENOBUFS] {
            let e = std::io::Error::from_raw_os_error(here);
            assert!(matches!(Unopened::of(&e), Unopened::Here), "{e}");
        }
        for there in [
            std::io::Error::from_raw_os_error(libc::ECONNREFUSED),
            std::io::Error::from_raw_os_error(libc::ETIMEDOUT),
            std::io::Error::other("the upstream is not the build it was declared to be"),
        ] {
            assert!(matches!(Unopened::of(&there), Unopened::There), "{there}");
        }
    }
}
