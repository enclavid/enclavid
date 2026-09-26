//! Which member of a group takes a request, and what a push does to the set.
//!
//! ## A push says what CHANGED, not what there is
//!
//! Membership reaches the balancer as a stream of arrivals and departures. So a
//! member the host declares again is not touched at all: it keeps the legs it
//! has open, and if it is out, it stays out. Only the difference moves.
//!
//! That matters more than it sounds. The obvious arrangement — rebuild the set
//! on every push — throws away every open connection to api and puts back every
//! member that was left out, and then spends requests finding it all out again.
//! A push is rare and deliberate; the traffic across it is not.
//!
//! ## What a push may NOT carry across
//!
//! A set is carried over only while its group's declared BUILD is unchanged. If
//! the host declares a different build at the same label, the set is built
//! afresh — because the legs in it proved the old build, and a leg proving one
//! build must never serve a request that named another. The old set is dropped
//! whole, which closes those legs.
//!
//! So the rule is not "reuse when convenient". It is: the identity of a set
//! includes what its members must prove.
//!
//! ## Telling the set never waits
//!
//! [`Members::declare`] hands its changes over without awaiting anything, so
//! applying a push has no point at which it can be suspended — and so none at
//! which a timeout could cut it off with some sets told and others not. A set
//! that is told half a push and never the other half keeps a membership the
//! host never declared, and the next push, computing its difference from that,
//! would never repair it.
//!
//! ## Either of two that can take work
//!
//! Selection is the library's power-of-two-choices over a load that is a
//! CONSTANT, which makes it a uniform choice among the members that are ready.
//! Ready means not left out after a leg that would not open, and not already
//! starting `requests_per_member` requests — a member in either state reports
//! itself unready and is simply not among the candidates. It needs no cursor,
//! which is the trap a turn-by-turn rotation fell into twice.
//!
//! That limit is not a ceiling on legs, and the difference matters. Its permit
//! is released when api's answer HEAD comes back, while the leg travels on with
//! the body — so a caller that stops reading holds a leg and no permit. What
//! bounds legs is the streams a public connection may open, times the
//! connections; see `crate::listener`. What the limit does bound is how much
//! work one member is asked to start at once, so a slow member spreads load
//! instead of collecting it.
//!
//! The constant is deliberate. The library also offers latency-based load, and
//! it is the wrong measure for this role: a member that fails instantly looks
//! like the fastest member there is, so a broken one would attract traffic.
//! Load by requests in flight breaks the same way — a member that fails each
//! request at once holds the fewest.
//!
//! ## A request that never left goes to another member
//!
//! A member whose leg will not open hands the request back — nothing of it was
//! written anywhere — and, when the member was the reason, is left out for its
//! cooldown. So the set offers the request again, up to `tries` times in all,
//! and a member that died, is restarting or was declared wrongly costs the
//! caller nothing while another is up. A request that failed after any of it
//! was sent is not offered again: whether api acted on it is unknown.
//!
//! A leg that would not open because THIS process was out of descriptors or
//! memory leaves no member out, so the next offer may go to the same member.
//! That costs nothing either: the dial fails before a byte is sent.
//!
//! ## Nothing waits for ever
//!
//! A member left out after a leg that would not open reports itself not ready
//! rather than failing — see `crate::upstream::member`. If EVERY member of a set
//! is in that state, the set is simply not ready, and a request on it would wait
//! until one came back. `member_wait` is what bounds that: past it the caller
//! is told the hop failed, which is the truth and is better than a request held
//! for the rest of a cooldown. It runs from the moment the request asks, so a
//! request queued behind others for the same set is not given its own wait on
//! top of theirs.
//!
//! A request a member handed back is offered again with a wait of its own,
//! counted from the moment it came back. The one it had went on that member's
//! dial, which `open_timeout` lets outlast it — offered again on what was left
//! of it, the request would take a member only if one were free that instant,
//! and a caller whose request never left would be told the hop failed while
//! the set was about to have room. So a request waits at most `tries` of these,
//! each with its opening; `crate::config` checks the drain against that sum.
//!
//! The same bound covers the other reason a set can be unready — every member
//! already holding its limit — and one bound is right for both, because from the
//! caller's side they are the same fact: there is no capacity right now. Both
//! resolve on their own or not at all, so the wait is meant to be short.
//!
//! Once a member has the request, `answer_timeout` bounds how long it has to
//! START answering, counted from when the request body has all been sent —
//! opening a leg has `open_timeout`, and the upload its own bounds. It is a
//! ceiling against hanging, not a latency budget: a leg to a peer that accepted
//! and then said nothing looks exactly like one to a peer that is thinking — the
//! dial and the HTTP/2 handshake both succeed — and only the answer never comes.
//! It bounds the head and not the answer's body, so a large answer is not cut
//! off. See `crate::upstream::member`.
//!
//! ## The numbers are the set's
//!
//! Every one of them comes with the set, from the push that built it — see
//! `crate::config`. A push that changes them builds the set afresh rather than
//! retelling this one, because every member in it was built with them.

use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::{Request, Response};
use safe_logger::debug;
use tokio::sync::{Mutex, mpsc};
use tower::balance::p2c::Balance;
use tower::discover::Change;
use tower::limit::ConcurrencyLimit;
use tower::load::Constant;
use tower::{Service, ServiceExt};

use super::Proof;
use super::member::{Member, NotSent, Returning, Sent, Unreachable};
use crate::config::UpstreamTuning;

/// A member, by the address this role dials it at.
///
/// The address alone, because the build every member of one set must prove is
/// the set's own and does not vary within it — see the module docs on what a
/// push may not carry across.
type Key = String;

/// One member as the selection sees it: how many requests it may be starting.
/// How long it has to start answering one is the member's own to bound, since
/// the clock starts only once the request body has all been sent — see
/// `crate::upstream::member`.
type Limited = ConcurrencyLimit<Member>;

/// The selection over a set whose membership arrives as changes, every member at
/// one load that does not vary.
type Chosen = Balance<Constant<Arrivals, usize>, Request<Sent>>;

/// Membership, as the balancer consumes it.
///
/// The balancer takes a stream of changes and there is no trait to implement for
/// it — it is spelled as a stream, so this is one. Everything it does is forward
/// the channel a push writes to.
///
/// Unbounded, so that writing to it never waits — see the module docs. What is
/// in it is bounded anyway: one message per member a push changed, and a push
/// is at most `MAX_PUSH_BYTES` of addresses. [`Members::declare`] also drains it
/// whenever the set is not busy, so changes do not pile up behind a set nobody
/// is asking about.
struct Arrivals(mpsc::UnboundedReceiver<Change<Key, Limited>>);

impl futures_core::Stream for Arrivals {
    /// Infallible: a change this role put on the channel cannot be malformed by
    /// the time it comes off it, and the balancer's error path exists for
    /// discovery that can fail — a DNS lookup, a registry — which this is not.
    type Item = Result<Change<Key, Limited>, std::convert::Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|change| change.map(Ok))
    }
}

/// One group's members under one name: who takes a request, and what is
/// currently in the set.
pub struct Members {
    /// What every member of this set must prove, shared with its group. Part of
    /// the set's identity — see the module docs.
    proof: Arc<Proof>,
    /// The numbers this set and every member in it run by. Part of its
    /// identity too.
    tuning: UpstreamTuning,
    /// Where a push writes what changed.
    tells: mpsc::UnboundedSender<Change<Key, Limited>>,
    /// What this set currently holds, so the next push can say the difference.
    /// The balancer keeps its own copy and will not tell us about it.
    holds: std::sync::Mutex<BTreeSet<Key>>,
    /// The selection. Behind a lock because reserving a member and handing it
    /// the request must be one act: two callers that each reserved and then
    /// dispatched would both spend the same reservation.
    ///
    /// The lock is held for that handshake only — never while an answer is
    /// coming back — and a caller's `member_wait` runs while it waits for the
    /// lock as well as under it, so a set with nothing to give holds no caller
    /// longer than that, however many are queued.
    ///
    /// A lock and not the library's `Buffer`, which is the stock answer to "the
    /// balancer is not `Clone`". `Buffer` waits for readiness inside its own
    /// task, where that wait can be neither bounded on its own nor noticed; a
    /// timeout outside it would bound readiness and the answer together. This
    /// role bounds them apart: `member_wait` short, `answer_timeout` long.
    choosing: Mutex<Chosen>,
}

impl Members {
    /// An empty set for one group under one name, ready to be told who is in it.
    pub fn new(proof: Arc<Proof>, tuning: UpstreamTuning) -> Members {
        let (tells, arrivals) = mpsc::unbounded_channel();
        Members {
            proof,
            tuning,
            tells,
            holds: std::sync::Mutex::new(BTreeSet::new()),
            choosing: Mutex::new(Balance::new(Constant::new(Arrivals(arrivals), 1))),
        }
    }

    /// Tell the set who is in it now, as a difference from who was.
    ///
    /// Members that appear in both are not mentioned, which is what leaves their
    /// legs alone, and a member that is out, out.
    ///
    /// Not async, and that is the point — see the module docs.
    pub fn declare(&self, addrs: &BTreeSet<String>) {
        let (gone, arrived) = {
            let mut holds = self.holds.lock().expect("never held on panic");
            let gone: Vec<Key> = holds.difference(addrs).cloned().collect();
            let arrived: Vec<Key> = addrs.difference(&holds).cloned().collect();
            holds.clone_from(addrs);
            (gone, arrived)
        };

        // A send fails only if the balancer is gone, and the balancer lives in
        // this same value.
        for addr in gone {
            // The balancer evicts it; dropping the member closes its parked legs.
            let _ = self.tells.send(Change::Remove(addr));
        }
        for addr in arrived {
            let member = Member::new(addr.clone(), self.proof.clone(), self.tuning);
            let limited = ConcurrencyLimit::new(member, self.tuning.requests_per_member);
            let _ = self.tells.send(Change::Insert(addr, limited));
        }

        self.take_in();
    }

    /// Let the balancer take in what it has been told, if nobody is using it.
    ///
    /// The balancer reads its membership only when asked for a member, so a set
    /// nobody sends to would otherwise hold every change it was told — and every
    /// member removed in them, legs and all — until its first request. This
    /// asks once, with a waker that wakes nobody, purely so that it reads.
    ///
    /// Only if the lock is free. A request holding it is asking already, and
    /// asking again with a waker that wakes nobody would take that request's
    /// wakeup from it.
    ///
    /// Outside the task's budget. The channel spends one unit of it per change
    /// and, once it is spent, answers "not yet" and wakes the waker to come back
    /// — which here wakes nobody, so a push of more changes than the budget
    /// would leave the rest queued. The whole of what is queued is bounded by
    /// the push, so reading it at once is not the starvation the budget is for.
    fn take_in(&self) {
        let Ok(mut choosing) = self.choosing.try_lock() else {
            return;
        };
        let asked = tokio::task::unconstrained(choosing.ready());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let _ = std::pin::pin!(asked).poll(&mut cx);
    }

    /// Give the request to a member that can take it — and to another, if the
    /// first one's leg would not open.
    pub async fn send(&self, mut req: Request<Sent>) -> Result<Response<Returning>, Unreachable> {
        for _ in 0..self.tuning.tries {
            // One deadline for each offer: the wait for the lock and the wait
            // for a member under it. Counted apart, each caller queued on a set
            // with nothing to give would wait out every caller ahead of it as
            // well. Afresh for an offer after a hand-back — see the module docs.
            let deadline = tokio::time::Instant::now() + self.tuning.member_wait;
            let answering = {
                let Ok(mut choosing) =
                    tokio::time::timeout_at(deadline, self.choosing.lock()).await
                else {
                    debug!("no member of a set could take a request in time");
                    return Err(Unreachable);
                };
                match tokio::time::timeout_at(deadline, choosing.ready()).await {
                    // Dispatched under the same lock the reservation was taken
                    // under, and awaited outside it.
                    Ok(Ok(chosen)) => chosen.call(req),
                    Ok(Err(e)) => {
                        debug!("a set of members could not be asked: {e}");
                        return Err(Unreachable);
                    }
                    Err(_) => {
                        debug!("no member of a set could take a request in time");
                        return Err(Unreachable);
                    }
                }
            };
            // Bounded by the member: its opening, and `answer_timeout` once the
            // body is sent.
            match answering.await {
                Ok(answer) => return Ok(answer),
                Err(e) => match e.downcast::<NotSent>() {
                    // Nothing of it reached any api, so it is offered again as
                    // it is. A member that handed it back for its own failure is
                    // out for its cooldown, so the next choice is not that one.
                    Ok(back) => req = back.0,
                    Err(e) => {
                        debug!("a request did not come back from its member: {e}");
                        return Err(Unreachable);
                    }
                },
            }
        }
        debug!(
            "no leg to any member of a set would open, in {} tries",
            self.tuning.tries
        );
        Err(Unreachable)
    }

    /// How many members the BALANCER holds, as opposed to what this set was
    /// told — the two differ exactly when changes are queued and not yet read.
    #[cfg(test)]
    fn taken_in(&self) -> usize {
        self.choosing
            .try_lock()
            .expect("nothing else is using the set in a test")
            .len()
    }

    /// The addresses this set holds, for the tests that pin what a push does
    /// to it.
    #[cfg(test)]
    pub fn addresses(&self) -> BTreeSet<String> {
        self.holds.lock().expect("never held on panic").clone()
    }

    /// What this set's members must prove, by identity — what the tests compare
    /// to tell "carried across" from "asked again".
    #[cfg(test)]
    pub fn proof(&self) -> &Arc<Proof> {
        &self.proof
    }

    /// How many members this set holds.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.holds.lock().expect("never held on panic").len()
    }
}

/// TCP arm only, because these stand an api up on a socket.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    /// An api stand-in answering with the address it is listening on, so a test
    /// can tell which member served it, and counting the connections it
    /// accepted — each one a leg a member opened.
    async fn api() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let said = addr.clone();
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counting = opened.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                counting.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let said = said.clone();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            hyper::service::service_fn(move |_| {
                                let said = said.clone();
                                async move {
                                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                        Bytes::from(said),
                                    )))
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        (addr, opened)
    }

    fn members() -> Members {
        Members::new(
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

    /// Who answered.
    async fn served_by(members: &Members) -> String {
        let answer = members.send(asking()).await.expect("a member took it");
        String::from_utf8(
            answer
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .into(),
        )
        .unwrap()
    }

    fn set(addrs: &[&str]) -> BTreeSet<String> {
        addrs.iter().map(|addr| (*addr).to_owned()).collect()
    }

    /// The whole point of a difference: a member the next push declares again
    /// keeps the legs it has open.
    ///
    /// Measured at api, which is the only place it is visible: the connection
    /// that carried the first request carries every later one too, across a
    /// push that added a member beside it. A set rebuilt on each push would
    /// show a second connection here.
    #[tokio::test]
    async fn a_member_declared_again_keeps_its_legs() {
        let (first, reached) = api().await;
        let (second, _) = api().await;
        let members = members();

        members.declare(&set(&[&first]));
        assert_eq!(served_by(&members).await, first);
        assert_eq!(reached.load(std::sync::atomic::Ordering::Relaxed), 1);

        // A push that adds a member and declares the first again.
        members.declare(&set(&[&first, &second]));
        assert_eq!(members.len(), 2);

        // Both take work. Which one a request goes to is a coin between the
        // two, which is why this asks until both have answered.
        let spread = tokio::time::timeout(Duration::from_secs(5), async {
            let mut seen = BTreeSet::new();
            while seen.len() < 2 {
                seen.insert(served_by(&members).await);
            }
            seen
        })
        .await
        .expect("both members took work");
        assert_eq!(spread, set(&[&first, &second]));

        assert_eq!(
            reached.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "and the first was never reconnected to across the push"
        );
    }

    /// A member a push drops stops being given work.
    #[tokio::test]
    async fn a_member_a_push_omits_stops_taking_work() {
        let (first, _) = api().await;
        let (second, _) = api().await;
        let members = members();

        members.declare(&set(&[&first, &second]));
        members.declare(&set(&[&second]));
        assert_eq!(members.len(), 1);

        for _ in 0..10 {
            assert_eq!(
                served_by(&members).await,
                second,
                "only the one still declared"
            );
        }
    }

    /// A member that accepts a connection and then says nothing is the worst
    /// case, because every step before the answer SUCCEEDS.
    ///
    /// The dial connects, the HTTP/2 handshake returns without waiting for the
    /// peer's settings, and the leg is made and looks usable, so nothing counts
    /// against the member. Only the answer never comes. So
    /// the bound that matters is on the answer — `answer_timeout` — and
    /// without it this test hangs for ever rather than failing.
    #[tokio::test]
    async fn a_member_that_says_nothing_does_not_hold_a_request_for_ever() {
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut accepted = Vec::new();
            while let Ok((stream, _)) = silent.accept().await {
                // Held open, so the caller sees a live connection and no bytes.
                accepted.push(stream);
            }
        });

        let members = members();
        members.declare(&set(&[&addr]));

        let answered = tokio::time::timeout(Duration::from_secs(10), members.send(asking())).await;
        assert!(
            answered
                .expect("the request returned rather than hanging")
                .is_err(),
            "a member that never answers is a member the request fails at"
        );
    }

    /// Telling a set about many members at once, with nobody asking it for
    /// anything, returns — and it returns having told the balancer, not having
    /// queued the telling behind a request that has not come.
    ///
    /// A set built for a push is exactly such a set: it has no traffic until the
    /// push is published. When telling it waited on a bounded channel only a
    /// request drains, a push of more members than the channel held could never
    /// finish.
    #[tokio::test]
    async fn a_set_nobody_asks_takes_in_any_number_of_members() {
        let members = members();
        let many: BTreeSet<String> = (0..500)
            .map(|n| format!("127.0.0.1:{}", 20_000 + n))
            .collect();

        members.declare(&many);
        assert_eq!(
            members.taken_in(),
            500,
            "the balancer has every one of them"
        );

        let fewer: BTreeSet<String> = many.iter().take(10).cloned().collect();
        members.declare(&fewer);
        assert_eq!(
            members.taken_in(),
            10,
            "and the departures went through too"
        );
        assert_eq!(members.addresses(), fewer);
    }

    /// Callers queued on a set with nothing to give are each refused within
    /// their own member_wait, not after everyone ahead of them has waited theirs
    /// out.
    ///
    /// No socket: an empty set is one nothing ever answers at.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn queued_callers_are_refused_within_the_member_wait() {
        let members = Arc::new(members());
        let asked = tokio::time::Instant::now();
        let queued: Vec<_> = (0..10)
            .map(|_| {
                let members = members.clone();
                tokio::spawn(async move { members.send(asking()).await.is_err() })
            })
            .collect();
        for one in queued {
            assert!(one.await.unwrap(), "refused");
        }
        let took = asked.elapsed();
        assert!(
            took < crate::config::testing::MEMBER_WAIT + Duration::from_millis(150),
            "all ten answered within one member_wait, took {took:?}"
        );
    }

    /// A member whose leg would not open costs the caller nothing while another
    /// is up: the request it hands back goes to the one that answers.
    ///
    /// Nothing checked either member before the first request, which is the
    /// point: the question is asked by requests, and one refused leg is enough
    /// to leave a member out — without the request that found out paying for it.
    #[tokio::test]
    async fn a_request_whose_leg_would_not_open_goes_to_another_member() {
        let (live, _) = api().await;
        let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nowhere = taken.local_addr().unwrap().to_string();
        drop(taken);

        let members = members();
        members.declare(&set(&[&live, &nowhere]));

        for _ in 0..20 {
            assert_eq!(
                served_by(&members).await,
                live,
                "every request answered, and by the live one"
            );
        }
    }

    /// A request a member handed back after the rest of the set had gone out
    /// waits its own `member_wait` for the next one, rather than the remains of
    /// the first: here a member comes up inside the third offer's wait, well
    /// after the first offer's would have ended.
    #[tokio::test]
    async fn a_request_handed_back_waits_afresh_for_the_next_member() {
        let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nowhere = taken.local_addr().unwrap().to_string();
        drop(taken);
        let (live, _) = api().await;

        let wait = Duration::from_millis(1000);
        let tuning = UpstreamTuning {
            member_wait: wait,
            cooldown: Duration::from_millis(800),
            tries: 3,
            ..crate::config::testing::tuning().upstream
        };
        let members = Arc::new(Members::new(
            Arc::new(Proof::new(
                "a build",
                "one",
                crate::upstream::Tls,
                Arc::default(),
            )),
            tuning,
        ));
        members.declare(&set(&[&nowhere]));

        // The only member refuses at once and is out until 800 ms; the second
        // offer finds it back and it refuses again, out until 1600 ms. The third
        // offer starts at 800 ms, and a live member arrives at 1200 ms — after
        // the first offer's wait ended at 1000 ms, inside the third's.
        let declaring = members.clone();
        let (nowhere_too, live_too) = (nowhere.clone(), live.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            declaring.declare(&set(&[&nowhere_too, &live_too]));
        });

        let answer = tokio::time::timeout(wait * 3, members.send(asking()))
            .await
            .expect("bounded")
            .expect("the third offer waited for the member that came up");
        let body = answer.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, live.as_bytes());
    }

    /// A request that reached api and failed there is not sent again — not to
    /// that member and not to another. Whether api acted on it is unknown, and
    /// a second send could do twice what the caller asked for once.
    #[tokio::test]
    async fn a_request_that_reached_api_is_not_sent_again() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Two members that take the request and then fail it, counting every
        // one they were handed.
        let seen = Arc::new(AtomicUsize::new(0));
        let mut addrs = Vec::new();
        for _ in 0..2 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            addrs.push(listener.local_addr().unwrap().to_string());
            let seen = seen.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let seen = seen.clone();
                    tokio::spawn(async move {
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(
                                TokioIo::new(stream),
                                hyper::service::service_fn(move |_| {
                                    seen.fetch_add(1, Ordering::Relaxed);
                                    async {
                                        Err::<Response<Full<Bytes>>, _>(std::io::Error::other(
                                            "failed after it arrived",
                                        ))
                                    }
                                }),
                            )
                            .await;
                    });
                }
            });
        }

        let members = members();
        let declared: Vec<&str> = addrs.iter().map(String::as_str).collect();
        members.declare(&set(&declared));

        assert!(members.send(asking()).await.is_err(), "the caller is told");
        assert_eq!(
            seen.load(Ordering::Relaxed),
            1,
            "and api was handed it once"
        );
    }

    /// A set with nobody in it refuses rather than waiting for ever — the
    /// balancer is simply never ready, and `member_wait` is what makes that an
    /// answer.
    #[tokio::test]
    async fn an_empty_set_refuses_in_bounded_time() {
        let members = members();
        let refused = tokio::time::timeout(Duration::from_secs(5), members.send(asking())).await;
        assert!(refused.expect("bounded").is_err(), "told, not left waiting");
    }

    /// A set every member of which is unreachable does the same, and does not
    /// hold up the caller behind it.
    #[tokio::test]
    async fn a_set_of_unreachable_members_refuses_too() {
        let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nowhere = taken.local_addr().unwrap().to_string();
        drop(taken);

        let members = members();
        members.declare(&set(&[&nowhere]));

        for _ in 0..2 {
            let refused =
                tokio::time::timeout(Duration::from_secs(5), members.send(asking())).await;
            assert!(refused.expect("bounded").is_err());
        }
    }
}
