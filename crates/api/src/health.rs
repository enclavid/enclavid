//! What api answers on the health port.
//!
//! api reports FACTS and draws no conclusion from them: whether it finished
//! coming up, whether each fleet leg is connected, whether the hatch answers.
//! The field named `healthy` is not a verdict either — it means for api exactly
//! what it means for a leaf, "I finished coming up and I am listening", and
//! says nothing about whether traffic should arrive here.
//!
//! That is the whole shape, and it is the shape the port was described with
//! from the start: a role says what it knows about itself, and READY is the
//! host's conclusion. The host draws it from the WHOLE answer — every field
//! true, this role and its peers — before it sends a first request. After that
//! first yes, a peer going down and coming back is what the peer bools carry,
//! and the host needs no third state to tell "not yet" from "no longer": it
//! started this guest, so it knows whether it has ever seen a yes.
//!
//! # Why `healthy` is not "every leg is up"
//!
//! It was, and that was api deciding something that is not its to decide.
//!
//! Aggregating also destroyed the information the decision needs. From
//! `healthy: false` there is no way back to WHICH leg, so a host acting on it
//! can only act on this guest whole — send it nothing, restart it — and for one
//! of the three legs that is the wrong action. A session is affine to the api
//! holding its legs: its next request can only be served where its state lives.
//! So "send work here or not" is really two questions — whether a NEW session
//! may start here, which is a free choice because another guest will do, and
//! whether session S's next request may, where there is no choice at all and
//! not sending it ends S.
//!
//! storage and the execution-worker are on every round, so losing either
//! answers both questions at once. The compile-worker answers only the first: a
//! composition nobody has compiled yet cannot start here, but a session already
//! running reaches it only when the executor's L1 and the L2 in the storage-CVM
//! both miss, which normally means never. One bool answered the second question
//! with the first, and turned an outage that blocks new sessions into one that
//! ends the sessions already in flight.
//!
//! Which peer sits on which path is a fact about the CACHE, not about api. It
//! moves when the caching moves — there is a window after a new
//! execution-worker build where the compat token invalidates L2 and the
//! compile-worker is briefly on every path — and it depends on things only the
//! host can see, like whether it just deployed that build. Freezing it into a
//! measured image would mean a new measurement and a fleet-wide redeploy to
//! change a routing rule. So it is not frozen here: api reports the legs, the
//! host owns the policy.
//!
//! # What is not here
//!
//! No timestamps, no counters, no ages. Two reasons, and the second is the one
//! that decided it.
//!
//! The host polls, so it timestamps its own observations — how long a leg has
//! been down is something the asker already knows better than the answerer, and
//! carrying it would be duplication.
//!
//! And a time-of-last-exchange would not be duplication, it would be a session
//! oracle: every round writes state to the storage-CVM, so that number moves
//! with applicant activity and polling it would report when someone is being
//! verified. The legs avoid this because chmux pings on a fixed schedule
//! whether or not anyone is being verified. The hatch bit avoids it the same
//! way and for the same reason, which is why it comes from a probe on a clock
//! and NEVER from the outcome of a real call: a bit set by real traffic would
//! flip to say "an applicant-driven call happened, and failed" — and the host,
//! being the far end of that hop, is the party that failed it.

use std::sync::atomic::{AtomicBool, Ordering};

/// The fleet peers api dials. Named rather than indexed so the JSON keys and the
/// call sites cannot drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    Storage,
    CompileWorker,
    ExecutionWorker,
}

impl Peer {
    /// The name in the answer, and in the log line for the same leg.
    pub const fn as_str(self) -> &'static str {
        match self {
            Peer::Storage => "storage",
            Peer::CompileWorker => "compile_worker",
            Peer::ExecutionWorker => "execution_worker",
        }
    }
}

/// Everything api can truthfully say about itself, and the body that says it.
///
/// Every field starts false. That is not a placeholder — it is the truth until
/// each becomes otherwise, and it is what lets the host bring the fleet up in
/// order: api answers false everywhere from the moment its port binds.
#[derive(Debug, Default)]
pub struct ApiHealth {
    /// Monotonic, and it carries the same meaning a leaf's bool carries: set
    /// once, after both serving listeners are bound. api has the same come-up
    /// interval a leaf has — longer, if anything, because `fleet::dial` waits
    /// without a bound — and this is the field that describes it.
    ///
    /// It does not go back down. A leg dropping is not api becoming unwell; it
    /// is a leg dropping, and the peer bools say so.
    ///
    /// What that leaves unsaid is worth naming rather than papering over. A
    /// peer bool reports only that THIS api does not currently hold that leg,
    /// and it reads the same whether the peer is gone or the fault is on this
    /// side. The attestor is consulted per dial and never again for a connection
    /// already up, so an attestation path that has wedged tears nothing down —
    /// it fails whichever legs happen to drop next, one at a time. No shape of
    /// this answer tells those two apart.
    own: fleet_transport::health::Health,
    storage: AtomicBool,
    compile_worker: AtomicBool,
    execution_worker: AtomicBool,
    /// Set by the probe ticker in `main`, never by the outcome of a real call.
    /// See the module docs — that distinction is the difference between a fact
    /// about a hop and an oracle on session activity.
    hatch: AtomicBool,
}

impl ApiHealth {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    fn slot(&self, peer: Peer) -> &AtomicBool {
        match peer {
            Peer::Storage => &self.storage,
            Peer::CompileWorker => &self.compile_worker,
            Peer::ExecutionWorker => &self.execution_worker,
        }
    }

    /// Called by [`crate::fleet::supervise`] on connect and on loss.
    pub fn set_peer(&self, peer: Peer, up: bool) {
        self.slot(peer).store(up, Ordering::Relaxed);
    }

    pub fn peer_is_up(&self, peer: Peer) -> bool {
        self.slot(peer).load(Ordering::Relaxed)
    }

    /// Called by the probe ticker, on its clock and nowhere else.
    pub fn set_hatch(&self, up: bool) {
        self.hatch.store(up, Ordering::Relaxed);
    }

    pub fn hatch_is_up(&self) -> bool {
        self.hatch.load(Ordering::Relaxed)
    }

    /// Called once, after both serving surfaces are bound.
    pub fn declare_serving(&self) {
        self.own.declare_healthy();
    }

    pub fn is_serving(&self) -> bool {
        self.own.is_healthy()
    }

    /// The answer, as JSON. Hand-rendered from a fixed set of names and bools —
    /// there is nothing here a serializer would do differently, and a test pins
    /// the shape against one.
    ///
    /// `hatch` is a top-level field rather than a fourth entry in `peers`, and
    /// that is deliberate: `peers` are attested TEE guests reached under mutual
    /// RA-TLS, the hatch is the untrusted host. One map would suggest they are
    /// facts of the same kind and invite the next reader to fold them into one
    /// loop.
    pub fn body(&self) -> Vec<u8> {
        let peer = |p: Peer| format!("\"{}\":{}", p.as_str(), self.peer_is_up(p));
        format!(
            "{{\"healthy\":{},\"peers\":{{{},{},{}}},\"hatch\":{}}}\n",
            self.is_serving(),
            peer(Peer::Storage),
            peer(Peer::CompileWorker),
            peer(Peer::ExecutionWorker),
            self.hatch_is_up(),
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the hand-rendered body is a rendering OF, so the field names and
    /// the JSON conventions are checked against a real serializer rather than
    /// against someone's typing.
    #[derive(serde::Serialize)]
    struct Body {
        healthy: bool,
        peers: Peers,
        hatch: bool,
    }

    #[derive(serde::Serialize)]
    struct Peers {
        storage: bool,
        compile_worker: bool,
        execution_worker: bool,
    }

    fn rendered(
        healthy: bool,
        storage: bool,
        compile_worker: bool,
        execution_worker: bool,
        hatch: bool,
    ) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&Body {
            healthy,
            peers: Peers {
                storage,
                compile_worker,
                execution_worker,
            },
            hatch,
        })
        .expect("serialize");
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn the_body_is_what_the_model_serialises_to() {
        let h = ApiHealth::new();
        assert_eq!(h.body(), rendered(false, false, false, false, false));

        h.set_peer(Peer::Storage, true);
        h.set_peer(Peer::CompileWorker, true);
        assert_eq!(h.body(), rendered(false, true, true, false, false));

        h.set_peer(Peer::ExecutionWorker, true);
        h.set_hatch(true);
        h.declare_serving();
        assert_eq!(h.body(), rendered(true, true, true, true, true));
    }

    /// Everything starts false, so api answers false everywhere from the moment
    /// its port binds until each field has become otherwise on its own account.
    #[test]
    fn every_field_starts_false() {
        let h = ApiHealth::new();
        assert!(!h.is_serving());
        assert!(!h.hatch_is_up());
        for p in [Peer::Storage, Peer::CompileWorker, Peer::ExecutionWorker] {
            assert!(!h.peer_is_up(p), "{p:?}");
        }
    }

    /// THE point of the reshape: `healthy` is api's own state and nothing else
    /// moves it. A guest whose storage leg is gone is a guest whose api is fine
    /// and whose storage leg is gone, and the answer has to be able to say that
    /// — otherwise a host acting on `healthy` restarts api for a fault in a
    /// different guest.
    #[test]
    fn a_peer_going_down_does_not_move_healthy() {
        let h = ApiHealth::new();
        h.declare_serving();
        for p in [Peer::Storage, Peer::CompileWorker, Peer::ExecutionWorker] {
            h.set_peer(p, true);
        }
        h.set_hatch(true);
        assert_eq!(h.body(), rendered(true, true, true, true, true));

        h.set_peer(Peer::Storage, false);
        assert!(h.is_serving(), "api is still up; its storage leg is not");
        assert_eq!(h.body(), rendered(true, false, true, true, true));

        h.set_hatch(false);
        assert!(
            h.is_serving(),
            "api is still up; the hatch is not answering"
        );
        assert_eq!(h.body(), rendered(true, false, true, true, false));
    }

    /// A leg comes back. This is the whole difference from a leaf's bool, which
    /// only ever moves forward because a leaf that loses something ends.
    #[test]
    fn a_leg_can_come_back_up() {
        let h = ApiHealth::new();
        h.set_peer(Peer::Storage, true);
        assert!(h.peer_is_up(Peer::Storage));
        h.set_peer(Peer::Storage, false);
        assert!(!h.peer_is_up(Peer::Storage));
        h.set_peer(Peer::Storage, true);
        assert!(h.peer_is_up(Peer::Storage));
    }

    /// Losing every peer still does not move `healthy`. Worth pinning on its
    /// own, because it is the case where folding the legs in would have been
    /// most tempting: an api that reaches nothing is exactly the one somebody
    /// would want to report as unwell, and it is still api that is fine.
    #[test]
    fn healthy_stays_true_when_every_peer_is_gone() {
        let h = ApiHealth::new();
        h.declare_serving();
        assert_eq!(h.body(), rendered(true, false, false, false, false));
    }
}
