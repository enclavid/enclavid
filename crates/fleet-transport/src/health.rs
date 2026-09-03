//! The health port: the one channel in this system where the HOST asks and a
//! guest answers.
//!
//! # Why it exists
//!
//! A guest that is up but not yet serving looks, from outside, exactly like one
//! that is up and serving: the VM is running either way. That gap used to be
//! closed by giving up — a role that could not reach its peers within a fixed
//! budget ended, and the machine powered off, so "not answering" meant
//! "not working". Waiting instead of giving up is the better behaviour, and it
//! removes that signal. This replaces it.
//!
//! A role reports its HEALTH. Whether it is READY — whether traffic may go
//! there — is not a fact about the guest and is not claimed here: it is the
//! host's conclusion, drawn from the WHOLE answer, every field true, and then
//! from still seeing it. That split is worth keeping because the two belong to
//! different parties. A guest cannot know whether it should be routed to; it
//! can only say what it knows about itself.
//!
//! `healthy` means one thing in every role and it is the narrow one: this role
//! finished coming up and is listening. It is not an aggregate. api reports its
//! peers alongside it and does not fold them in, because folding them in would
//! be api concluding for the host — and destroying, on the way, the one thing
//! the conclusion needs, which is WHICH peer. See `enclavid_api::health`.
//!
//! So the host builds ordering out of the history — bring the leaves up, wait
//! for each to first answer healthy, then api, wait for its whole answer, then
//! route — and it acts on the present value when a field goes false. What
//! action, and for which field, is the host's policy and lives with the host:
//! the same answer justifies stopping a guest, sending it no new work while it
//! finishes what it has, or doing nothing and waiting.
//!
//! What it does NOT prove is that the serving path works. That path is mutual
//! RA-TLS, so the host cannot traverse it, and this port deliberately does not
//! try to stand in for it. Whether the machine is alive at all is the host's own
//! knowledge, from the VMM.
//!
//! # It reads nothing
//!
//! [`serve`] accepts a connection, writes, and closes. It never calls `read`,
//! and that is the security property of the channel rather than a detail of the
//! protocol: the host cannot inject anything into a guest here because there is
//! no point at which a guest takes bytes from it. Not "we parse only a fixed
//! request" — no request exists.
//!
//! That is why this lives here and not in each role. The invariant is one
//! function to review and one `grep` to check, instead of four copies that agree
//! today.
//!
//! It has one consequence a prober's author needs: **do not send anything.**
//! Closing a socket that still holds unread bytes sends RST rather than FIN, so
//! a prober that speaks first can have its own answer reset away before it reads
//! it. That is not a fault to work around — it is the invariant being visible
//! from outside. `connect`, read to EOF, done.
//!
//! # The answer is the role's, not this module's
//!
//! [`serve`] takes a closure and writes whatever it returns. api's answer
//! carries its fleet peers and the hatch alongside its own bool; a leaf's is
//! that bool alone, because a leaf has no peers and nothing else it could
//! truthfully say. The shape is JSON in both cases so one parser reads the whole
//! fleet, but nothing here imposes it — and because `healthy` carries the same
//! meaning either way, one parser reads them field for field rather than merely
//! byte for byte.
//!
//! # What may be in the answer
//!
//! The same rule as a log line: only what the host already knows. A role's own
//! health qualifies — the host launched it and provisioned everything it waits
//! for. Which fleet peers api can reach qualifies too: the host owns the
//! relays those legs run through, so it can see a live connection on each.
//!
//! What does NOT qualify is anything a session moves. The time of the last
//! exchange on the api↔storage leg would be an example, and a tempting one: it
//! is a direct function of applicant activity, so polling it would report when
//! someone is verifying and at what cadence. api therefore pings its peers on a
//! FIXED schedule and reports that instead — a clock that runs whether or not
//! anyone is being verified says the leg works and nothing else.
//!
//! # The direction is unusual, and that is convenient
//!
//! Every other leg goes guest → the host on CID 2 → a relay → a guest, because
//! vsock addresses guest↔host and there is no guest-to-guest. This one is the
//! other way: the host dials the guest's own CID, which the VMM exposes
//! natively. So the health plane needs nothing on the host and shares no path
//! with the data plane.

use safe_logger::{debug, info, reason, safe};

/// The body of a leaf's answer before it is serving.
///
/// A literal rather than a serialized struct, and the reason is where it runs:
/// storage and the two workers carry no JSON serializer today, and adding one to
/// three measured binaries to render fifteen constant bytes is not a trade worth
/// making.
///
/// The model still exists, in this module's tests, and a test asserts these two
/// literals are exactly what `serde_json` renders it as. So the convention —
/// field name, no spaces, the trailing newline — is pinned against a real
/// serializer rather than against someone's typing, and `serde` stays a
/// dev-dependency that no measured binary links.
pub const UNHEALTHY: &[u8] = b"{\"healthy\":false}\n";

/// The body of a leaf's answer once it is serving. See [`UNHEALTHY`].
pub const HEALTHY: &[u8] = b"{\"healthy\":true}\n";

/// A role's own health, in the only shape it needs: one bool.
///
/// It starts false and the role sets it once, and that is not a latch by
/// construction — nothing here forbids the reverse. It simply never happens: on
/// a leaf the accept loop runs for ever, and anything that genuinely breaks
/// reaches a return from `main`, at which point PID 1 powers the machine off. So
/// "was healthy and now is not" is a state no leaf is alive to report.
///
/// api holds one of these too, for the same field and with the same meaning —
/// it finished coming up and is listening — and composes it with the peer and
/// hatch bools that only it has. Its peers going up and down is not this bool
/// moving; see `enclavid_api::health` for why those are kept apart.
#[derive(Debug, Default)]
pub struct Health(std::sync::atomic::AtomicBool);

impl Health {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Called once, by the role, after everything that could fail has succeeded.
    pub fn declare_healthy(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_healthy(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The body a leaf answers with.
    pub fn body(&self) -> Vec<u8> {
        if self.is_healthy() {
            HEALTHY
        } else {
            UNHEALTHY
        }
        .to_vec()
    }
}

/// Take the health port, or end the process.
///
/// **Await this on the role's own task; do not spawn it.** That is what makes
/// the sentence above true, and the split from [`serve`] exists for no other
/// reason — so do not merge them back.
///
/// The failure is meant to be fatal: every other listener in a role is
/// load-bearing for serving, this one is load-bearing for being MANAGED, and a
/// guest that came up unmanageable should not quietly serve traffic the host
/// cannot withdraw. But it is expressed as a panic, and a panic only ends the
/// process if it reaches the end of a thread — nothing in this workspace sets
/// `panic = "abort"`, and `safe_logger::install_panic` installs a hook that
/// logs and returns rather than one that aborts. Inside `tokio::spawn` the
/// unwind therefore stops at the task boundary, tokio stores it in a
/// `JoinHandle` nobody holds, and the role carries on serving with no health
/// port at all — the exact outcome this is written to prevent. Awaited from
/// `main`, the unwind leaves `block_on`, leaves `main`, and the machine stops.
///
/// Bind EARLY — before the work whose progress the port reports — or it is
/// unreachable during exactly the window it exists to describe.
pub async fn bind(addr: &str) -> crate::Listener {
    let listener = crate::bind(addr).await.unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "health: cannot bind the health port, so this guest would come up with no way \
             for the host to tell whether it is serving. Stopping.",
            reason!("a constant naming a listener whose address the host itself supplied")
        )
    });
    info!(
        "health: answering on {}",
        safe(
            &addr,
            reason!("a listen address from the measured command line")
        ),
        reason!("a constant, emitted once at boot before any session exists")
    );
    listener
}

/// Answer every connection on an already-bound port, until the process ends.
///
/// Safe to spawn, and meant to be: nothing here can fail in a way the role
/// needs to hear about. `body` is called per connection, so the answer is
/// current rather than one captured at bind time.
///
/// Accept errors are not fatal, and are not reported outward either: a refused
/// or reset probe is the host's own connection failing, which the host can see
/// from its end.
pub async fn serve<F>(mut listener: crate::Listener, body: F) -> !
where
    F: Fn() -> Vec<u8>,
{
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                debug!("health accept: {e}");
                continue;
            }
        };
        // Write, then drop. `read` is never called on `stream` — see the module
        // docs. Nothing inspects the peer either: the answer holds only what the
        // host already knows, so who asked does not change it.
        let answer = body();
        if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut stream, &answer).await {
            debug!("health write: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the literals are literals OF. It lives here rather than in the
    /// crate proper because nothing in production serializes it — the leaves
    /// answer with the constants above. What it buys is that those constants are
    /// checked against a real serializer.
    #[derive(serde::Serialize)]
    struct Healthy {
        healthy: bool,
    }

    fn rendered(healthy: bool) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&Healthy { healthy }).expect("serialize");
        bytes.push(b'\n');
        bytes
    }

    /// The literals are what the model serializes to. This is what lets the
    /// leaves ship constants without a serializer: change the model, and if the
    /// bytes no longer match, this fails.
    #[test]
    fn the_literals_are_what_the_model_serialises_to() {
        assert_eq!(rendered(true), HEALTHY);
        assert_eq!(rendered(false), UNHEALTHY);
    }

    /// A leaf starts unhealthy and says so; declaring it is what flips the body.
    #[test]
    fn a_leaf_answers_unhealthy_until_it_says_otherwise() {
        let h = Health::new();
        assert!(!h.is_healthy());
        assert_eq!(h.body(), UNHEALTHY);

        h.declare_healthy();
        assert!(h.is_healthy());
        assert_eq!(h.body(), HEALTHY);
    }

    /// A prober that says nothing gets the answer; a prober that speaks does
    /// not wedge the port for the next one.
    ///
    /// The second half is the interesting one. A server that parsed a request
    /// would block on the first prober until it sent a complete one — so the
    /// assertion is not about what the chatty prober receives (it may get its
    /// answer, or an RST caused by the unread bytes in the buffer; both are
    /// correct and which one happens is the kernel's business) but that a silent
    /// prober AFTERWARDS is still served promptly. That can only hold if nothing
    /// waited for input.
    ///
    /// Compiled only on the TCP arm, because the address below is a TCP one and
    /// `bind` on the vsock arm takes a bare port. Nothing is lost by that: what
    /// this proves is a property of the PROTOCOL — a port that answers without
    /// ever reading behaves the same over either transport — and the vsock arm
    /// carrying real bytes is `tests/vsock_loopback.rs`, which is `#[ignore]`d
    /// because it needs a kernel module rather than because it is uninteresting.
    #[cfg(not(feature = "vsock"))]
    #[tokio::test]
    async fn it_answers_the_silent_and_is_not_wedged_by_the_talkative() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let health = Health::new();
        health.declare_healthy();

        let listener = crate::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let h = health.clone();
        tokio::spawn(async move { serve(listener, move || h.body()).await });

        let read_answer = async |addr: &str| {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.expect("read");
            got
        };

        assert_eq!(
            read_answer(&addr).await,
            HEALTHY,
            "a prober that says nothing gets the answer"
        );

        // Speak first. Whatever comes back, the bytes went nowhere.
        {
            let mut chatty = tokio::net::TcpStream::connect(&addr)
                .await
                .expect("connect");
            chatty
                .write_all(b"GET /status HTTP/1.1\r\n\r\n")
                .await
                .expect("write");
            let mut got = Vec::new();
            let _ = chatty.read_to_end(&mut got).await;
        }

        // The port moved on. A parser would still be waiting for the rest of
        // that request.
        let after = tokio::time::timeout(std::time::Duration::from_secs(5), read_answer(&addr))
            .await
            .expect("the port must not be wedged by a prober that spoke");
        assert_eq!(after, HEALTHY);
    }
}
