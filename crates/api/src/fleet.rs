//! How this process treats a fleet peer being absent.
//!
//! Two different absences, and they want opposite answers.
//!
//! **Not there yet.** Roles come up in whatever order they come up, and a peer
//! that is not listening is the ordinary case rather than a fault. [`dial`]
//! waits, without a bound.
//!
//! It used to give up after a fixed budget, on the argument that a guest which
//! waits for ever tells nobody anything. That argument has stopped being true
//! twice over. Every attempt now writes a line to the log device naming the peer
//! and its address, so a waiting guest says exactly what it is waiting for; and
//! the health port answers that peer false throughout, so the host does not
//! conclude the guest is ready. What the bound actually bought was a boot loop:
//! 18.75 s was a bet on how fast a peer binds, and losing the bet powered the
//! machine off and started a fresh one to lose it again.
//!
//! Waiting also lets the host order the fleet instead of racing it — bring the
//! leaves up, wait for each to answer healthy, then api. Nothing here depends on
//! the host getting that right, which is the point of keeping the retry: the
//! order is an operational convention, and this is what makes being wrong about
//! it cost nothing.
//!
//! **Gone after being there.** The leg is marked down, the health port starts
//! reporting that peer false, and [`supervise`] dials again. The process does
//! not end, and neither does the `healthy` field: api being unable to reach a
//! peer is not api being unwell, and conflating the two is what would send a
//! host to restart the wrong guest. See [`crate::health`].
//!
//! It used to. That was a substitute for a health channel that did not exist:
//! the only way to say "I cannot serve" was to stop existing, and PID 1 turning
//! the machine off made the silence unambiguous. With a port that can say it, the
//! decision moves to where it belongs — the host stops sending work here and
//! then chooses to wait, to stop this guest, or to restart the whole set. A
//! guest should not be making that call on the host's behalf, and it was making
//! it by cascade: one peer restarting took this process down with it.
//!
//! What that used to be defended by is worth stating, because it does not apply.
//! Reconnecting was said to need every in-flight call classified into those safe
//! to repeat and those that might already have applied. That is true of
//! TRANSPARENT resumption — replaying a call across a reconnect — which nothing
//! here does: a call in flight when the leg dies fails, and is reported as a
//! failure. Nor did ending the process avoid the ambiguity; it relocated it, since
//! the applicant's request failed either way. And the state layer already carries
//! the mechanism that makes a retry safe — `SessionStoreService::write` is an
//! atomic CAS on `expected_version`, so a stale repeat fails the check instead of
//! applying twice.

use std::future::Future;
use std::time::Duration;

use safe_logger::{info, reason, safe, warn};

/// Waits between dial attempts, ramping to a ceiling and staying there.
///
/// Quick at first because the ordinary case is a peer that is seconds behind;
/// then slow, because a peer that is minutes behind is waiting on a human and
/// polling it faster changes nothing.
const RETRY_DELAYS: [Duration; 6] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
];

/// Ceiling on ONE attempt, separate from the ladder above.
///
/// The ladder bounds how often a failed attempt is repeated; it does nothing
/// about an attempt that never finishes. Nothing in the dial path has a timeout
/// of its own — not the connect, not the RA-TLS handshake, not remoc bringing
/// the connection up — so a peer that accepts and then says nothing would park
/// this for ever, and no number of retries would help because the first one
/// never returns.
///
/// Generous, because a real attempt does chip work on both ends: the handshake
/// is mutual RA-TLS, so each side mints and verifies an attestation report.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Dial a fleet peer, waiting however long it takes.
///
/// `attempt` is retried rather than its result inspected, because at this stage
/// every failure means the same thing: nothing is listening yet. There is no
/// error return — this does not give up, so there is nothing to hand back.
///
/// `addr` is only for the log line, and it belongs there: a peer that never
/// answers and a peer whose address is wrong look identical from here, and the
/// address is the one thing that tells them apart. It is safe to name because
/// the measured command line is where it came from.
pub async fn dial<T, E, F, Fut>(peer: &str, addr: &str, mut attempt: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display + safe_logger::SafeToLog,
{
    let mut delays = RETRY_DELAYS.iter().copied();
    // The ladder's last rung, repeated once it runs out.
    let mut ceiling = RETRY_DELAYS[RETRY_DELAYS.len() - 1];
    loop {
        match tokio::time::timeout(ATTEMPT_TIMEOUT, attempt()).await {
            Ok(Ok(value)) => return value,
            Ok(Err(e)) => {
                let delay = delays.next().unwrap_or(ceiling);
                ceiling = delay;
                warn!(
                    "api: {} at {} not reachable yet ({}); retrying in {:?}",
                    safe(&peer, reason!("a name fixed in this image")),
                    safe(&addr, reason!("an address from the measured command line")),
                    e,
                    safe(&delay, reason!("one of a fixed ladder of delays")),
                    reason!(
                        "a peer name fixed in this image, an address from the measured \
                         command line, a closed-enum failure and one of a fixed ladder of \
                         delays — nothing a session can reach. Not boot-only: `supervise` \
                         dials again on every loss"
                    )
                );
                tokio::time::sleep(delay).await;
            }
            Err(_elapsed) => {
                let delay = delays.next().unwrap_or(ceiling);
                ceiling = delay;
                warn!(
                    "api: {} at {} accepted nothing within {:?}; retrying in {:?}",
                    safe(&peer, reason!("a name fixed in this image")),
                    safe(&addr, reason!("an address from the measured command line")),
                    safe(
                        &ATTEMPT_TIMEOUT,
                        reason!("a compile-time constant of this build")
                    ),
                    safe(&delay, reason!("one of a fixed ladder of delays")),
                    reason!(
                        "a peer name fixed in this image, an address from the measured \
                         command line, a closed-enum failure and one of a fixed ladder of \
                         delays — nothing a session can reach. Not boot-only: `supervise` \
                         dials again on every loss"
                    )
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// A fleet client that can be replaced underneath its holders.
///
/// The adapters (`Compiler`, `Executor`, the two storage backends) hold one of
/// these instead of a client, so a reconnect swaps what is inside and every call
/// site is untouched. `RwLock` rather than a lock-free cell because the write
/// happens twice per outage and the read clones a remoc handle, which is a few
/// atomics — the guard never crosses an await.
pub struct Leg<C> {
    client: std::sync::RwLock<Option<C>>,
}

impl<C: Clone> Leg<C> {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            client: std::sync::RwLock::new(None),
        })
    }

    /// The client, or `None` while the leg is down. Callers map `None` to their
    /// own domain error — a request that arrives during an outage fails, it does
    /// not wait, because how long to wait is the host's decision and it is
    /// already being told.
    pub fn get(&self) -> Option<C> {
        self.client
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Install or clear the client. Called only by [`supervise`] and by the
    /// install closure it is given — the adapters read, they never write.
    pub fn set(&self, client: Option<C>) {
        *self.client.write().unwrap_or_else(|e| e.into_inner()) = client;
    }
}

/// Keep one fleet leg connected for the life of the process.
///
/// Dials once inline — so boot blocks until the peer answers, and nothing serves
/// before its peers are reachable — then spawns a task that watches the
/// connection and dials again when it ends.
///
/// `install` is how the leg reaches its adapters: `Some(clients)` on connect,
/// `None` on loss. It is a closure rather than a `Leg` because the storage leg
/// carries two clients on one connection, and both have to move together.
///
/// `connect` returns the clients and a handle for the connection's driver.
/// Awaiting that handle is how this learns the connection ended — and it is a
/// verdict rather than silence, because chmux pings at half its
/// `connection_timeout` whenever the link is idle, so "no traffic" and "no peer"
/// are already distinct one layer down.
pub async fn supervise<C, F, Fut, E, I>(
    peer: crate::health::Peer,
    addr: String,
    health: std::sync::Arc<crate::health::ApiHealth>,
    mut connect: F,
    install: I,
) where
    C: Send + 'static,
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(C, tokio::task::JoinHandle<()>), E>> + Send,
    E: std::fmt::Display + safe_logger::SafeToLog + Send,
    I: Fn(Option<C>) + Send + 'static,
{
    let (clients, driver) = dial(peer.as_str(), &addr, &mut connect).await;
    install(Some(clients));
    health.set_peer(peer, true);

    tokio::spawn(async move {
        let mut driver = driver;
        loop {
            let _ = driver.await;
            install(None);
            health.set_peer(peer, false);
            warn!(
                "api: the {} leg ended; requests touching it now fail and the health port \
                 reports it down. Dialling again.",
                safe(&peer.as_str(), reason!("a name fixed in this image")),
                reason!(
                    "constant text; that a fleet link dropped is already visible to whoever \
                     carries it"
                )
            );

            let (clients, next) = dial(peer.as_str(), &addr, &mut connect).await;
            install(Some(clients));
            health.set_peer(peer, true);
            info!(
                "api: the {} leg is back",
                safe(&peer.as_str(), reason!("a name fixed in this image")),
                reason!("constant text about a link the host itself routes")
            );
            driver = next;
        }
    });
}
