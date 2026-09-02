//! How this process treats a fleet peer being absent.
//!
//! Two different absences, and they want opposite answers.
//!
//! **Not there yet.** Roles come up in whatever order they come up, and a peer
//! that is not listening during the first seconds is the ordinary case rather
//! than a fault. [`dial`] waits for it. Bounded, because a peer that never
//! arrives is a different thing from one that is slow, and a guest that waits
//! for ever tells nobody anything.
//!
//! **Gone after being there.** [`watch`] ends the process. The alternative —
//! staying up holding a client whose connection is dead — keeps the surfaces
//! listening and fails every request that reaches them, which reads as working
//! and is not. Ending is safe here because this process owns no state worth
//! preserving: session state lives sealed in the storage-CVM, boot takes
//! seconds, and PID 1 powers the guest off when this returns so whatever brings
//! guests up starts a fresh one that dials again.
//!
//! Reconnecting in place would be the other answer, and it is a larger one: it
//! needs every in-flight call classified into those safe to repeat and those
//! that might already have applied. What this costs instead is a cascade — a
//! peer restarting takes this process down with it.

use std::future::Future;
use std::time::Duration;

use safe_logger::{error, reason, safe, warn};

/// Waits between dial attempts. Roughly a minute in total, which is far longer
/// than a peer takes to bind and far shorter than a human waits before assuming
/// something is wrong.
const RETRY_DELAYS: [Duration; 6] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
];

/// Dial a fleet peer, waiting for it to appear.
///
/// `attempt` is retried rather than its result inspected, because at this stage
/// every failure means the same thing: nothing is listening yet.
pub async fn dial<T, E, F, Fut>(peer: &str, mut attempt: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display + safe_logger::SafeToLog,
{
    for delay in RETRY_DELAYS {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(e) => {
                warn!(
                    "api: {} not reachable yet ({}); retrying in {:?}",
                    safe(&peer, reason!("a name fixed in this image")),
                    e,
                    safe(&delay, reason!("one of a fixed ladder of delays")),
                    reason!("boot only, before either listener binds")
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
    attempt().await
}

/// Run a connection's driver, and end the process when it finishes.
///
/// The driver completing IS the connection ending — there is no other signal,
/// and every client handle multiplexed over it is dead from that moment.
pub fn watch<F>(driver: F, peer: &'static str)
where
    F: Future + Send + 'static,
{
    tokio::spawn(async move {
        let _ = driver.await;
        error!(
            "api: {} connection ended; every client on it is dead. Stopping so a fresh \
             instance dials again rather than serving requests that cannot succeed.",
            safe(&peer, reason!("a name fixed in this image")),
            reason!(
                "constant text; that a fleet link dropped is already visible to \
                     whoever carries it"
            )
        );
        std::process::exit(1);
    });
}
