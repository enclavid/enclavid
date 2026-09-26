//! Accepting connections into a `tower` service. One function, [`serve`].
//!
//! Accepting itself is [`crate::Incoming`]'s, in the crate proper; this only
//! decides when to take the next connection and what to hand it to.
//!
//! Liveness is deliberately absent. It is answered by whatever protocol runs
//! over the stream — api's legs learn it from chmux pinging on the same link —
//! and a transport has no protocol to ask.

use std::convert::Infallible;

use tower_service::Service;

use crate::{Accepted, Listener};

/// Serve every connection with `service`, for ever.
///
/// [`crate::accept_forever`] with a service for a handler, and two differences
/// that are the reason to pick it:
///
/// - the service is asked for capacity BEFORE a connection is accepted, so a
///   caller over its limit waits in the listener's backlog rather than inside
///   this process holding a descriptor;
/// - each connection is SPAWNED, where `accept_forever` awaits its handler. The
///   bound is the service saying it is full, not the handler being slow.
///
/// The service cannot fail, by type. A connection's outcome is the service's to
/// report, because only the service knows what it was serving; a driver handed
/// an error it cannot name could only drop it, which is how an expired timeout
/// would vanish without a word. No stock combinator brings a failing layer's
/// error to `Infallible` short of a closure that panics, so a bound that can
/// end a connection lives inside the service's future, where the connection it
/// bounds is known.
///
/// A panic inside one connection ends that connection's task and nothing else.
pub async fn serve<S>(listener: Listener, mut service: S) -> !
where
    S: Service<Accepted, Response = (), Error = Infallible>,
    S::Future: Send + 'static,
{
    let mut incoming = listener.incoming();
    loop {
        let Ok(()) = std::future::poll_fn(|cx| service.poll_ready(cx)).await;
        tokio::spawn(service.call(incoming.next().await));
    }
}

/// TCP arm only, because these stand a listener up on a socket.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::Notify;

    /// A service behind the same limit the roles use, counting what it is
    /// handed and holding each connection open until `release` is rung.
    ///
    /// Held open, so the permit is spent for as long as the connection lives —
    /// which is what the ceiling is about.
    fn holding(
        at_once: usize,
        seen: Arc<AtomicUsize>,
        release: Arc<Notify>,
    ) -> impl Service<Accepted, Response = (), Error = Infallible, Future: Send + 'static> {
        tower::ServiceBuilder::new()
            .concurrency_limit(at_once)
            .service_fn(move |accepted: Accepted| {
                seen.fetch_add(1, Ordering::Relaxed);
                let release = release.clone();
                async move {
                    let _held = accepted;
                    release.notified().await;
                    Ok::<_, Infallible>(())
                }
            })
    }

    /// Wait until `seen` reaches `count`, or fail after a generous bound.
    async fn reaches(seen: &AtomicUsize, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while seen.load(Ordering::Relaxed) < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the service was not handed connection {count}"));
    }

    /// A connection reaches the service.
    #[tokio::test]
    async fn a_connection_reaches_the_service() {
        let listener = crate::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        tokio::spawn(serve(listener, holding(8, seen.clone(), release)));

        let _caller = tokio::net::TcpStream::connect(&addr).await.unwrap();
        reaches(&seen, 1).await;
    }

    /// A full service is handed nothing more — and is handed the next
    /// connection once it has room again.
    ///
    /// The second half is what tells "full" from "stuck". A driver that never
    /// asks again, or a service that loses the wakeup when its permit comes
    /// back, passes the first half and fails this one.
    #[tokio::test]
    async fn a_full_service_waits_and_is_handed_the_next_once_it_has_room() {
        let listener = crate::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        tokio::spawn(serve(listener, holding(1, seen.clone(), release.clone())));

        let _first = tokio::net::TcpStream::connect(&addr).await.unwrap();
        reaches(&seen, 1).await;

        // The kernel completes this handshake into the backlog; nothing here
        // takes it, because the service said it was full.
        let _second = tokio::net::TcpStream::connect(&addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            seen.load(Ordering::Relaxed),
            1,
            "not while the first holds the only permit"
        );

        release.notify_one();
        reaches(&seen, 2).await;
    }
}
