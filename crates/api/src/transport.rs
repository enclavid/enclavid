//! Inbound listener — single location with the `vsock` feature gate.
//!
//! Default build: TCP listener via `tokio::net::TcpListener`, no TLS. That is a
//! developer box, where the caller is a tool on the same machine and there is no
//! host between them.
//!
//! `vsock` build: the attested one. A vsock listener wrapped in mutual RA-TLS,
//! driven per connection through hyper.
//!
//! ## Why the attested build cannot use `axum::serve`
//!
//! `axum::serve::Listener::accept` returns no `Result`, so a TLS listener
//! written against it has to complete the handshake INSIDE `accept` and
//! therefore serially — one peer stalling mid-handshake holds up every other
//! peer's accept, and a full attestation verification is not a fast handshake. A
//! refused handshake would also land in axum's `handle_accept_error`, which
//! classifies a rustls error as a listener problem and throttles accepts to one
//! per second.
//!
//! So the attested arm uses the shape the three leaves already use for remoc:
//! accept, spawn, handshake on the spawned task.
//!
//! ## What the handshake settles, and what it does not
//!
//! One direction: this end proves what it is, and asks the caller for nothing.
//!
//! These are the ports the outside arrives on — a browser, a consumer's
//! integration, our CLI — and none of them can present an attestation, so
//! demanding one would refuse every caller the surface exists for. The gateway
//! standing in front changes none of that: it terminates the public session and
//! opens another one here, but this is a layer on a public surface rather than a
//! fleet leg, and the surface was reachable from outside before the gateway
//! existed.
//!
//! So it is NOT the posture the three leaves take toward api. Those legs have a
//! closed set of peers, all of them ours, and demanding an attestation there
//! costs nothing. Applying that shape here would read as strictness and act as
//! an exclusion of the people the port is for.
//!
//! Who the caller is stays where it already was: every request carries a
//! credential this process checks itself, and a session's state opens only under
//! the bearer it was sealed with.

use std::sync::Arc;

use axum::Router;
use enclavid_attestation::Attestor;
use safe_logger::{info, reason, safe};

/// What `serve` needs to wrap a connection, or nothing where it does not.
///
/// Built ONCE and cloned into both surfaces. The server config behind it —
/// `enclavid_ra_tls::public_server_config`, through
/// `endorsement::inbound_server_config` — mints a fresh certificate on every
/// call, so building one per surface would give this process two identities and
/// two quotes, for no reason a peer could make sense of.
///
/// Once per process, too, and nothing in the certificate or its quote expires —
/// see `enclavid_ra_tls`. What checks it is the gateway, which takes it for the
/// build a caller named: so the key of this surface, stolen from a running api,
/// reaches only callers still naming this build, and rolling to a new build is
/// what ends that.
#[cfg(feature = "vsock")]
pub type Acceptor = tokio_rustls::TlsAcceptor;

/// A unit STRUCT rather than `()`, and `Clone` without `Copy`. `main` builds one
/// and clones it into each surface either way; `()` makes those lines read as a
/// mistake, and `Copy` makes the clone read as one. The placeholder behaves like
/// the thing it stands in for.
#[cfg(not(feature = "vsock"))]
#[derive(Clone)]
pub struct Acceptor;

/// Mint this process's serving identity.
#[cfg(feature = "vsock")]
pub fn acceptor(attestor: Arc<dyn Attestor>) -> Acceptor {
    tokio_rustls::TlsAcceptor::from(Arc::new(
        crate::endorsement::inbound_server_config(attestor).unwrap_or_else(|e| {
            safe_logger::debug!("{e}");
            safe_logger::error_and_panic!(
                "api: cannot build the RA-TLS server config for the inbound surfaces. Stopping.",
                reason!("a constant reporting a platform state the host provisioned")
            )
        }),
    ))
}

/// A developer build terminates nothing, so there is no identity to mint.
#[cfg(not(feature = "vsock"))]
pub fn acceptor(_attestor: Arc<dyn Attestor>) -> Acceptor {
    Acceptor
}

/// Binds the inbound listener at `addr` and runs the HTTP server.
///
/// `addr` format is per-transport:
/// - default (TCP): `host:port` — e.g. `0.0.0.0:3000`
/// - `vsock` feature: bare u32 port — e.g. `3000` (bound to `VMADDR_CID_ANY`)
///
/// `bound` fires once the listener exists and before the first accept. It is
/// what lets `main` set the health port's `healthy` field on the same terms a
/// leaf sets its own — after the bind, not after the spawn. Dropped without a
/// send only if this function panics, which is the bind failing, which ends the
/// process.
#[cfg(not(feature = "vsock"))]
pub async fn serve(
    app: Router,
    addr: &str,
    bound: tokio::sync::oneshot::Sender<()>,
    _acceptor: Acceptor,
) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");
    info!(
        "api: listening on tcp://{}",
        safe(
            &addr,
            reason!("a listen address from this process's environment")
        ),
        reason!("a constant, emitted once at boot before any session exists")
    );
    let _ = bound.send(());
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(feature = "vsock")]
pub async fn serve(
    app: Router,
    addr: &str,
    bound: tokio::sync::oneshot::Sender<()>,
    acceptor: Acceptor,
) {
    let listener = fleet_transport::bind(addr)
        .await
        .expect("failed to bind vsock listener");
    info!(
        "api: listening on vsock://*:{}",
        safe(&addr, reason!("on the measured command line")),
        reason!("a constant, emitted once at boot before any session exists")
    );
    let _ = bound.send(());

    // The loop, the delay after a failed accept, and the split between an error
    // that clears itself and one that does not all live in `accept_forever`.
    fleet_transport::accept_forever(listener, move |stream, peer| {
        let app = app.clone();
        let acceptor = acceptor.clone();
        // Returns as soon as the connection has its own task, so the next accept
        // is not held up behind this one's handshake.
        async move {
            tokio::spawn(async move {
                serve_conn(stream, acceptor, app, peer).await;
            });
        }
    })
    .await
}

/// RA-TLS-accept one connection, then serve the surface's router on it.
#[cfg(feature = "vsock")]
async fn serve_conn(
    stream: fleet_transport::Stream,
    acceptor: Acceptor,
    app: Router,
    peer: String,
) {
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let tls = match acceptor.accept(stream).await {
        Ok(tls) => tls,
        Err(e) => {
            // `debug!` and not a tier the host reads. A refused handshake is
            // ordinary here — the host can provoke one whenever it likes — and a
            // per-connection line on an outward tier would be a channel whose
            // rate the caller chooses.
            safe_logger::debug!("api: handshake with {peer} failed: {e}");
            return;
        }
    };

    // `auto` settles h2 against http/1.1 by what the peer actually sends.
    if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(
            TokioIo::new(tls),
            hyper_util::service::TowerToHyperService::new(app),
        )
        .await
    {
        safe_logger::debug!("api: connection from {peer} ended: {e}");
    }
}
