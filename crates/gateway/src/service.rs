//! Everything this role runs, as the server library runs things.
//!
//! ## Why each of these is a service rather than a task
//!
//! The library supervises what it is given: it holds the shutdown signal, it
//! waits for each service to finish, and — now that the public listener is its
//! own, see `crate::bridge` — a graceful stop reaches real client connections
//! rather than only what it started itself. That is the whole reason to hand it
//! the rest as well: one place decides when this role stops, and it is the same
//! place that knows what is still in flight.
//!
//! ## Each binds inside `start`, and that is not incidental
//!
//! The server builds its own runtimes, so there is no runtime before it runs
//! and nothing asynchronous can happen first. Every port this role takes is
//! therefore taken inside the service that serves it. A bind that fails ends
//! the process, which is what it did before and what it must keep doing: a
//! guest that came up without its configuration port is one nobody can fix.
//!
//! ## What is taken once
//!
//! A `BackgroundService` is started with `&self`, and several of these own
//! something that can only be consumed once — a channel's sending half, a
//! listener. They hold it in a `Mutex<Option<_>>` and take it on the first
//! start. A second start would find nothing and stop, which is the honest
//! answer: there is no second one.

use std::sync::{Arc, Mutex};

use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use safe_logger::{debug, info, reason, safe};
use tokio::sync::watch;

use crate::upstream::Upstreams;

/// Take the one-shot thing a service owns, or say why there is nothing to do.
fn once<T>(held: &Mutex<Option<T>>, what: &'static str) -> Option<T> {
    let taken = held.lock().ok()?.take();
    if taken.is_none() {
        debug!("{what} was started twice and has nothing left to start");
    }
    taken
}

/// Run `forever` until the server says to stop.
///
/// Every loop here is written to run for the life of the process, because that
/// is what each of them is for: a role that stopped taking configuration, or
/// stopped checking its members, is a role that should end rather than carry
/// on. What ENDS them is the server deciding to stop, and this is where that
/// decision reaches them.
///
/// Without it the server would signal a stop, drain the public listener, and
/// then wait for runtimes that never finish — a shutdown that hangs, which is
/// worse than one that is abrupt.
async fn until_stopped<F>(mut stop: ShutdownWatch, forever: F)
where
    F: std::future::Future,
{
    tokio::select! {
        _ = forever => (),
        // `changed()` erring means every sender is gone, which happens only as
        // the server itself goes away. Either way there is nothing left to
        // serve.
        _ = stop.changed() => (),
    }
}

/// What the party running the fleet reads to know this guest came up.
///
/// First of everything, and before anything slow: a guest that is still
/// deriving a key should already be answering that it is not ready.
pub struct Health {
    pub addr: String,
    pub state: Arc<fleet_transport::health::Health>,
}

#[async_trait::async_trait]
impl BackgroundService for Health {
    async fn start(&self, shutdown: ShutdownWatch) {
        let listener = fleet_transport::health::bind(&self.addr).await;
        let state = self.state.clone();
        until_stopped(
            shutdown,
            fleet_transport::health::serve(listener, move || state.body()),
        )
        .await
    }
}

/// The port the host pushes the table to.
///
/// A role that can no longer be reconfigured does not go on serving a table
/// nobody can change, so a failure here ends the process.
pub struct Config {
    pub addr: String,
    pub table: Mutex<Option<watch::Sender<Arc<Upstreams>>>>,
}

#[async_trait::async_trait]
impl BackgroundService for Config {
    async fn start(&self, shutdown: ShutdownWatch) {
        let Some(table) = once(&self.table, "the configuration port") else {
            return;
        };
        let listener = fleet_transport::bind(&self.addr).await.unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "gateway: cannot bind the configuration port at {}. Stopping.",
                safe(&self.addr, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        });
        info!(
            "gateway: taking configuration on {}; serving nothing until the first push",
            safe(&self.addr, reason!("on the measured command line")),
            reason!("a constant, emitted once at boot before any session exists")
        );
        until_stopped(shutdown, crate::push::serve(listener, table)).await
    }
}

/// Keeping current what is known about every member of the current table.
pub struct Checks {
    pub table: watch::Receiver<Arc<Upstreams>>,
}

#[async_trait::async_trait]
impl BackgroundService for Checks {
    async fn start(&self, shutdown: ShutdownWatch) {
        until_stopped(shutdown, crate::balance::check_forever(self.table.clone())).await
    }
}

/// Keeping current the certificate the public listener answers with.
pub struct Certificate {
    pub table: watch::Receiver<Arc<Upstreams>>,
    pub identity: Arc<crate::key::Identity>,
    pub publish:
        Mutex<Option<watch::Sender<Option<Arc<tokio_rustls::rustls::sign::CertifiedKey>>>>>,
}

#[async_trait::async_trait]
impl BackgroundService for Certificate {
    async fn start(&self, shutdown: ShutdownWatch) {
        let Some(publish) = once(&self.publish, "the certificate") else {
            return;
        };
        until_stopped(
            shutdown,
            crate::listen::follow(self.table.clone(), self.identity.clone(), publish),
        )
        .await
    }
}

/// The public connection's first metre — see `crate::bridge`.
///
/// It waits for the first push before accepting anything. Open before there is
/// a table, every request would fail as an unavailable upstream, and the host
/// would see a guest that answers and cannot tell it from one that routes.
pub struct Bridge {
    pub addr: String,
    pub to: std::path::PathBuf,
    pub at_once: usize,
    pub table: watch::Receiver<Arc<Upstreams>>,
    pub state: Arc<fleet_transport::health::Health>,
}

#[async_trait::async_trait]
impl BackgroundService for Bridge {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // One push, not a non-empty table: declaring no group at all is a state
        // the host may choose, and it is still a table.
        //
        // Raced against the stop, because a role told to stop before it was
        // ever configured must not sit here holding the shutdown up.
        let mut table = self.table.clone();
        tokio::select! {
            first = table.changed() => {
                if first.is_err() {
                    return;
                }
            }
            _ = shutdown.changed() => return,
        }

        let listener = fleet_transport::bind(&self.addr).await.unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "gateway: cannot bind the public listener at {}. Stopping.",
                safe(&self.addr, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        });
        // Said after the bind, not before: "listening" is a claim about a
        // socket that exists.
        info!(
            "gateway: listening for public connections on {}",
            safe(&self.addr, reason!("on the measured command line")),
            reason!("a constant, emitted once at boot before any session exists")
        );
        self.state.declare_healthy();
        // A stop reaches the accept loop here; the connections already carried
        // are the listener's to drain, and that is the library's own.
        until_stopped(
            shutdown,
            crate::bridge::carry(listener, self.to.clone(), self.at_once),
        )
        .await
    }
}
