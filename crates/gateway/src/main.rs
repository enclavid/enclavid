//! The `gateway` deployable: the measured role that terminates client TLS.
//!
//! It exists because nothing does that today. api's two serving listeners run
//! `axum::serve` on a bare socket, so whatever carries TLS to the host either
//! terminates it — which ends the central guarantee — or splices it into a
//! listener that cannot speak it. This role is where "TLS-in-TEE for inbound"
//! stops being aspirational. Routing, one public name and fewer certificates
//! are consequences, not the reason.
//!
//! It cannot live on the host: it holds the private key for a public name AND
//! serves the page. Either alone might be arguable; together they would let a
//! host-side process present whatever it liked about the enclave behind it.
//!
//! ## Its public listener is vsock, and that is the whole trick
//!
//! This guest has no NIC either — it is a fleet CVM like the rest, and the
//! absence of network modules is measured into its rootfs. So the host carries
//! the public connection in over vsock **without terminating it**: a blind byte
//! splice that never holds a key and never sees a plaintext record. The TLS
//! session begins here.
//!
//! The proxy library cannot listen on vsock — it listens on TCP or a unix
//! socket and offers no trait for a third — so `crate::bridge` carries that
//! connection one more metre, to a socket inside this guest that the library
//! does listen on. Everything from the handshake onward is then the library's.
//!
//! That is also why there is one public listener rather than one per name. From
//! outside there is one TLS session per connection, and the name it agreed on is
//! settled by the handshake. Every name the host declares is this role's, and one
//! listener answers for all of them.
//!
//! ## What this build does
//!
//! It terminates TLS on the public listener and carries each request to a group
//! of interchangeable api — at the address that group serves the settled name on,
//! running the build the caller named. Bodies stream through unbuffered and
//! unread.
//!
//! Which api builds exist, and where, is the host's to say. It pushes that to a
//! port of its own rather than putting it on the command line, and this role
//! serves nothing publicly until the first push — see `crate::config` and
//! `crate::push`.
//!
//! The hop to api is RA-TLS in the attested build: this end verifies api's quote
//! and proves it carries the measurement the caller named, and presents nothing,
//! because api asks this end for no certificate — it could not, since what it
//! serves is open to callers that have none. See `crate::upstream`. A developer
//! build speaks plain HTTP on both legs, because there is no host between the two
//! processes to protect anything from.
//!
//! Nothing is served from here. Whatever this role carries is compiled into the
//! build behind it, beside the handlers it calls, so one launch digest covers
//! both. Terminating the session here is still what makes that worth anything — a
//! terminator can replace whatever is served over it, so it has to be measured,
//! and the leg onward has to be attested. Both are.
//!
//! What this role does not do is parse what it carries: no body and no path,
//! ever. That is the standing defence against a runtime exploit, which changes
//! behaviour without changing a measurement.

mod affinity;
mod attest;
mod balance;
mod bridge;
mod config;
mod identity;
mod key;
mod leg;
mod listen;
mod proxy;
mod push;
mod service;
mod tls;
mod upstream;

#[cfg(not(any(feature = "dev-attestation", feature = "sev-snp")))]
compile_error!(
    "no attestation backend selected: build with `dev-attestation` (the default, a \
     software test key) or `sev-snp` (real hardware attestation)"
);

// The two backends are a choice, not an addition — see `[features]`.
#[cfg(all(feature = "sev-snp", feature = "dev-attestation"))]
compile_error!(
    "both attestation backends selected: `sev-snp` needs `--no-default-features`, \
     otherwise the default `dev-attestation` comes along with it"
);

#[cfg(all(feature = "sev-snp", not(target_os = "linux")))]
compile_error!(
    "feature `sev-snp` needs /dev/sev-guest, which exists only inside a Linux guest. \
     Build without it for non-Linux dev environments."
);

use std::sync::Arc;

use pingora_core::services::background::background_service;
use safe_logger::{debug, reason, safe};
use tokio::sync::watch;

/// How many public connections this role serves at once.
///
/// A ceiling on descriptors and on memory, both of which a public connection
/// spends — see `crate::bridge`, which is where it is taken. It is a constant of
/// the build rather than something the host sets, because the two budgets it
/// divides are this image's: the descriptor limit it boots with, and the guest's
/// memory. The host decides how many of these guests to run.
///
/// STALE, and now doubly so: it was sized when a connection could pin 5 MiB of
/// windows, and since the bridge each one costs THREE descriptors here rather
/// than one. It also bounds the wrong half — a leg is opened per request in
/// flight, not per connection, and one connection may carry a hundred of them.
/// Derive it from a measured per-connection footprint, and bound legs
/// separately.
const MAX_PUBLIC_CONNECTIONS: usize = 256;

/// Where the public connection is handed to the proxy library.
///
/// A constant of the build rather than configuration: it is an arrangement
/// INSIDE this guest, between the bridge and the listener, and nothing outside
/// can see it or should be able to choose it — see `crate::bridge`.
const PUBLIC_SOCKET: &str = "/run/gateway-public.sock";

/// A setting this build cannot run without, or the process ends.
///
/// Every one of them is on the measured command line, so an absent value is a
/// launch nobody could have intended rather than a case to fall back from — and
/// naming the key is safe because the key is a constant of this build.
fn required(key: &'static str) -> String {
    std::env::var(key).unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "gateway: {} is not set. Stopping.",
            safe(&key, reason!("a configuration key this build itself names")),
            reason!("a constant naming a configuration key the host itself supplied")
        )
    })
}

/// The key this build serves on.
///
/// Derived from what the chip gives this guest, so it is the same key at every
/// boot and a certificate issued for it outlives a restart — see `crate::key`.
#[cfg(feature = "sev-snp")]
fn serving_key() -> Result<key::Identity, String> {
    let chip = enclavid_attestation::derive_seal_key()
        .map_err(|e| format!("the chip did not return a key to derive from: {e}"))?;
    key::Identity::derived(&chip)
}

/// A developer build has no chip, so it derives from a stand-in that is no
/// secret — see `crate::key::NO_CHIP`. The path is the same one the attested
/// build takes, which is the point.
#[cfg(not(feature = "sev-snp"))]
fn serving_key() -> Result<key::Identity, String> {
    key::Identity::derived(&key::NO_CHIP)
}

/// A panic ends the PROCESS, not the task it happened on.
///
/// Every loop this role runs is a service the server library supervises on a
/// runtime of its own, and a panicking task there dies quietly: the guest would
/// go on serving with no configuration port, or with nothing keeping its members
/// checked, and look perfectly well doing it. Before the library ran them these
/// loops were awaited on the main task, where a panic ended everything — this is
/// how that property is kept.
///
/// It runs AFTER the logging hook, so the panic is still reported before the
/// process goes.
fn end_the_process_on_panic() {
    let reported = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        reported(info);
        std::process::abort()
    }));
}

fn main() {
    // First, so nothing can speak before the channel exists.
    //
    // Panic locations are on. This binary IS the measured code, so a location
    // names a line in a build anyone can fetch and read. The argument is worth
    // rechecking now that it proxies: the far end chooses the input, which is
    // the condition under which the engine roles turn locations off. What keeps
    // it defensible here is that this role parses nothing of what it carries —
    // no path, no body — so there is no per-request site for a caller to steer
    // into.
    safe_logger::install();
    safe_logger::install_panic(true);
    end_the_process_on_panic();

    let health = fleet_transport::health::Health::new();
    let health_addr = required("ENCLAVID_ADDRESS_IN_HEALTH");
    let public_addr = required("ENCLAVID_ADDRESS_IN_PUBLIC");
    let config_addr = required("ENCLAVID_ADDRESS_IN_CONFIG");

    // The key this role serves on, settled before the bind so a guest that
    // cannot hold an identity never takes the port. It never leaves this
    // guest's encrypted memory — which is the only reason terminating here is
    // worth anything, and the reason this cannot be done on the host. The
    // certificate around it comes later, when a push says which names to mint
    // it over; the key outlives every one of them, and every restart — see
    // `crate::key`.
    let identity = Arc::new(serving_key().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "gateway: cannot settle the key this role would serve on. Stopping.",
            reason!("a constant reporting a platform state the host provisioned")
        )
    }));

    // The proof that goes with that key, minted once and before the bind for
    // the same reason: a caller is asked to delegate its choice of api build to
    // this role, and a role that cannot say what it is has nothing to delegate
    // to. It binds the KEY, so it outlives the certificates as well — see
    // `crate::attest`.
    let proof =
        attest::proof(identity.spki().to_vec(), &identity::attestor()).unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "gateway: cannot prove what this build is, so nothing could check it. Stopping.",
                reason!("a constant reporting a platform state the host provisioned")
            )
        });

    // Every api this role may forward to, and every name it answers to, as the
    // host last pushed them. Empty until the first push, and never read from the
    // command line — see `crate::config` for why it cannot be.
    let (table, current) = watch::channel(Arc::new(upstream::Upstreams::empty()));
    let (certificate, presented) = watch::channel(None);
    let inside = bridge::prepare(PUBLIC_SOCKET);

    // Nothing asynchronous has happened yet, and nothing can: the server builds
    // its own runtimes, so every port this role takes is taken inside the
    // service that serves it — see `crate::service`.
    //
    // `None` rather than parsed arguments. The library reads its settings from
    // an `Opt` it never goes looking for, so this build takes its defaults and
    // the command line stays what the measurement says it is: the environment
    // this role reads above, and nothing the library also interprets.
    let mut server = pingora_core::server::Server::new(None).unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "gateway: the server would not start. Stopping.",
            reason!("a constant; it reports no address and no caller")
        )
    });
    // What this does for a server taking over from an older one: collect its
    // listening sockets. This role never does that — a guest is replaced whole
    // and its listener belongs to the host — so with no upgrade asked for, this
    // reduces to a log line and nothing else. It is here because the library's
    // own examples put it here, and leaving it out would be a difference from
    // them that nothing explains.
    server.bootstrap();

    server.add_service(background_service(
        "health",
        service::Health {
            addr: health_addr,
            state: health.clone(),
        },
    ));
    server.add_service(background_service(
        "config",
        service::Config {
            addr: config_addr,
            table: std::sync::Mutex::new(Some(table)),
        },
    ));
    server.add_service(background_service(
        "checks",
        service::Checks {
            table: current.clone(),
        },
    ));
    server.add_service(background_service(
        "certificate",
        service::Certificate {
            table: current.clone(),
            identity,
            publish: std::sync::Mutex::new(Some(certificate)),
        },
    ));
    server.add_service(background_service(
        "bridge",
        service::Bridge {
            addr: public_addr,
            to: inside.clone(),
            at_once: MAX_PUBLIC_CONNECTIONS,
            table: current.clone(),
            state: health,
        },
    ));

    // The library's own listener, its own TLS, and one proxy for every name —
    // see `crate::listen`.
    let hop = proxy::Hop::new(current, proof, Arc::new(leg::Ledger::default()));
    server.add_service(listen::service(
        &inside,
        &server.configuration.clone(),
        hop,
        presented,
    ));

    server.run_forever()
}
