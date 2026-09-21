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
mod config;
mod identity;
mod key;
mod leg;
mod listen;
mod probe;
mod proxy;
mod push;
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

use safe_logger::{debug, info, reason, safe};
use tokio::sync::watch;

/// How many public connections this role serves at once.
///
/// A ceiling on descriptors and on memory, both of which a public connection
/// spends — see where it is taken. It is a constant of the build rather than
/// something the host sets, because the two budgets it divides are this image's:
/// the descriptor limit it boots with, and the guest's memory. The host decides
/// how many of these guests to run.
const MAX_PUBLIC_CONNECTIONS: usize = 256;

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

#[tokio::main]
async fn main() {
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

    // The health port, up before anything that can be slow, and bound on THIS
    // task rather than inside the spawn — binding inside would turn a failure
    // into one dead task and a guest that serves with no health port. See
    // `fleet_transport::health::bind`.
    let health = fleet_transport::health::Health::new();
    {
        let health_addr = required("ENCLAVID_ADDRESS_IN_HEALTH");
        let listener = fleet_transport::health::bind(&health_addr).await;
        let health = health.clone();
        tokio::spawn(async move {
            fleet_transport::health::serve(listener, move || health.body()).await
        });
    }

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
    let (table, mut current) = watch::channel(Arc::new(upstream::Upstreams::empty()));

    let config_listener = fleet_transport::bind(&config_addr)
        .await
        .unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "gateway: cannot bind the configuration port at {}. Stopping.",
                safe(&config_addr, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        });
    info!(
        "gateway: taking configuration on {}; serving nothing until the first push",
        safe(&config_addr, reason!("on the measured command line")),
        reason!("a constant, emitted once at boot before any session exists")
    );

    // Polled on this task for the life of the process, never spawned: a panic
    // in it then ends the process instead of one task, and a role that can no
    // longer be reconfigured does not go on serving a table nobody can change.
    let pushes = push::serve(config_listener, table);
    tokio::pin!(pushes);

    // The public port stays closed until there is a table. Open before it, every
    // request would fail as an unavailable upstream, and the host would see a
    // guest that answers and cannot tell it from one that routes.
    tokio::select! {
        first = current.changed() => first.expect("the sender lives in `pushes`, still held here"),
        never = &mut pushes => never,
    }

    // Asking each api what it knows about itself, on this task for the same
    // reason the push loop is: a role that stopped asking would keep placing new
    // sessions on what it last believed.
    let probes = probe::probe_forever(current.clone());
    tokio::pin!(probes);

    let listener = fleet_transport::bind(&public_addr)
        .await
        .unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "gateway: cannot bind the public listener at {}. Stopping.",
                safe(&public_addr, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        });

    // Said after the bind, not after the spawn: "listening" is a claim about a
    // socket that exists.
    info!(
        "gateway: listening for public connections on {}",
        safe(&public_addr, reason!("on the measured command line")),
        reason!("a constant, emitted once at boot before any session exists")
    );
    health.declare_healthy();

    // Spawn and return at once. `accept_forever` AWAITS this closure, so doing
    // the handshake here would put every peer behind the slowest one — which is
    // the same defect that rules out `axum::serve` for a TLS listener. See
    // `serve::connection`.
    //
    // The permit is what bounds this role: every public connection costs a
    // descriptor here, a descriptor and a connection at api, and the memory of
    // whatever api has sent that the caller has not yet taken. Without a ceiling
    // one caller opening connections takes all three until an accept fails, and
    // a failing accept stops every other caller too. Taken BEFORE the spawn, so
    // the wait happens here and unaccepted connections queue in the listener's
    // backlog rather than inside this process.
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_PUBLIC_CONNECTIONS));
    // Built once and shared: it holds sizes and timeouts, nothing about a
    // caller.
    let conf = Arc::new(pingora_core::server::configuration::ServerConf::default());

    // What it takes to answer a connection — a certificate over the names the
    // host declared, and a door for each of them — rebuilt whenever those names
    // change. On this task for the same reason as the others: a role that
    // stopped rebuilding would present a certificate for names it no longer
    // serves.
    let (serving, current_public) = watch::channel(None);
    let following = listen::follow(current.clone(), identity, proof, conf, serving);
    tokio::pin!(following);

    let public = fleet_transport::accept_forever(listener, move |stream, peer| {
        let current_public = current_public.clone();
        let slots = slots.clone();
        async move {
            // Nothing to answer with until the first push has been acted on.
            // Dropping is the honest answer: a handshake needs a certificate,
            // and there is none.
            let Some(public) = current_public.borrow().clone() else {
                return;
            };
            let Ok(slot) = slots.acquire_owned().await else {
                return;
            };
            tokio::spawn(async move {
                listen::connection(public, stream, peer).await;
                drop(slot);
            });
        }
    });

    tokio::select! {
        never = public => never,
        never = &mut pushes => never,
        never = &mut probes => never,
        never = &mut following => never,
    }
}
