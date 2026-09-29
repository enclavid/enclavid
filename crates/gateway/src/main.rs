//! The `gateway` deployable: the measured role that terminates client TLS.
//!
//! It exists because nothing else can. api's serving listeners speak plain HTTP
//! in a developer build and RA-TLS in the attested one — a certificate that
//! carries a quote, which no browser has a way to trust. So a browser's session
//! for a public name either ends on the host, which ends the central guarantee,
//! or ends in a measured role that holds that name's key. This role is where
//! "TLS-in-TEE for inbound" stops being aspirational. Routing, one public name
//! and fewer certificates are consequences, not the reason.
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
//! It arrives on the same transport as every other fleet port, and the only
//! thing ahead of the handshake is a PROXY protocol header the host's first hop
//! writes, naming who dialled: `crate::listener` reads it, then starts the TLS
//! session on the same stream — unless the hello offers nothing but ACME's
//! `acme-tls/1`, which is an issuer validating a name, and is answered from what
//! the host armed for it. See `crate::listener::acme`.
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
//! `crate::config::push`.
//!
//! The hop to api is RA-TLS in the attested build: this end verifies api's quote
//! and proves it carries the measurement the caller named, and presents nothing,
//! because api asks this end for no certificate — it could not, since what it
//! serves is open to callers that have none. See `crate::upstream`. A developer
//! build speaks plain HTTP on both legs, because there is no host between the two
//! processes to protect anything from.
//!
//! Nothing is served from here but this role's own evidence and the key of its
//! ACME account — see `crate::identity::attest` and `crate::identity::account`.
//! Whatever else it carries is compiled into the
//! build behind it, beside the handlers it calls, so one launch digest covers
//! both. Terminating the session here is still what makes that worth anything — a
//! terminator can replace whatever is served over it, so it has to be measured,
//! and the leg onward has to be attested. Both are.
//!
//! What this role reads of what it carries is little, and fixed: the PROXY
//! header ahead of a connection, the protocols its hello offers, the marker a
//! link carries at the head of a
//! path, its own two paths and the method asked of them, the host a
//! request names — its target's authority and its `Host`, compared to the name
//! the connection agreed to — a header of its own, the build a caller names,
//! and the method and path the name's rules match against. What it takes off
//! by name is the caller's `Host`, the headers in which a request gives an
//! account of its own origin, and trailers. Every other byte — the query, every
//! other header, every body — passes through unread, and the path goes on as
//! it came but for the marker. That is the standing defence against a runtime
//! exploit, which changes behaviour without changing a measurement: what is
//! never interpreted cannot be steered.

mod budget;
mod config;
mod identity;
mod listener;
mod route;
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

// Real evidence in front of a leg that checks nothing: `vsock` is what makes
// the leg to api RA-TLS, and without it the leg is plain and proves no build —
// while this role would still hand callers a quote saying it is the attested
// one. See `crate::upstream`.
#[cfg(all(feature = "sev-snp", not(feature = "vsock")))]
compile_error!(
    "feature `sev-snp` needs `vsock`: without it the leg to api verifies nothing, \
     behind evidence that says this is the attested build"
);

use std::sync::Arc;

use safe_logger::{debug, reason, safe};
use tokio::sync::watch;

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

/// The key this build serves on, and the ACME account key its certificates are
/// issued to.
///
/// Both derived from what the chip gives this guest, each for its own purpose,
/// so they are the same keys at every boot: a certificate issued for the one
/// outlives a restart, and a CAA record naming the other goes on naming this
/// build — see `crate::identity::key` and `crate::identity::account`.
#[cfg(feature = "sev-snp")]
fn keys() -> Result<(identity::key::Identity, identity::account::Account), String> {
    let chip = zeroize::Zeroizing::new(
        enclavid_attestation::derive_seal_key()
            .map_err(|e| format!("the chip did not return a key to derive from: {e}"))?,
    );
    Ok((
        identity::key::Identity::derived(&chip)?,
        identity::account::Account::derived(&chip)?,
    ))
}

/// A developer build has no chip, so it derives from a stand-in that is no
/// secret — see `crate::identity::key::Identity::no_chip`. The path is the same
/// one the attested build takes, which is the point; what the keys may not
/// have is an issued certificate, or an account anything is issued to.
#[cfg(not(feature = "sev-snp"))]
fn keys() -> Result<(identity::key::Identity, identity::account::Account), String> {
    Ok((
        identity::key::Identity::no_chip()?,
        identity::account::Account::no_chip()?,
    ))
}

/// Every loop of this role's own is awaited HERE, on the main task.
///
/// So a panic in any of them ends the process, which is the behaviour worth
/// having: a guest serving with no configuration port, or with a certificate
/// that no longer follows the pushed names, looks perfectly well from the
/// outside and is not.
///
/// A panic in a spawned task does NOT end the process, and that is deliberate
/// too. What this role spawns is per caller, per leg or per member: a task per
/// accepted connection, public or configuration, and whatever the HTTP library
/// spawns under it; a driver per leg to api; a sweep per member, whose loss
/// only leaves aged legs for the next request to that member to close. A hook
/// that aborted on any panic would turn one malformed request into the end of
/// every session in this guest. The line between the two is exactly the line
/// between "this role has stopped working" and "one caller's connection has".
/// A push that panics is the second: the table it would have replaced stays,
/// and the port takes the next.
#[tokio::main]
async fn main() -> std::convert::Infallible {
    // First, so nothing can speak before the channel exists.
    //
    // Panic locations are on. This binary IS the measured code, so a location
    // names a line in a build anyone can fetch and read. The argument is worth
    // rechecking now that it proxies: the far end chooses the input, which is
    // the condition under which the engine roles turn locations off. What keeps
    // it defensible here is how little of that input this role reads — a few
    // fixed shapes, see the module docs — none of it through a path that can
    // panic, so there is no per-request site for a caller to steer into.
    safe_logger::install();
    safe_logger::install_panic(true);

    let descriptors = reserve_descriptors(config::MOST_DESCRIPTORS);
    budget::limit(descriptors);

    let health = fleet_transport::health::Health::new();
    let health_addr = required("ENCLAVID_ADDRESS_IN_HEALTH");
    let public_addr = required("ENCLAVID_ADDRESS_IN_PUBLIC");
    let config_addr = required("ENCLAVID_ADDRESS_IN_CONFIG");

    // One attestor for the process, handed to both of its uses: it mints this
    // role's evidence, and it verifies api on every leg. Building one asks the
    // Secure Processor for a report and checks this platform against the
    // build's floor, so it is built once — and first, so nothing below is
    // derived on a platform that check refuses.
    let attestor = identity::attestor();

    // The key this role serves on, settled before the bind so a guest that
    // cannot hold an identity never takes the port. It never leaves this
    // guest's encrypted memory — which is the only reason terminating here is
    // worth anything, and the reason this cannot be done on the host. The
    // certificate around it comes later, when a push says which names to mint
    // it over; the key outlives every one of them, and every restart — see
    // `crate::identity::key`. The account key beside it is derived with it,
    // and stays as close.
    let (identity, account) = keys().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "gateway: cannot settle the keys this role would serve on and sign with. Stopping.",
            reason!("a constant reporting a platform state the host provisioned")
        )
    });
    let (identity, account) = (Arc::new(identity), Arc::new(account));

    // The evidence that goes with that key, minted once and before the bind for
    // the same reason: a caller is asked to delegate its choice of api build to
    // this role, and a role that cannot say what it is has nothing to delegate
    // to. It binds the KEY, so it outlives the certificates as well — see
    // `crate::identity::attest`.
    let spki = identity.spki().to_vec();
    let evidence = identity::attest::evidence(spki, &attestor).unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "gateway: cannot prove what this build is, so nothing could check it. Stopping.",
            reason!("a constant reporting a platform state the host provisioned")
        )
    });

    // Every api this role may forward to, and every name it answers to, as the
    // host last pushed them. Empty until the first push, and never read from the
    // command line — see `crate::config` for why it cannot be.
    let (table, current) = watch::channel(Arc::new(upstream::Upstreams::empty(attestor)));
    let (certificate, presented) = watch::channel(None);
    // Certificates an issuer signed over the same key, once the host pushes
    // some — see `crate::config::push`. Until then this role presents its own.
    let (issued, accepted) = watch::channel(Vec::new());

    let health_port = fleet_transport::health::bind(&health_addr).await;
    let config_port = fleet_transport::bind(&config_addr)
        .await
        .unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "gateway: cannot bind the configuration port at {}. Stopping.",
                safe(&config_addr, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        });

    let hop = Arc::new(route::Hop::new(
        current.clone(),
        evidence,
        bytes::Bytes::copy_from_slice(account.jwk().as_bytes()),
    ));
    let tls = listener::certificate::acceptor(presented);
    // What a validator is answered with, armed through the configuration port
    // and read by the public listener — see `crate::listener::acme`.
    let challenges = Arc::new(listener::acme::Challenges::new());

    // Awaited together, and none of them ever returns — see the note above.
    // The first to end takes the process with it, which is what "this role has
    // stopped working" should look like from the outside.
    tokio::select! {
        ended = fleet_transport::health::serve(health_port, {
            let state = health.clone();
            move || state.body()
        }) => ended,
        ended = config::push::serve(
            config_port,
            config::push::Port::new(
                table,
                descriptors,
                identity.clone(),
                account,
                challenges.clone(),
                issued,
            ),
        ) => ended,
        ended = listener::certificate::follow(current.clone(), accepted, identity, certificate) => ended,
        ended = public(public_addr, current, hop, tls, challenges, health) => ended,
    }
}

/// Take as many descriptors as the largest tuning could need, or as many as the
/// kernel gives, and say how many that is.
///
/// A push's connection limits are counts of descriptors, and a limit the
/// descriptor table cannot back is not one: the moment it is reached, dials to
/// api fail, then accepts, then the configuration and health ports — every
/// caller at once, and the host unable to push a fix. So the limit is raised
/// toward `needed`, and what it reaches is what every push is measured against —
/// one that could need more is refused at the push, where the host is told why
/// — and what `crate::budget` counts callers against.
///
/// Both numbers are safe to log: the guest's kernel sets the one, and the other
/// is this build's constant.
fn reserve_descriptors(needed: libc::rlim_t) -> u64 {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a stack-local `rlimit` passed by pointer for the duration of the
    // call, the standard POSIX shape; a non-zero return leaves it untouched.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        safe_logger::error_and_panic!(
            "gateway: cannot read RLIMIT_NOFILE, so the descriptor budget cannot be checked. \
             Stopping.",
            reason!("a constant, emitted once at boot before any session exists")
        )
    }
    // First the hard limit as well. This role is its guest's one process and
    // runs as root, and nothing else in the image raises the kernel's default —
    // so the ceiling is this process's to lift, and it lifts it. Where it may
    // not, the soft limit goes as far as the hard one; where the kernel holds
    // the soft limit lower still, as far as it will.
    let mut asks = vec![(needed, needed.max(limit.rlim_max))];
    let mut soft = needed.min(limit.rlim_max);
    while soft > limit.rlim_cur {
        asks.push((soft, limit.rlim_max));
        soft /= 2;
    }
    for (soft, hard) in asks {
        if soft <= limit.rlim_cur {
            break;
        }
        let raised = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        // SAFETY: as above.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            limit = raised;
            break;
        }
    }

    let available = limit.rlim_cur;
    safe_logger::info!(
        "gateway: {} file descriptors available, of the {} the largest tuning could need; \
         a push needing more is refused",
        safe(&available, reason!("a limit this guest's own kernel sets")),
        safe(&needed, reason!("a constant of the measured build")),
        reason!("a constant, emitted once at boot before any session exists")
    );
    available
}

/// The public listener, opened only once there is a table to route against.
///
/// One push, not a non-empty table: declaring no group at all is a state the
/// host may choose, and it is still a table. Open before there is one, every
/// request would fail as an unavailable upstream, and the host could not tell a
/// guest that responds from one that routes.
async fn public(
    addr: String,
    mut table: watch::Receiver<Arc<upstream::Upstreams>>,
    hop: Arc<route::Hop>,
    tls: tokio_rustls::TlsAcceptor,
    challenges: Arc<listener::acme::Challenges>,
    health: Arc<fleet_transport::health::Health>,
) -> std::convert::Infallible {
    if table.changed().await.is_err() {
        // The sender lives as long as the process, so this cannot happen while
        // anything is still serving.
        std::future::pending::<()>().await;
    }

    let listener = fleet_transport::bind(&addr).await.unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "gateway: cannot bind the public listener at {}. Stopping.",
            safe(&addr, reason!("on the measured command line")),
            reason!("a constant; the address is the host's own configuration")
        )
    });
    // Said after the bind, not before: "listening" is a claim about a socket
    // that exists.
    safe_logger::info!(
        "gateway: listening for public connections on {}",
        safe(&addr, reason!("on the measured command line")),
        reason!("a constant, emitted once at boot before any session exists")
    );
    health.declare_healthy();
    listener::serve(listener, hop, tls, challenges, table).await
}
