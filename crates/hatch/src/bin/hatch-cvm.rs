//! The `hatch-cvm` deployable: the fleet's one way out. LISTENS for api over
//! mutual RA-TLS and serves `hatch-rpc` on one remoc connection per api.
//!
//! It holds no applicant data and no seal key. What api hands it — a
//! consumer's credential to ask the authorization hook about, a registry
//! bearer, a broker leg — goes to the party it is for and nowhere else, and
//! what comes back is checked by api where it arrives.
//!
//! The listener is whatever `fleet-transport` selects at compile time, wrapped
//! in RA-TLS either way: vsock in the measured build, TCP on a developer box.
//! So are the hooks: a port of the host in the measured build, of localhost on
//! a developer box.

use std::sync::Arc;
use std::time::Duration;

use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;

use enclavid_hatch::hooks::Hooks;
use enclavid_hatch::oci::{DEFAULT_CONCURRENT_BLOBS, DEFAULT_CONCURRENT_MANIFESTS, Pulls};
use enclavid_hatch::service::Hatch;
use fleet_transport::LegFailure;
use fleet_transport::launch::{LaunchError, Settings};
use hatch_rpc::{HatchClient, HatchServiceServerShared, LegSettings};
use safe_logger::{debug, info, reason, safe, warn};

/// How long a hook has to answer, unless the host says otherwise (the
/// `hook-deadline-secs` setting). A hook is on this host, and answers from what
/// it holds — under api's own wait for an authorization, which a creation's two
/// questions have to clear together.
const DEFAULT_HOOK_DEADLINE: Duration = Duration::from_secs(10);
/// How many calls the service takes off a connection ahead of handling them,
/// unless the host says otherwise (the `request-buffer` setting) — not how many
/// run at once: remoc spawns a handler for each call it takes.
const DEFAULT_REQUEST_BUFFER: usize = 16;

#[cfg(not(any(feature = "dev-attestation", feature = "sev-snp")))]
compile_error!(
    "no attestation backend selected: build with `dev-attestation` (the default, a \
     software test key) or `sev-snp` (real hardware attestation)"
);

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

/// The identity this role presents on its leg, and what it asks of api.
///
/// api pins which image this is; this end does not pin api back, for the
/// reason every leaf gives: api's measurement is a function of the ones it
/// pins, this one's among them. `AcceptAny` still runs the whole quote check —
/// a genuine AMD part, its posture, its TCB floor, the quote bound to the TLS
/// key in front of it — and what it leaves open, which guest of this host is
/// calling, the relay in front of this port closes: it takes calls from api
/// alone.
///
/// Minting is `mint_only`: this guest's launch gives it no certificate that
/// would endorse its own report. api's own report carries the chain it is
/// checked by.
#[cfg(feature = "sev-snp")]
fn fleet_identity() -> (
    Arc<dyn enclavid_attestation::Attestor>,
    enclavid_ra_tls::MeasurementPolicy,
) {
    let attestor = enclavid_attestation::SnpAttestor::mint_only().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "hatch-cvm: cannot present an attested identity — /dev/sev-guest is absent, or this \
             guest was launched in a posture this build refuses (VMPL, debug, migration \
             agent, TCB floor). Stopping.",
            reason!("a constant reporting a platform state the host provisioned")
        )
    });
    (
        Arc::new(attestor),
        enclavid_ra_tls::MeasurementPolicy::AcceptAny,
    )
}

/// The dev fleet's one shared software identity, pinned to itself.
#[cfg(feature = "dev-attestation")]
fn fleet_identity() -> (
    Arc<dyn enclavid_attestation::Attestor>,
    enclavid_ra_tls::MeasurementPolicy,
) {
    (
        Arc::new(enclavid_attestation::MockAttestor::dev_fleet()),
        enclavid_ra_tls::MeasurementPolicy::Pinned(vec![
            enclavid_attestation::DEV_FLEET_MEASUREMENT.to_string(),
        ]),
    )
}

/// The setting `key` the host gave at launch: `default` when it gave none, and
/// no boot when it gave one that does not parse.
fn setting<T: std::str::FromStr>(launch: &mut Settings, key: &'static str, default: T) -> T {
    launch
        .take(key)
        .map(|value| parse(key, &value))
        .unwrap_or(default)
}

fn parse<T: std::str::FromStr>(key: &'static str, value: &str) -> T {
    value.parse().unwrap_or_else(|_| {
        safe_logger::error_and_panic!(
            "hatch-cvm: the setting {} does not parse. Stopping.",
            safe(
                &key,
                reason!("a constant naming one of this role's settings")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        )
    })
}

fn secs(launch: &mut Settings, key: &'static str, default: Duration) -> Duration {
    Duration::from_secs(setting(launch, key, default.as_secs()))
}

fn millis(launch: &mut Settings, key: &'static str, default: Duration) -> Duration {
    let default = u64::try_from(default.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(setting(launch, key, default))
}

/// Where a hook is, from the port its setting names — switched off where the
/// host names none. A port of the host in the measured build, which is the only
/// address a guest reaches; of localhost on a developer box.
fn hook(launch: &mut Settings, key: &'static str) -> Option<String> {
    let port: u32 = parse(key, &launch.take(key)?);
    if port == 0 || port == u32::MAX {
        safe_logger::error_and_panic!(
            "hatch-cvm: the setting {} names no port. Stopping.",
            safe(
                &key,
                reason!("a constant naming one of this role's settings")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        );
    }
    Some(if cfg!(feature = "vsock") {
        format!("vsock://2:{port}")
    } else {
        format!("127.0.0.1:{port}")
    })
}

fn refused(e: LaunchError) -> ! {
    safe_logger::error_and_panic!(
        "hatch-cvm: {}. Stopping.",
        e,
        reason!("a constant, emitted once at boot before any request exists")
    )
}

fn required(key: &'static str) -> String {
    std::env::var(key).unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "hatch-cvm: {} is not set. Stopping.",
            safe(&key, reason!("a configuration key named in this image")),
            reason!("a constant naming a configuration key the host itself supplied")
        )
    })
}

#[tokio::main]
async fn main() {
    safe_logger::install();
    safe_logger::install_panic(true);
    // Every certificate a registry or a broker presents is checked by this
    // clock; the guest ends once the kernel stops vouching for it.
    #[cfg(feature = "vsock")]
    timesync::guard();

    let mut launch = Settings::load("hatch").unwrap_or_else(|e| refused(e));
    let manifests: usize = setting(
        &mut launch,
        "concurrent-manifests",
        DEFAULT_CONCURRENT_MANIFESTS,
    );
    let blobs: usize = setting(&mut launch, "concurrent-blobs", DEFAULT_CONCURRENT_BLOBS);
    let authorize_hook = hook(&mut launch, "authorize-hook-port");
    let limits_hook = hook(&mut launch, "limits-hook-port");
    let hook_deadline = secs(&mut launch, "hook-deadline-secs", DEFAULT_HOOK_DEADLINE);
    let request_buffer: usize = setting(&mut launch, "request-buffer", DEFAULT_REQUEST_BUFFER);
    let leg_default = LegSettings::default();
    let leg = LegSettings {
        timeout: secs(&mut launch, "leg-timeout-secs", leg_default.timeout),
        max_ports: setting(&mut launch, "leg-max-ports", leg_default.max_ports),
        chunk_bytes: setting(&mut launch, "leg-chunk-bytes", leg_default.chunk_bytes),
        receive_bytes: setting(&mut launch, "leg-receive-bytes", leg_default.receive_bytes),
    };
    let accept_retry = millis(
        &mut launch,
        "accept-retry-ms",
        fleet_transport::DEFAULT_ACCEPT_RETRY,
    );
    launch.finish().unwrap_or_else(|e| refused(e));
    // No turn at a registry, a hook with no time to answer, a service with no
    // request buffer and a listener that retries at once are all a hatch that
    // serves nothing.
    if manifests == 0
        || blobs == 0
        || hook_deadline.is_zero()
        || request_buffer == 0
        || accept_retry.is_zero()
    {
        safe_logger::error_and_panic!(
            "hatch-cvm: the concurrent manifests and blobs, the hook deadline, the request \
             buffer and the accept retry must be above zero. Stopping.",
            reason!("a constant naming configuration keys the host itself supplied")
        );
    }
    if let Some(refusal) = leg.refusal() {
        safe_logger::error_and_panic!(
            "hatch-cvm: {} cannot hold a leg up. Stopping.",
            safe(
                &refusal,
                reason!("a constant naming which of this role's settings")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        );
    }

    let health = fleet_transport::health::Health::new();
    {
        let health_addr = required("ENCLAVID_HATCH_HEALTH_LISTEN");
        let listener = fleet_transport::health::bind(&health_addr)
            .await
            .with_accept_retry(accept_retry);
        let health = health.clone();
        tokio::spawn(async move {
            fleet_transport::health::serve(listener, move || health.body()).await
        });
    }

    let kbs = enclavid_hatch::kbs::client().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "hatch-cvm: cannot build the key broker client. Stopping.",
            reason!("a constant")
        )
    });
    let hatch = Arc::new(Hatch {
        hooks: Hooks::new(authorize_hook.clone(), limits_hook.clone(), hook_deadline),
        pulls: Pulls::new(manifests, blobs),
        kbs,
    });

    let listen = required("ENCLAVID_HATCH_LISTEN");
    let listener = fleet_transport::bind(&listen)
        .await
        .unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "hatch-cvm: cannot bind {}. Stopping.",
                safe(&listen, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        })
        .with_accept_retry(accept_retry);
    let named = |hook: &Option<String>| hook.clone().unwrap_or_else(|| "off".into());
    info!(
        "hatch-cvm: listening on {}, authorize hook {}, limits hook {}, hook deadline {:?}, \
         {} manifests and {} blobs at once, request buffer={}, leg_timeout={:?}, \
         leg_max_ports={}, leg_chunk={} bytes, leg_receive={} bytes, accept_retry={:?}",
        safe(&listen, reason!("on the measured command line")),
        safe(
            &named(&authorize_hook),
            reason!("a port of the host the host's own setting names")
        ),
        safe(
            &named(&limits_hook),
            reason!("a port of the host the host's own setting names")
        ),
        safe(
            &hook_deadline,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &manifests,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &blobs,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &request_buffer,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &leg.timeout,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &leg.max_ports,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &leg.chunk_bytes,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &leg.receive_bytes,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &accept_retry,
            reason!("the host's own setting, or this build's default")
        ),
        reason!("a constant, emitted once at boot")
    );

    let (attestor, policy) = fleet_identity();
    let ratls = tokio_rustls::TlsAcceptor::from(Arc::new(
        enclavid_ra_tls::server_config(attestor, policy).unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "hatch-cvm: cannot build the RA-TLS server config. Stopping.",
                reason!("a constant reporting a platform state the host provisioned")
            )
        }),
    ));

    health.declare_healthy();
    fleet_transport::accept_forever(listener, move |stream, peer| {
        let hatch = hatch.clone();
        let ratls = ratls.clone();
        async move {
            tokio::spawn(async move {
                if let Err(e) = serve_conn(stream, ratls, hatch, request_buffer, leg).await {
                    warn!(
                        "hatch-cvm: connection from {} ended ({})",
                        safe(&peer, reason!("an address the host routed itself")),
                        e,
                        reason!(
                            "constant text; a connection closing is already visible to \
                             whoever carries it"
                        )
                    );
                }
            });
        }
    })
    .await
}

/// RA-TLS-accept one api connection, frame it with remoc on this end's `leg`
/// settings, and serve the hatch on it — its client sent to api on the base
/// channel.
async fn serve_conn(
    stream: fleet_transport::Stream,
    ratls: tokio_rustls::TlsAcceptor,
    hatch: Arc<Hatch>,
    request_buffer: usize,
    leg: LegSettings,
) -> Result<(), LegFailure> {
    let tls = ratls.accept(stream).await.map_err(|e| {
        debug!("ra-tls accept: {e}");
        LegFailure::Attest
    })?;
    let (read, write) = tokio::io::split(tls);
    let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, HatchClient, HatchClient, Ciborium>(
        hatch_rpc::connection_cfg(&leg),
        read,
        write,
    )
    .await
    .map_err(|e| {
        debug!("rpc connect: {e}");
        LegFailure::Rpc
    })?;
    tokio::spawn(conn);

    let (server, client) = HatchServiceServerShared::<_, Ciborium>::new(hatch, request_buffer);
    tx.send(client).await.map_err(|e| {
        debug!("send service client: {e}");
        LegFailure::Clients
    })?;
    server.serve(true).await.map_err(|e| {
        debug!("serve: {e}");
        LegFailure::Serve
    })
}
