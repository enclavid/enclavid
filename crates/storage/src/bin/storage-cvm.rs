//! The `storage-cvm` deployable: the trusted storage node. LISTENS for the
//! orchestrator (api) over mutual RA-TLS and serves BOTH `storage-rpc` services
//! — `SessionStoreService` (one SQLite file per session) + `CacheService`
//! (object_store) — on one remoc connection. Started by INFRASTRUCTURE, exactly
//! like the hatch and the engine workers.
//!
//! **Blind.** It holds no `tee_seal_key` and no applicant token; every payload is
//! already AEAD-sealed TEE-side. RA-TLS proves the peer is an attested guest and
//! hides the access pattern + key from the untrusted host; the sealed payload
//! means even a storage-CVM compromise leaks only ciphertext. WHICH attested
//! guest it is, this node cannot demand — so it partitions its records by the
//! digest the peer proved instead of trusting that only api calls
//! (`enclavid_storage::scope`).
//!
//! The listener is whatever `fleet-transport` selects at compile time, wrapped
//! in RA-TLS either way: vsock in the measured build, TCP on a developer box.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use object_store::local::LocalFileSystem;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;

use enclavid_storage::{
    CacheBlobs, Caller, DEFAULT_BUSY_TIMEOUT, SessionStore, StorageSvc, now_unix,
};
use fleet_transport::LegFailure;
use fleet_transport::launch::{LaunchError, Settings};
use safe_logger::{debug, info, reason, safe, warn};
use storage_rpc::{
    CacheServiceServerShared, LegSettings, SessionStoreServiceServerShared, StorageClients,
};

/// How many expired sessions the sweeper purges per tick, unless the host says
/// otherwise (the `sweep-batch` setting): what bounds one sweep pass.
const DEFAULT_SWEEP_BATCH: usize = 1024;
/// What the compiled-bundle cache may hold, unless the host says otherwise (the
/// `cache-bytes` setting), the bundles being written counted with the ones
/// written. 4 GiB holds three bundles carrying a gigabyte of data each beside
/// hundreds of ordinary ones (about 8 MiB each), and leaves the sessions most
/// of the 12 GiB volume the cache shares with them.
const DEFAULT_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// What a compiled bundle loaded from the cache is read from disk in, and so
/// streamed in, unless the host says otherwise (the `cache-read-bytes`
/// setting). Past a leg's chunk a piece adds nothing to how fast it crosses;
/// below it, each piece is a frame of its own. Never zero: a read of nothing
/// would never reach the end.
const DEFAULT_CACHE_READ_BYTES: NonZeroUsize = NonZeroUsize::new(1024 * 1024).unwrap();
/// How often expired sessions are swept, unless the host says otherwise (the
/// `sweep-secs` setting). The host's to choose like the clock the sweep reads.
const DEFAULT_SWEEP_SECS: u64 = 60;
/// How many calls each service takes off a connection ahead of handling them,
/// unless the host says otherwise (the `session-request-buffer` and
/// `cache-request-buffer` settings) — not how many run at once: remoc spawns a
/// handler for each call it takes.
const DEFAULT_SESSION_REQUEST_BUFFER: usize = 16;
const DEFAULT_CACHE_REQUEST_BUFFER: usize = 8;

/// Each service's request buffer, as the boot read them.
#[derive(Clone, Copy)]
struct RequestBuffers {
    session: usize,
    cache: usize,
}

#[cfg(not(any(feature = "dev-attestation", feature = "sev-snp")))]
compile_error!(
    "no attestation backend selected: build with `dev-attestation` (the default, a \
     software test key) or `sev-snp` (real hardware attestation)"
);

// The two attestation backends are a choice, not an addition — see `[features]`.
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

/// The identity this role presents on a fleet leg, and what it asks of api.
///
/// **Asymmetric on purpose, and the direction is load-bearing.** api pins which
/// image this is; this end does not pin api back. It cannot: pinning api's
/// measurement would require knowing it before api is built, and api's is a
/// function of the three measurements it pins. Leaves first, api last, no cycle.
///
/// So `AcceptAny` here is not an absence of attestation. `verify_quote` runs
/// whole — a genuine AMD part, VMPL 0, debug off, no migration agent, platform
/// TCB above this build's floor, and the quote bound to the very TLS key in
/// front of it. What it does not check is WHICH image is on the other end —
/// nor, because a verifier holding no endorsement reads the chain out of the
/// peer's own quote, which machine. The peer is a genuine SNP guest on some
/// Milan part, and that is the whole of it.
///
/// What that costs here: records are partitioned by the digest the peer proved, so one caller cannot reach another's (`enclavid_storage::scope`). That is the property to keep whole, since it
/// is the one carrying the weight the pin would have carried.
///
/// Minting is `mint_only`: this guest has no egress, so it cannot fetch the
/// certificate that would endorse its own report. It sends the report bare and
/// api, which reaches AMD through the hatch, verifies it against its own copy of
/// the same chip's — which proves more than a self-endorsed quote would, not
/// less.
#[cfg(feature = "sev-snp")]
fn fleet_identity() -> (
    std::sync::Arc<dyn enclavid_attestation::Attestor>,
    enclavid_ra_tls::MeasurementPolicy,
) {
    let attestor = enclavid_attestation::SnpAttestor::mint_only().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "storage-cvm: cannot present an attested identity — /dev/sev-guest is absent, or this \
             guest was launched in a posture this build refuses (VMPL, debug, migration \
             agent, TCB floor). Stopping.",
            reason!("a constant reporting a platform state the host provisioned")
        )
    });
    (
        std::sync::Arc::new(attestor),
        enclavid_ra_tls::MeasurementPolicy::AcceptAny,
    )
}

/// The dev fleet's one shared software identity, pinned to itself. It proves
/// the peer links this source tree and nothing about where it runs — which is
/// all a fleet without hardware can say.
#[cfg(feature = "dev-attestation")]
fn fleet_identity() -> (
    std::sync::Arc<dyn enclavid_attestation::Attestor>,
    enclavid_ra_tls::MeasurementPolicy,
) {
    (
        std::sync::Arc::new(enclavid_attestation::MockAttestor::dev_fleet()),
        enclavid_ra_tls::MeasurementPolicy::Pinned(vec![
            enclavid_attestation::DEV_FLEET_MEASUREMENT.to_string(),
        ]),
    )
}

/// The setting `key` the host gave at launch (see [`fleet_transport::launch`]):
/// `default` when it gave none, and no boot when it gave one that does not
/// parse. A value the host wrote and got wrong is not a request for the default.
fn setting<T: std::str::FromStr>(launch: &mut Settings, key: &'static str, default: T) -> T {
    match launch.take(key) {
        None => default,
        Some(value) => value.parse().unwrap_or_else(|_| {
            safe_logger::error_and_panic!(
                "storage-cvm: the setting {} does not parse. Stopping.",
                safe(
                    &key,
                    reason!("a constant naming one of this role's settings")
                ),
                reason!("a constant, emitted once at boot before any request exists")
            )
        }),
    }
}

/// A setting given in whole seconds.
fn secs(launch: &mut Settings, key: &'static str, default: Duration) -> Duration {
    Duration::from_secs(setting(launch, key, default.as_secs()))
}

/// A setting given in milliseconds.
fn millis(launch: &mut Settings, key: &'static str, default: Duration) -> Duration {
    let default = u64::try_from(default.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(setting(launch, key, default))
}

/// The host's launch settings could not be taken as given.
fn refused(e: LaunchError) -> ! {
    safe_logger::error_and_panic!(
        "storage-cvm: {}. Stopping.",
        e,
        reason!("a constant, emitted once at boot before any request exists")
    )
}

#[tokio::main]
async fn main() {
    // First, so nothing can speak before the channel exists. Panic locations are
    // on: this binary IS the measured code, and it holds only ciphertext.
    safe_logger::install();
    safe_logger::install_panic(true);

    // The host's settings for this guest, read once and before anything else:
    // reading them talks to nothing, and the health port below is one of the
    // listeners they set. Every one of them is about how this node keeps up with
    // what it holds — what it holds is ciphertext either way.
    let mut launch = Settings::load("storage").unwrap_or_else(|e| refused(e));
    let sweep_secs: u64 = setting(&mut launch, "sweep-secs", DEFAULT_SWEEP_SECS);
    let sweep_batch: usize = setting(&mut launch, "sweep-batch", DEFAULT_SWEEP_BATCH);
    let cache_bytes: u64 = setting(&mut launch, "cache-bytes", DEFAULT_CACHE_BYTES);
    let cache_read: NonZeroUsize =
        setting(&mut launch, "cache-read-bytes", DEFAULT_CACHE_READ_BYTES);
    let buffers = RequestBuffers {
        session: setting(
            &mut launch,
            "session-request-buffer",
            DEFAULT_SESSION_REQUEST_BUFFER,
        ),
        cache: setting(
            &mut launch,
            "cache-request-buffer",
            DEFAULT_CACHE_REQUEST_BUFFER,
        ),
    };
    let db_busy = secs(&mut launch, "db-busy-secs", DEFAULT_BUSY_TIMEOUT);
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
    // A sweep every zero seconds would spin the sweeper without a pause, a
    // batch of zero would sweep nothing, a service with no request buffer
    // cannot be built, a zero busy timeout fails every statement that meets a
    // lock, and a zero accept retry spins on a listener that cannot accept.
    if sweep_secs == 0
        || sweep_batch == 0
        || buffers.session == 0
        || buffers.cache == 0
        || db_busy.is_zero()
        || accept_retry.is_zero()
    {
        safe_logger::error_and_panic!(
            "storage-cvm: the sweep period, the sweep batch, both request buffers, the \
             database busy timeout and the accept retry must be above zero. Stopping.",
            reason!("a constant naming configuration keys the host itself supplied")
        );
    }
    if let Some(refusal) = leg.refusal() {
        safe_logger::error_and_panic!(
            "storage-cvm: {} cannot hold a leg up. Stopping.",
            safe(
                &refusal,
                reason!("a constant naming which of this role's settings")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        );
    }

    // The health port, up before anything that can be slow. The host polls it to
    // learn when this role has finished coming up — which is what lets it bring
    // the fleet up in order instead of racing it, and what replaced the old
    // "give up after a fixed budget so that silence means broken".
    //
    // Bound FIRST on purpose: everything below can take time (opening stores,
    // minting an attestation), and a port that only appears afterwards cannot
    // report the interval it exists to describe.
    let health = fleet_transport::health::Health::new();
    {
        let health_addr = std::env::var("ENCLAVID_STORAGE_HEALTH_LISTEN").unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "storage-cvm: ENCLAVID_STORAGE_HEALTH_LISTEN is not set. Stopping.",
                reason!("a constant naming a configuration key the host itself supplied")
            )
        });
        // Bound HERE, on this task, and only the answering loop is spawned:
        // binding inside the spawn would turn a failure into one dead task and
        // a guest that serves with no health port. See `health::bind`.
        let listener = fleet_transport::health::bind(&health_addr)
            .await
            .with_accept_retry(accept_retry);
        let health = health.clone();
        tokio::spawn(async move {
            fleet_transport::health::serve(listener, move || health.body()).await
        });
    }

    // Explicit config; fail loud if unset (minimal-defaults).
    let listen = std::env::var("ENCLAVID_STORAGE_LISTEN").unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "storage-cvm: ENCLAVID_STORAGE_LISTEN is not set. Stopping.",
            reason!("a constant naming a configuration key the host itself supplied")
        )
    });
    let sessions_dir = std::env::var("ENCLAVID_STORAGE_SESSIONS_DIR").unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "storage-cvm: ENCLAVID_STORAGE_SESSIONS_DIR is not set. Stopping.",
            reason!("a constant naming a configuration key the host itself supplied")
        )
    });
    let cache_dir = std::env::var("ENCLAVID_STORAGE_CACHE_DIR").unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "storage-cvm: ENCLAVID_STORAGE_CACHE_DIR is not set. Stopping.",
            reason!("a constant naming a configuration key the host itself supplied")
        )
    });
    let sessions = Arc::new(
        SessionStore::open(&sessions_dir, db_busy).unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "storage-cvm: cannot open the session store at {}. Stopping.",
                safe(&sessions_dir, reason!("on the measured command line")),
                reason!("a constant; the path is the host's own configuration")
            )
        }),
    );

    std::fs::create_dir_all(&cache_dir).unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "storage-cvm: cannot create the cache directory at {}. Stopping.",
            safe(&cache_dir, reason!("on the measured command line")),
            reason!("a constant; the path is the host's own configuration")
        )
    });
    let store = Arc::new(
        LocalFileSystem::new_with_prefix(&cache_dir).unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "storage-cvm: cannot open the cache store at {}. Stopping.",
                safe(&cache_dir, reason!("on the measured command line")),
                reason!("a constant; the path is the host's own configuration")
            )
        }),
    );
    let cache = CacheBlobs::new(store, cache_bytes, cache_read);
    let svc = Arc::new(StorageSvc::new(sessions.clone(), cache.clone()));

    // TTL sweeper — enforce per-session deadlines INSIDE the trust boundary (the
    // host STATUS byte is gone). Clock is host-skewable → availability-only.
    // The same tick brings the cache within its budget when that was lowered
    // since its blobs were written; a store keeps within it on its own.
    {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(sweep_secs);
            loop {
                tokio::time::sleep(interval).await;
                let sessions = sessions.clone();
                match tokio::task::spawn_blocking(move || {
                    sessions.sweep_once(now_unix(), sweep_batch)
                })
                .await
                {
                    Ok(Ok(n)) if n > 0 => info!(
                        "storage-cvm: swept {} expired session(s)",
                        safe(
                            &n,
                            reason!(
                                "a count of expired index rows on a volume the host \
                                 provisions unencrypted and reads itself"
                            )
                        ),
                        reason!("a sweep ran; the sweeper is on a fixed timer")
                    ),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!("storage-cvm: sweep failed", reason!("a constant"));
                        debug!("  cause: {e}");
                    }
                    Err(e) => {
                        warn!(
                            "storage-cvm: sweep did not finish, {}",
                            safe(
                                &if e.is_panic() {
                                    "panicked"
                                } else {
                                    "cancelled"
                                },
                                reason!("one of two fixed words")
                            ),
                            reason!("constant text")
                        );
                        // NOT vouched: a JoinError's Display forwards the panic
                        // payload verbatim.
                        debug!("  cause: {e}");
                    }
                }
                match cache.evict().await {
                    Ok(n) if n > 0 => info!(
                        "storage-cvm: dropped {} cache blob(s) over the budget",
                        safe(
                            &n,
                            reason!(
                                "a count of files on a volume the host provisions \
                                 unencrypted and reads itself"
                            )
                        ),
                        reason!("an eviction ran; it is on the sweeper's fixed timer")
                    ),
                    Ok(_) => {}
                    Err(e) => {
                        warn!("storage-cvm: cache eviction failed", reason!("a constant"));
                        debug!("  cause: {e}");
                    }
                }
            }
        });
    }

    let listener = fleet_transport::bind(&listen)
        .await
        .unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "storage-cvm: cannot bind {}. Stopping.",
                safe(&listen, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        })
        .with_accept_retry(accept_retry);
    info!(
        "storage-cvm: listening on {}, sessions={}, cache={} (at most {} bytes, read in \
         {} bytes), sweep={}s of up to {}, request buffers={}/{}, db_busy={:?}, \
         leg_timeout={:?}, leg_max_ports={}, leg_chunk={} bytes, leg_receive={} bytes, \
         accept_retry={:?}",
        safe(&listen, reason!("on the measured command line")),
        safe(&sessions_dir, reason!("on the measured command line")),
        safe(&cache_dir, reason!("on the measured command line")),
        safe(
            &cache_bytes,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &cache_read,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &sweep_secs,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &sweep_batch,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &buffers.session,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &buffers.cache,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &db_busy,
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

    // Mutual RA-TLS acceptor, minted once at boot: every accepted connection is
    // an attested TLS server that also REQUIRES an attested client certificate.
    // WHOSE it is depends on the build, and `fleet_identity` above says what
    // each arm gives up — the measured one accepts any attested guest, which is
    // why records are partitioned by the digest the peer proved rather than by
    // an assumption about who called.
    let (attestor, policy) = fleet_identity();
    let ratls = tokio_rustls::TlsAcceptor::from(Arc::new(
        enclavid_ra_tls::server_config(attestor, policy).unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "storage-cvm: cannot build the RA-TLS server config. Stopping.",
                reason!("a constant reporting a platform state the host provisioned")
            )
        }),
    ));

    // Everything that could fail has succeeded: the stores are open, the listener
    // is bound and the attestation acceptor is minted. From here the host's probe
    // answers healthy — whether that means READY is the host's conclusion to draw,
    // not this role's to claim. See `fleet_transport::health`.
    health.declare_healthy();
    // The loop, the delay after a failed accept and the split between an error
    // that clears itself and one that does not all live in `accept_forever` —
    // four roles wrote that loop four ways and all four omitted the delay.
    fleet_transport::accept_forever(listener, move |stream, peer| {
        let svc = svc.clone();
        let ratls = ratls.clone();
        // Returns as soon as the connection is handed to its own task, so the
        // next accept is not held up behind this one's whole session.
        async move {
            tokio::spawn(async move {
                if let Err(e) = serve_conn(stream, ratls, svc, buffers, leg).await {
                    warn!(
                        "storage-cvm: connection from {} ended ({})",
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
/// settings, and serve BOTH services (their clients sent to the api on the base
/// channel).
async fn serve_conn(
    stream: fleet_transport::Stream,
    ratls: tokio_rustls::TlsAcceptor,
    svc: Arc<StorageSvc>,
    buffers: RequestBuffers,
    leg: LegSettings,
) -> Result<(), LegFailure> {
    let tls = ratls.accept(stream).await.map_err(|e| {
        debug!("ra-tls accept: {e}");
        LegFailure::Attest
    })?;

    // Read the peer's digest HERE, before the stream is split — the connection
    // object is what carries it, and splitting consumes it. `peer_measurement`
    // enforces the other half of the timing itself: it refuses while the
    // connection is still handshaking, so this cannot be moved somewhere the
    // value would not yet have been verified. See `enclavid_storage::Caller` for
    // what it partitions and why nobody can claim someone else's.
    //
    // A successful RA-TLS handshake cannot leave this absent: the verifier
    // refuses a peer with no certificate and a certificate with no quote. The
    // fallible path is therefore unreachable, and it is written as a refusal
    // rather than a default because the alternative to a digest is not "some
    // other digest" but "every caller in one partition", which is the state this
    // exists to prevent.
    let measurement = enclavid_ra_tls::peer_measurement(tls.get_ref().1).ok_or_else(|| {
        debug!("attested peer carries no readable measurement");
        LegFailure::Attest
    })?;

    let (read, write) = tokio::io::split(tls);
    let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, StorageClients, StorageClients, Ciborium>(
        storage_rpc::connection_cfg(&leg),
        read,
        write,
    )
    .await
    .map_err(|e| {
        debug!("rpc connect: {e}");
        LegFailure::Rpc
    })?;
    tokio::spawn(conn);

    // The services are per-connection so they can carry who is calling; the
    // backends they delegate to stay shared, which is what keeps this one node
    // rather than one node per peer.
    let caller = Arc::new(Caller::new(svc, measurement));
    let (session_server, session) =
        SessionStoreServiceServerShared::<_, Ciborium>::new(caller.clone(), buffers.session);
    let (cache_server, cache) = CacheServiceServerShared::<_, Ciborium>::new(caller, buffers.cache);
    tx.send(StorageClients { session, cache })
        .await
        .map_err(|e| {
            debug!("send service client: {e}");
            LegFailure::Clients
        })?;

    // Both services run for the lifetime of the connection; drive one on a task
    // and await the other.
    tokio::spawn(async move {
        let _ = session_server.serve(true).await;
    });
    cache_server.serve(true).await.map_err(|e| {
        debug!("serve: {e}");
        LegFailure::Serve
    })?;
    Ok(())
}
