//! The `execution-worker` deployable: the SUPERVISOR of the execute side.
//!
//! It LISTENS for the orchestrator (api) and serves `engine_rpc::ExecutorService`
//! — the same api-facing contract as before — but it runs NO wasm itself. Per
//! reducer round it drives a fresh `engine-executor-child` PROCESS (spawned + bounded +
//! deadline-guarded + released by the shared [`engine_supervisor::ChildRunner`]), primes
//! it with the compiled bundle, drives exactly one round in it, and discards it.
//! Untrusted policy wasm and `Component::deserialize` execute ONLY in that
//! disposable per-round child, behind an OS address-space boundary — so a wasmtime
//! sandbox escape is confined to one round's plaintext (one applicant), with no
//! cross-round persistence and no cross-session bleed. It is started for it, not
//! by api — one instance per guest, brought up at boot.
//!
//! **Keyless.** The supervisor holds no `tee_seal_key` and no applicant token. Two
//! hops carry the keyless callbacks — blob rehydration + state persistence, both
//! seal-key-side. There is NO bundle-resolution callback: on an L1 miss this
//! worker answers [`engine_rpc::RunOutcome::CacheMiss`] and runs nothing, and the
//! orchestrator resolves the bundle under its own key and comes back on
//! `run_with_bundle`. So the OCI-pull / compile probe surface never touches the
//! worker, and the worker never names a cache slot back (L2 cache-poisoning
//! defence).
//!   * api → supervisor: the orchestrator passes a `CallbackServiceClient` into
//!     `run`.
//!   * supervisor → child: the supervisor stands up a [`relay::RelayCallbacks`]
//!     ([`engine_rpc::ChildCallbacks`]) that forwards the child's `media_load` /
//!     `session_change` on to the api client — so the untrusted-wasm child gets
//!     blob + state I/O but never the seal key.
//!
//! **What is domain vs supervisor.** The generic process plumbing — spawn a
//! disposable child over a socketpair, bound concurrency, enforce the per-round
//! wall-clock DEADLINE (so a wedged child can't leak its slot), kill + release, and
//! the capability-scoped fd handoff — lives in [`engine_supervisor::ChildRunner`],
//! shared with the compile-worker. What stays HERE is the executor's domain: the
//! memfd-backed L1 ([`bundles`]), what a cwasm goes through on its way into it
//! ([`cwasm`]), the api-facing service ([`service`]), the callback relay
//! ([`relay`]) and what the host decides about all of it at launch
//! ([`settings`]).
//!
//! **L1.** The supervisor owns the fleet's ONLY in-memory L1, one
//! [`bundles::CompositionEntry`] per `(caller measurement, composition_key)` — the
//! caller is in the key because entries are written by whoever calls and read by
//! whoever asks, and only the digest keeps one peer's bytes out of another's.
//! See [`service::Caller`].
//!
//! The compiled `cwasm` lives there as a single anonymous in-RAM file — a sealed
//! Linux `memfd` in prod, an unlinked tmpfile in dev — held by fd, NOT as heap
//! bytes and NOT as a named file (the two earlier copies collapse into this
//! one). On an L1 miss it returns
//! [`engine_rpc::RunOutcome::CacheMiss`]; the orchestrator resolves the bundle
//! under its OWN `composition_key` and re-drives through `run_with_bundle`, whose
//! bundle streams beside the call straight into the memfd that becomes its entry
//! ([`cwasm::Incoming`]) — there is no wire `Vec`. Only once every byte has arrived
//! at its declared length and digest is the file sealed, checked and committed to
//! the L1 ([`cwasm::Cwasm`]). Each per-round child then MMAPs it
//! via a write-sealed fd the supervisor hands it — never a path — so no child can
//! reach another composition's code. A live `Component` never crosses the process
//! boundary; the `Component::deserialize` unsafe sink stays in the disposable child.
//!
//! Transport to api: a listener under mutual RA-TLS — TCP by default, vsock
//! under that feature, which is what the measured image builds. The
//! supervisor↔child hop is a private per-child socketpair (never leaves this
//! host).

mod bundles;
mod cwasm;
mod relay;
mod service;
mod settings;

use std::sync::Arc;

use engine_executor::admission::{children_total, fd_budget, rounds_held, supervisor_per_child};
use engine_executor::compat_token;
use engine_rpc::{CompatToken, LegSettings};
use engine_supervisor::{Cgroups, ChildLimits, ChildRunner, RunnerConfig};
use fleet_transport::LegFailure;
use safe_logger::{debug, info, reason, safe, warn};
use tokio::sync::Semaphore;

use crate::bundles::Bundles;
use crate::service::{Caller, Supervisor};

/// Locate the `engine-executor-child` binary: `ENCLAVID_EXECUTION_WORKER_CHILD_BIN`
/// if set, else the sibling of this supervisor's own executable. They SHIP
/// together — the image installs both into `/bin` — but they are built apart,
/// each package by its own cargo invocation, which is what keeps
/// `engine-executor-child`'s dependency graph the short one its manifest
/// declares. Fails loud if neither resolves — per the minimal-defaults rule.
fn child_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ENCLAVID_EXECUTION_WORKER_CHILD_BIN") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::current_exe().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "execution-worker: cannot resolve this binary's own path, so the sibling \
             engine-executor-child cannot be located. Stopping.",
            reason!("a constant about this image's own layout, which the host built")
        )
    });
    p.set_file_name("engine-executor-child");
    p
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
/// What that costs here: L1 entries are partitioned by the digest the peer proved, so one caller cannot reach another's (see `Caller`). That is the property to keep whole, since it
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
            "execution-worker: cannot present an attested identity — /dev/sev-guest is absent, or this \
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

#[tokio::main]
async fn main() {
    // First, so nothing can speak before the channel exists.
    //
    // Panic locations are off in the measured build and on in a debug one. This
    // role runs the consumer's wasm, so in production a panic site reached is a
    // site adversary-chosen code could have steered to, and the report says only
    // that one happened. A debug image is a different measurement no consumer
    // pins, and it already puts the whole kernel log and every `debug!` on the
    // same port — withholding a source location there costs diagnosis and
    // protects nothing.
    safe_logger::install();
    safe_logger::install_panic(cfg!(feature = "debug"));

    // The host's settings for this guest, read once and before anything else:
    // reading them talks to nothing, and the health port below is one of the
    // listeners they set. A malformed one stops the boot here, on the log
    // device. See `settings`.
    let s = settings::load();

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
        let health_addr =
            std::env::var("ENCLAVID_EXECUTION_WORKER_HEALTH_LISTEN").unwrap_or_else(|e| {
                debug!("{e}");
                safe_logger::error_and_panic!(
                    "execution-worker: ENCLAVID_EXECUTION_WORKER_HEALTH_LISTEN is not set. \
                     Stopping.",
                    reason!("a constant naming a configuration key the host itself supplied")
                )
            });
        // Bound HERE, on this task, and only the answering loop is spawned:
        // binding inside the spawn would turn a failure into one dead task and
        // a guest that serves with no health port. See `health::bind`.
        let listener = fleet_transport::health::bind(&health_addr)
            .await
            .with_accept_retry(s.accept_retry);
        let health = health.clone();
        tokio::spawn(async move {
            fleet_transport::health::serve(listener, move || health.body()).await
        });
    }

    // Fail CLOSED if the kernel isn't hardened enough to keep one escaped child
    // out of a sibling child's in-flight applicant memory (the per-round isolation
    // rests on this). The real enforcement is the measured CVM image; this makes a
    // regressed image crash here instead of silently losing the guarantee.
    engine_supervisor::require_ptrace_scope();

    // api-facing listen address: first arg or ENCLAVID_EXECUTION_WORKER_LISTEN.
    // Fail loud if absent (per the minimal-defaults rule).
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ENCLAVID_EXECUTION_WORKER_LISTEN").ok())
        .unwrap_or_else(|| {
            safe_logger::error_and_panic!(
                "execution-worker: no listen address — pass one as the first argument or set \
                 ENCLAVID_EXECUTION_WORKER_LISTEN. Stopping.",
                reason!("a constant naming a configuration key the host itself supplied")
            )
        });

    // How many round children may run at once is a count, for what memory does
    // not bound — how many rounds share the CPUs, the descriptors and tasks each
    // slot holds. What they take in memory is held below, by the kernel.
    let settings::Settings {
        max_children,
        waiting_per_child,
        bundle_cache_bytes,
        bundle_cache_entries,
        bundle_idle,
        base_reserve,
        round_max,
        round_headroom,
        round_deadline,
        round_fuel,
        capacity_wait,
        bundle_stream,
        bundle_stream_idle,
        child_max_tasks,
        child_times,
        request_buffer,
        callback_request_buffer,
        leg,
        accept_retry,
    } = s;

    // What the children may hold together: this guest's memory less what this
    // process keeps for itself and for each child's round. Each child alone is
    // held to the round's max; a total that cannot hold one child there runs
    // nothing.
    let physical = engine_supervisor::physical_memory();
    let total = children_total(
        physical,
        bundle_cache_bytes,
        base_reserve,
        max_children as u64,
        waiting_per_child,
    );
    if total < round_max {
        safe_logger::error_and_panic!(
            "execution-worker: {} MiB of memory leaves the round children {} MiB beside a \
             {} MiB bundle cache, a {} MiB base reserve and {} MiB \
             in this process for each of {} children — not one child could run to its {} \
             MiB max. Give this guest more memory, or the cache, the reserve, the children \
             or the rounds waiting behind them less. Stopping.",
            safe(&(physical >> 20), reason!("a size the host provisioned")),
            safe(
                &(total >> 20),
                reason!("derived from that size, the host's settings and build constants")
            ),
            safe(
                &(bundle_cache_bytes >> 20),
                reason!("the host's own setting, or this build's default")
            ),
            safe(
                &(base_reserve >> 20),
                reason!("the host's own setting, or this build's default")
            ),
            safe(
                &(supervisor_per_child(waiting_per_child) >> 20),
                reason!("derived from the host's setting and build constants")
            ),
            safe(
                &max_children,
                reason!("the host's own setting, or this build's default")
            ),
            safe(
                &(round_max >> 20),
                reason!("the host's own setting, or this build's default")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        );
    }

    // Fail CLOSED if this process cannot open the descriptors its own caps are
    // counted in. Here rather than beside `require_ptrace_scope` because the
    // budget is a function of how many children may run and how many entries the
    // cache may hold, which are the host's settings — a check run before them
    // would be checking numbers nobody chose.
    engine_supervisor::require_fd_budget(fd_budget(max_children as u64, bundle_cache_entries));

    // The kernel's hold on the children: the total above for all of them, the
    // max for each, the room a child needs before it starts, and the tasks each
    // may have. In the measured image this builds the tree or stops the boot; a
    // build without `guest-hardening` holds nothing (see `Cgroups::create`).
    let cgroups = Cgroups::create(
        ChildLimits {
            total,
            max: round_max,
            headroom: round_headroom,
            tasks: child_max_tasks,
        },
        max_children,
    );

    let child_exe = child_exe();

    // This runtime's ABI id, parsed at boot rather than per cache miss: a build
    // whose runtime version does not fit the wire shape is a broken build, and it
    // should say so to an operator here rather than fail the first round to miss.
    let compat_token = CompatToken::parse(&compat_token()).unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "execution-worker: this runtime's cwasm ABI id does not fit the shape the \
             execute contract carries. Stopping.",
            reason!("a constant of the measured build, naming no runtime input")
        )
    });

    let svc = Arc::new(Supervisor {
        // ONE L1: the cwasm memfd + registry metadata per composition. Each entry
        // is charged what it holds — its cwasm, and its metadata by length times
        // the margin its decoded form stays under — so the budget is a RAM
        // budget rather than an entry count (each cwasm is ~10-15 MiB of memfd
        // RAM). That closes the consumer-driven OOM.
        //
        // Through `l1_entry_weight`, so the charge also has a FLOOR. Charging by
        // size alone made a small entry cheap and a zero-length one free, and an
        // entry costs a DESCRIPTOR whether or not it costs RAM — the floor is what
        // makes this one number bound both.
        bundles: Bundles::new(bundle_cache_bytes, bundle_cache_entries),
        rounds: Semaphore::new(rounds_held(max_children, waiting_per_child)),
        capacity_wait,
        bundle_stream,
        bundle_stream_idle,
        round_fuel,
        callback_request_buffer,
        runner: ChildRunner::new(
            RunnerConfig {
                exe: child_exe.clone(),
                max_children,
                deadline: round_deadline,
                admission_wait: Some(capacity_wait),
                times: child_times,
            },
            cgroups,
        ),
        compat_token,
    });

    // Compositions no round has used for the idle time go, whether or not
    // another needs their room.
    {
        let svc = svc.clone();
        tokio::spawn(async move {
            let mut sweep = tokio::time::interval(bundle_idle.min(bundles::IDLE_SWEEP));
            loop {
                sweep.tick().await;
                svc.bundles.evict_idle(bundle_idle);
            }
        });
    }

    let listener = fleet_transport::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "execution-worker: cannot bind {}. Stopping.",
                safe(&addr, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        })
        .with_accept_retry(accept_retry);
    // How many rounds the total holds at the headroom beside one at its max:
    // where that is under the child bound, the memory and not the count is what
    // turns rounds away under load.
    let beside_one_at_its_max = (total - round_max) / round_headroom;
    info!(
        "execution-worker (supervisor): listening on {}, engine-executor-child={}, \
         children={} sharing {} MiB of {} MiB memory (each to {} MiB; {} more at the \
         {} MiB headroom fit beside one at that max), waiting_per_child={}, \
         round_deadline={}s, round_fuel={}, bundle_cache={} MiB, bundle_idle={}s, \
         base_reserve={} MiB, capacity_wait={}s, bundle_stream={}s, bundle_stream_idle={}s",
        safe(&addr, reason!("on the measured command line")),
        safe(
            &child_exe.display(),
            reason!("a location inside the measured image")
        ),
        safe(
            &max_children,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &(total >> 20),
            reason!("derived from the memory, the host's settings and build constants")
        ),
        safe(&(physical >> 20), reason!("a size the host provisioned")),
        safe(
            &(round_max >> 20),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &beside_one_at_its_max,
            reason!("derived from the total and two of the host's settings")
        ),
        safe(
            &(round_headroom >> 20),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &waiting_per_child,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &round_deadline.as_secs(),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &round_fuel,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &(bundle_cache_bytes >> 20),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &bundle_idle.as_secs(),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &(base_reserve >> 20),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &capacity_wait.as_secs(),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &bundle_stream.as_secs(),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &bundle_stream_idle.as_secs(),
            reason!("the host's own setting, or this build's default")
        ),
        reason!(
            "the listen address is on the measured command line; the limits and the \
             child path are constants of the measured image or settings the host \
             chose, and the memory is the size the host gave this guest. Emitted at \
             boot, before any policy has been composed, let alone run"
        )
    );
    info!(
        "execution-worker (supervisor): bundle_cache_entries={}, child_max_tasks={}, \
         child_exit_wait={:?}, child_connect={:?}, room_poll={:?}, request_buffer={}, \
         callback_request_buffer={}, leg_timeout={:?}, leg_max_ports={}, \
         leg_chunk={} bytes, accept_retry={:?}",
        safe(
            &bundle_cache_entries,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &child_max_tasks,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &child_times.exit_wait,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &child_times.connect,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &child_times.room_poll,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &request_buffer,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &callback_request_buffer,
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
            &accept_retry,
            reason!("the host's own setting, or this build's default")
        ),
        reason!("settings the host chose or this build's defaults, emitted once at boot")
    );

    // Mutual RA-TLS acceptor, minted once at boot: every accepted connection is
    // wrapped in an attested TLS server that also REQUIRES an attested client
    // certificate. WHOSE it is depends on the build, and `fleet_identity` above
    // says what each arm gives up — the measured one accepts any attested guest,
    // which is why L1 entries are partitioned by the digest the peer proved
    // rather than by an assumption about who called (see `Caller`).
    let (attestor, policy) = fleet_identity();
    let ratls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        enclavid_ra_tls::server_config(attestor, policy).unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "execution-worker: cannot build the RA-TLS server config. Stopping.",
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
                if let Err(e) = serve_conn(stream, ratls, svc, request_buffer, leg).await {
                    warn!(
                        "execution-worker: connection from {} ended ({})",
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

/// RA-TLS-accept one api connection, then frame it with remoc and serve
/// `ExecutorService`, `request_buffer` of api's requests waiting at most, on this
/// end's `leg` settings.
async fn serve_conn(
    stream: fleet_transport::Stream,
    ratls: tokio_rustls::TlsAcceptor,
    svc: Arc<Supervisor>,
    request_buffer: usize,
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
    // value would not yet have been verified. See `Caller` for what it
    // partitions and why nobody can claim someone else's.
    //
    // A successful RA-TLS handshake cannot leave this absent: the verifier
    // refuses a peer with no certificate and a certificate with no quote. The
    // fallible path is therefore unreachable, and it is written as a refusal
    // rather than a default because the alternative to a digest is not "some
    // other digest" but "every caller in one partition", which is the state
    // this exists to prevent.
    let measurement = enclavid_ra_tls::peer_measurement(tls.get_ref().1).ok_or_else(|| {
        debug!("attested peer carries no readable measurement");
        LegFailure::Attest
    })?;

    let (read, write) = tokio::io::split(tls);

    // The service is per-connection so it can carry who is calling; the machinery
    // it delegates to — the L1 map and the child runner — stays shared, which is
    // what makes the runner ONE concurrency budget rather than one per caller.
    let caller = Arc::new(Caller {
        sup: svc,
        measurement,
    });
    // Bringing the hop up means naming the generated client, and that is the one
    // thing no crate outside engine-rpc may do — so the remoc half lives there for
    // this end too, and this one keeps what it is actually about: who connected.
    engine_rpc::serve_executor(read, write, caller, request_buffer, &leg)
        .await
        .map_err(|e| {
            debug!("execute leg: {e}");
            match e {
                engine_rpc::LegError::Rpc => LegFailure::Rpc,
                engine_rpc::LegError::Clients | engine_rpc::LegError::Closed => LegFailure::Clients,
                engine_rpc::LegError::Serve => LegFailure::Serve,
            }
        })
}
