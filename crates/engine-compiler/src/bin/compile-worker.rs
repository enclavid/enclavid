//! The `compile-worker` deployable: the SUPERVISOR of the compile side.
//!
//! It LISTENS for the orchestrator (api) and serves `engine_rpc::CompilerService`
//! — the same api-facing contract as before — but it runs NO Cranelift itself.
//! Per compile it drives a fresh `engine-compiler-child` PROCESS (spawned + bounded +
//! deadline-guarded + reaped by the shared [`engine_supervisor::ChildRunner`]) and
//! forwards the `(policy, plugins)` to it. Cranelift over UNTRUSTED wasm — a wide
//! surface — runs ONLY in that disposable per-compile child, so a compiler-bug
//! exploit is confined to one compile (no persistent implant that could poison a
//! later tenant's cwasm). It is started for api, not by it — one instance per
//! guest, brought up at boot.
//!
//! **Keyless + cacheless.** The compile-worker holds no keys and no in-memory
//! cache: compile RESULTS are cached in api's L2, so this is a pure forwarder.
//! Compared to the execution-worker it is the SIMPLER consumer of the shared
//! supervisor — no bundle L1, no callback relay — which is exactly why it also
//! validates that the engine-supervisor boundary is clean (process plumbing only).
//!
//! The runner's per-compile wall-clock DEADLINE doubles as the compile-worker's
//! availability guard: a malicious wasm can't hang Cranelift forever and wedge
//! the worker (a real gap the direct-compile design had no bound for). Its
//! memory is the kernel's to hold, the same way the execution-worker's rounds
//! are: every compile child together to one total, each alone to its own max,
//! in a group and under an identity made for it — so a compile that balloons
//! is killed alone, and its neighbours and this process go on.
//!
//! Transport to api: a listener under mutual RA-TLS — TCP by default, vsock
//! under that feature, which is what the measured image builds. The
//! supervisor↔child hop is a private per-child socketpair (never leaves this
//! host).

use std::sync::Arc;
use std::time::Duration;

use engine_supervisor::{
    Cgroups, ChildLimits, ChildRunner, ChildTimes, DEFAULT_CHILD_MAX_TASKS, Fate, RunnerConfig,
};
use remoc::codec::Ciborium;

use enclavid_boundary::{AuthN, Untrusted};
use engine_compiler::{CompileChildService, CompileChildServiceClient};
use engine_rpc::{
    CompileError, CompileRequest, CompiledBundle, CompilerServiceUntrusted, LegSettings,
};
use fleet_transport::LegFailure;
use fleet_transport::launch::{LaunchError, Settings};
use safe_logger::{debug, info, reason, safe, warn};

/// Wall-clock limit on ONE compile in the child (the `deadline-secs` setting;
/// enforced by the [`ChildRunner`]).
/// Bounds a malicious wasm that would otherwise hang Cranelift and hold a child
/// slot forever — the availability guard the direct-compile design lacked.
/// Generous: a legitimate cold compile of a large fused component is seconds,
/// not minutes.
const DEFAULT_COMPILE_DEADLINE_SECS: u64 = 300;

/// Default cap on concurrent compile children (the `max-compiles` setting).
/// Cranelift is CPU-bound, so this is
/// modest by design (roughly a core budget); compiles are rare (only L2 misses).
const DEFAULT_MAX_COMPILES: usize = 8;

/// The most one compile child may hold, in bytes, unless the host says
/// otherwise (the `compile-max-bytes` setting). A compile past it is killed by
/// the kernel and answered as its composition's: a fused component Cranelift
/// cannot compile within this is one this deployment refuses, and a larger one
/// takes a larger setting and a larger guest.
///
/// 2 GiB fits one compile at its max inside the 3 GiB guest beside
/// [`DEFAULT_BASE_RESERVE_BYTES`].
const DEFAULT_COMPILE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// What must be free before a compile child starts, in the children's total and
/// in the guest alike, unless the host says otherwise (the
/// `compile-headroom-bytes` setting): what a child takes to start Cranelift at
/// all. A gate read before each spawn, not a reservation.
const DEFAULT_COMPILE_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;

/// What this process keeps of the guest's memory for itself, out of reach of the
/// compile children's total, unless the host says otherwise (the
/// `base-reserve-bytes` setting): its runtime, its leg to api, and the request
/// and the reply of each compile in flight.
const DEFAULT_BASE_RESERVE_BYTES: u64 = 512 * 1024 * 1024;

/// The `engine_rpc::CompilerService` impl served to api: forward each compile to
/// a fresh disposable `engine-compiler-child` via the runner. Shared (`Arc`) across
/// api connections.
struct Supervisor {
    runner: ChildRunner,
}

impl CompilerServiceUntrusted for Supervisor {
    /// What this role does not know about its caller.
    ///
    /// `AuthN` and nothing else. The listener runs `AcceptAny` — it cannot pin api
    /// without a cycle — so a completed handshake proves a genuine SNP guest on this
    /// part and NOT that it is api. That is the one question open here, and it is
    /// open in a way it never is on api's side of the same wire.
    ///
    /// Not `AuthZ`: this role holds no resource a caller could reach past another's,
    /// and what a caller can spend is compute, answered by the deadline, the
    /// compile's memory max and the runner rather than by a judgement. Not `Replay`:
    /// no request outlives its own call, so there is no version for one to be stale
    /// from — and whether the peer invented it is `Asserted`'s question, which only a
    /// receiver of this role's OUTPUT can ask.
    type Scope = (AuthN,);

    async fn compile(
        &self,
        req: Untrusted<CompileRequest, Self::Scope>,
    ) -> Result<CompiledBundle, CompileError> {
        // INDIFFERENT, and it is a property of the position rather than of the
        // bytes: nothing DERIVED FROM a request outlives its call, so one caller's
        // input cannot reach another's compile, and the result goes back only to
        // whoever asked. Hostile input costs that caller its own compile.
        //
        // What IS shared is a concurrency budget — the runner's slots, one semaphore
        // across every connection — so a caller can make others WAIT. That is
        // availability, not a leak, and the deadline plus the compile's memory
        // max are what answer it; a judgement about the bytes would not.
        //
        // The data-side statelessness is load-bearing, not incidental: it carries
        // the weight the measurement pin would have carried if this end could pin
        // api back. A cache added here would end that, and would need the executor's
        // per-caller partitioning before it could.
        let CompileRequest { policy, plugins } = req
            .trust_unchecked::<AuthN, _>(enclavid_boundary::reason!(
                "indifferent: nothing derived from a request outlives its call, so \
                 hostile input reaches only its own compile and its own caller; the \
                 shared runner slots are availability, capped elsewhere"
            ))
            .into_inner();
        // Drive ONE compile in a fresh disposable child, under the runner's
        // concurrency bound + wall-clock deadline (the runner kills + reaps a wedged
        // child). The closure is the DOMAIN work: forward the compile.
        let outcome = self
            .runner
            // No inherited fd: the engine-compiler-child receives its `(policy, plugins)`
            // over the RPC, not by fd (only the executor hands a cwasm memfd down),
            // so nothing it maps needs keeping either.
            .run(
                None,
                (),
                move |client: CompileChildServiceClient<Ciborium>| async move {
                    client.compile(CompileRequest { policy, plugins }).await
                },
            )
            .await;

        // The runner returns the closure's domain result verbatim on success —
        // `Refused` included, and that is the child's word: a child turned by the
        // composition it compiles can claim it of that composition, which costs
        // only that composition's sessions a 422. A child that died without
        // answering reaches here as `Failed` — the leg to it closed — and the
        // kernel's record says whether the compile itself was the cause: killed
        // at its own max, with the children's total never reached meanwhile, is
        // its composition's, so `Refused`; anything else stays `Failed`. A
        // runner-level failure (spawn error, or the deadline killing a wedged child)
        // is `Failed`, its cause kept to this side's debug log.
        match outcome {
            Ok((Err(CompileError::Failed), exit)) => match exit.fate().await {
                Fate::OutgrewItsMax => Err(CompileError::Refused),
                Fate::Unattributed => Err(CompileError::Failed),
            },
            Ok((domain_result, _)) => domain_result,
            Err(runner_err) => {
                debug!("compile supervisor: {runner_err}");
                Err(CompileError::Failed)
            }
        }
    }
}

/// Locate the `engine-compiler-child` binary: `ENCLAVID_COMPILE_WORKER_CHILD_BIN`
/// if set, else the sibling of this supervisor's own executable. They SHIP
/// together — the image installs both into `/bin` — but they are built apart,
/// each package by its own cargo invocation, which is what keeps
/// `engine-compiler-child`'s dependency graph the short one its manifest
/// declares. Fails loud if neither resolves — per the minimal-defaults rule.
fn child_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ENCLAVID_COMPILE_WORKER_CHILD_BIN") {
        return std::path::PathBuf::from(p);
    }
    let mut p = std::env::current_exe().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "compile-worker: cannot resolve this binary's own path, so the sibling \
             engine-compiler-child cannot be located. Stopping.",
            reason!("a constant about this image's own layout, which the host built")
        )
    });
    p.set_file_name("engine-compiler-child");
    p
}

/// The setting `key` the host gave at launch (see [`fleet_transport::launch`]):
/// `default` when it gave none, and no boot when it gave one that does not
/// parse. A value the host wrote and got wrong is not a request for the default.
fn setting<T: std::str::FromStr>(launch: &mut Settings, key: &'static str, default: T) -> T {
    match launch.take(key) {
        None => default,
        Some(value) => value.parse().unwrap_or_else(|_| {
            safe_logger::error_and_panic!(
                "compile-worker: the setting {} does not parse. Stopping.",
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
        "compile-worker: {}. Stopping.",
        e,
        reason!("a constant, emitted once at boot before any request exists")
    )
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
/// What that costs here: there is nothing here to reach: this role holds no cache and no state between calls. That is the property to keep whole, since it
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
            "compile-worker: cannot present an attested identity — /dev/sev-guest is absent, or this \
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
    // First, so nothing can speak before the channel exists. Panic locations are
    // on: this binary IS the measured code, and the compile side never sees
    // applicant data.
    safe_logger::install();
    safe_logger::install_panic(true);

    // The host's settings for this guest, read once and before anything else:
    // reading them talks to nothing, and the health port below is one of the
    // listeners they set. None of them reaches what a compile produces — that is
    // the build's — only how many run, how long each may take and hold, and how
    // this end holds up api's leg.
    let mut launch = Settings::load("compile-worker").unwrap_or_else(|e| refused(e));
    let max_compiles: usize = setting(&mut launch, "max-compiles", DEFAULT_MAX_COMPILES);
    let deadline = secs(
        &mut launch,
        "deadline-secs",
        Duration::from_secs(DEFAULT_COMPILE_DEADLINE_SECS),
    );
    // What the compile children may hold, and what this process keeps for
    // itself: availability, which the kernel enforces (see `Cgroups::create`
    // below).
    let compile_max: u64 = setting(&mut launch, "compile-max-bytes", DEFAULT_COMPILE_MAX_BYTES);
    let compile_headroom: u64 = setting(
        &mut launch,
        "compile-headroom-bytes",
        DEFAULT_COMPILE_HEADROOM_BYTES,
    );
    let base_reserve: u64 = setting(
        &mut launch,
        "base-reserve-bytes",
        DEFAULT_BASE_RESERVE_BYTES,
    );
    let child_max_tasks: u64 = setting(&mut launch, "child-max-tasks", DEFAULT_CHILD_MAX_TASKS);
    let times = ChildTimes::default();
    let child_times = ChildTimes {
        fate_wait: secs(&mut launch, "child-fate-wait-secs", times.fate_wait),
        connect: secs(&mut launch, "child-connect-secs", times.connect),
        room_poll: millis(&mut launch, "room-poll-ms", times.room_poll),
    };
    let request_buffer: usize = setting(
        &mut launch,
        "request-buffer",
        engine_rpc::DEFAULT_REQUEST_BUFFER,
    );
    let leg_default = LegSettings::default();
    let leg = LegSettings {
        timeout: secs(&mut launch, "leg-timeout-secs", leg_default.timeout),
        max_ports: setting(&mut launch, "leg-max-ports", leg_default.max_ports),
        chunk_bytes: setting(&mut launch, "leg-chunk-bytes", leg_default.chunk_bytes),
    };
    let accept_retry = millis(
        &mut launch,
        "accept-retry-ms",
        fleet_transport::DEFAULT_ACCEPT_RETRY,
    );
    launch.finish().unwrap_or_else(|e| refused(e));
    // A compile waits for a slot as long as one takes, so with none it would
    // wait forever; a zero deadline ends every compile before it starts; and the
    // waits and buffers below each do nothing at zero but fail.
    if max_compiles == 0
        || deadline.is_zero()
        || child_max_tasks == 0
        || child_times.fate_wait.is_zero()
        || child_times.connect.is_zero()
        || child_times.room_poll.is_zero()
        || request_buffer == 0
        || accept_retry.is_zero()
    {
        safe_logger::error_and_panic!(
            "compile-worker: a compile bound, a compile deadline, a child task cap, a \
             child fate wait, handshake or room poll time, a request buffer or an \
             accept retry of zero compiles nothing; each must be above it. Stopping.",
            reason!("a constant, emitted once at boot before any request exists")
        );
    }
    // The room a compile needs to start must be above zero and within its max,
    // or no compile could ever start.
    if compile_headroom == 0 || compile_headroom > compile_max {
        safe_logger::error_and_panic!(
            "compile-worker: a {} MiB compile headroom must be above zero and within the \
             {} MiB compile max. Stopping.",
            safe(
                &(compile_headroom >> 20),
                reason!("the host's own setting, or this build's default")
            ),
            safe(
                &(compile_max >> 20),
                reason!("the host's own setting, or this build's default")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        );
    }
    // What the compile children may hold together: this guest's memory less what
    // this process keeps. A total that cannot hold one compile at its max
    // compiles nothing that needs it.
    let physical = engine_supervisor::physical_memory();
    let total = physical.saturating_sub(base_reserve);
    if total < compile_max {
        safe_logger::error_and_panic!(
            "compile-worker: {} MiB of memory leaves the compile children {} MiB beside a \
             {} MiB base reserve — not one compile could run to its {} MiB max. Give this \
             guest more memory, or the reserve or the compile max less. Stopping.",
            safe(&(physical >> 20), reason!("a size the host provisioned")),
            safe(
                &(total >> 20),
                reason!("derived from that size and the host's setting")
            ),
            safe(
                &(base_reserve >> 20),
                reason!("the host's own setting, or this build's default")
            ),
            safe(
                &(compile_max >> 20),
                reason!("the host's own setting, or this build's default")
            ),
            reason!("a constant, emitted once at boot before any request exists")
        );
    }
    if let Some(refusal) = leg.refusal() {
        safe_logger::error_and_panic!(
            "compile-worker: {} cannot hold a leg up. Stopping.",
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
        let health_addr =
            std::env::var("ENCLAVID_COMPILE_WORKER_HEALTH_LISTEN").unwrap_or_else(|e| {
                debug!("{e}");
                safe_logger::error_and_panic!(
                    "compile-worker: ENCLAVID_COMPILE_WORKER_HEALTH_LISTEN is not set. Stopping.",
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

    // Fail CLOSED if the kernel's ptrace hardening is too weak to isolate one
    // escaped engine-compiler-child from a sibling's memory (see the shared check).
    // The compile side is PII-free, but it rides the same disposable-child runner,
    // so it requires the same invariant — one fix, both workers.
    engine_supervisor::require_ptrace_scope();

    // api-facing listen address: first arg or ENCLAVID_COMPILE_WORKER_LISTEN.
    // Fail loud if absent (per the minimal-defaults rule).
    let addr = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ENCLAVID_COMPILE_WORKER_LISTEN").ok())
        .unwrap_or_else(|| {
            safe_logger::error_and_panic!(
                "compile-worker: no listen address — pass one as the first argument or set \
                 ENCLAVID_COMPILE_WORKER_LISTEN. Stopping.",
                reason!("a constant naming a configuration key the host itself supplied")
            )
        });

    // The kernel's hold on the compile children: the total above for all of
    // them, the max for each, the room a compile needs before it starts, and
    // the tasks each may have. In the measured image this builds the group or
    // stops the boot; a build without `guest-hardening` holds nothing (see
    // `Cgroups::create`).
    let cgroups = Cgroups::create(
        ChildLimits {
            total,
            max: compile_max,
            headroom: compile_headroom,
            tasks: child_max_tasks,
        },
        max_compiles,
    );

    let child_exe = child_exe();

    let svc = Arc::new(Supervisor {
        runner: ChildRunner::new(
            RunnerConfig {
                exe: child_exe.clone(),
                max_children: max_compiles,
                deadline,
                // No admission wait: a compile waits for a slot, and for room for
                // its child, as long as those take.
                admission_wait: None,
                times: child_times,
            },
            cgroups,
        ),
    });

    let listener = fleet_transport::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "compile-worker: cannot bind {}. Stopping.",
                safe(&addr, reason!("on the measured command line")),
                reason!("a constant; the address is the host's own configuration")
            )
        })
        .with_accept_retry(accept_retry);
    info!(
        "compile-worker (supervisor): listening on {}, engine-compiler-child={}, \
         max_compiles={} sharing {} MiB of {} MiB memory (each to {} MiB, {} MiB to \
         start, {} tasks), deadline={}s, child_fate_wait={:?}, child_connect={:?}, \
         room_poll={:?}, request_buffer={}, leg_timeout={:?}, leg_max_ports={}, \
         leg_chunk={} bytes, accept_retry={:?}",
        safe(&addr, reason!("on the measured command line")),
        safe(
            &child_exe.display(),
            reason!("a location inside the measured image")
        ),
        safe(
            &max_compiles,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &(total >> 20),
            reason!("derived from the memory and the host's setting")
        ),
        safe(&(physical >> 20), reason!("a size the host provisioned")),
        safe(
            &(compile_max >> 20),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &(compile_headroom >> 20),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &child_max_tasks,
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &deadline.as_secs(),
            reason!("the host's own setting, or this build's default")
        ),
        safe(
            &child_times.fate_wait,
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
        reason!("a constant, emitted at boot before any policy has been composed")
    );

    // Mutual RA-TLS acceptor, minted once at boot: every accepted connection is
    // wrapped in an attested TLS server that also requires an attested client
    // certificate. WHOSE it is depends on the build, and `fleet_identity` above
    // says what each arm gives up — the measured one accepts any attested guest.
    // Nothing here is partitioned by caller, because nothing here is retained:
    // this role holds no cache and no state between calls, so one caller's
    // request cannot reach another's (see the header).
    let (attestor, policy) = fleet_identity();
    let ratls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        enclavid_ra_tls::server_config(attestor, policy).unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "compile-worker: cannot build the RA-TLS server config. Stopping.",
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
                        "compile-worker: connection from {} ended ({})",
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

/// RA-TLS-accept one api connection, then hand it to the contract's own serve
/// half, `request_buffer` of api's requests waiting at most, on this end's `leg`
/// settings.
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
    let (read, write) = tokio::io::split(tls);

    // Above this line is WHO connected; below is WHAT MAY CROSS, which belongs to
    // the contract. Bringing the hop up means naming the generated client, and that
    // is what no crate outside engine-rpc may do.
    engine_rpc::serve_compiler(read, write, svc, request_buffer, &leg)
        .await
        .map_err(|e| {
            debug!("compile leg: {e}");
            match e {
                engine_rpc::LegError::Rpc => LegFailure::Rpc,
                engine_rpc::LegError::Clients | engine_rpc::LegError::Closed => LegFailure::Clients,
                engine_rpc::LegError::Serve => LegFailure::Serve,
            }
        })
}
