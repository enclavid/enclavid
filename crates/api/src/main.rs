mod applicant;
mod assets;
mod client;
mod client_state;
mod compiler;
mod cwasm_cache;
mod disclosure_commit;
mod dto;
mod endorsement;
mod error;
mod executor;
mod fleet;
mod health;
mod input;
mod keyprovider;
mod limits;
mod locale;
mod policy_pull;
mod settings;
mod shuffle;
mod state;
mod storage;
mod tee;
mod transport;
mod turns;

use std::sync::Arc;

use enclavid_attestation::Attestor;
use hatch_client::{CacheBackend, CacheStore, SessionBackend, SessionStore};
use safe_logger::{debug, info, reason};

use crate::client_state::ClientState;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    // First, so nothing can speak before the channel exists. Panic locations
    // are on: this binary IS the measured code, so nothing that could aim a
    // panic at a secret runs here without changing the measurement.
    safe_logger::install();
    safe_logger::install_panic(true);
    info!(
        "api: alive",
        reason!("a constant, emitted before this process holds anything at all")
    );

    // How long and how often to wait on each leg and on the hatch, and how to
    // hold each leg up — read from the launch, which talks to nothing, and first,
    // because the health port below is one of the listeners they set.
    let settings = settings::load();

    // The health port, up before everything: before attestation, before the
    // dials, before either serving listener. api is the one role whose progress
    // is invisible from outside — a guest waiting for the storage-CVM looks
    // exactly like one that is serving — and this is the port that closes that
    // gap. Every field answers false for the whole of the wait, and the host's
    // cue to start routing is the whole answer coming back true, not any one
    // field of it. See `health` for why api draws that conclusion for nobody.
    //
    // It is also what makes `fleet::dial` waiting for ever the right behaviour
    // rather than a hang: the guest says what it is doing, so nobody has to
    // infer it from silence.
    let api_health = health::ApiHealth::new();
    {
        let health_addr = std::env::var("ENCLAVID_ADDRESS_IN_HEALTH").unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "api: ENCLAVID_ADDRESS_IN_HEALTH is not set. Stopping.",
                reason!("a constant naming a configuration key the host itself supplied")
            )
        });
        // Bound HERE, on this task, and only the answering loop is spawned:
        // binding inside the spawn would turn a failure into one dead task and
        // a guest that serves with no health port. See `health::bind`.
        let listener = fleet_transport::health::bind(&health_addr)
            .await
            .with_accept_retry(settings.accept_retry);
        let api_health = api_health.clone();
        tokio::spawn(async move {
            fleet_transport::health::serve(listener, move || api_health.body()).await
        });
    }

    // Where each leg is dialed, the hatch's first: the attestation below needs
    // it. Read from the launch, which talks to nothing.
    let legs = fleet::legs::load();
    let address_out = legs.hatch;

    // The attestation backend, chosen at compile time — see `endorsement`.
    // FIRST, ahead of the storage-CVM dial below and both listeners: under
    // `sev-snp` this is where the guest establishes that it is running
    // somewhere fit to serve and holds the endorsement that lets it prove so.
    // A guest that answers no to either must reach nothing and serve nobody,
    // so nothing that talks to anything may precede it.
    let attestor: Arc<dyn Attestor> =
        endorsement::build_attestor(&address_out, settings.vcek_deadline, settings.vcek_retries)
            .await;
    info!(
        "api: attested",
        reason!(
            "a constant; reaching this line says only that the platform was \
                 accepted and an endorsement was obtained"
        )
    );

    // The hatch bit, on a clock of its own.
    //
    // Fixed cadence is the whole design, not an implementation choice. A bit set
    // from the outcome of REAL calls would flip only when an applicant-driven
    // call failed — and since the host is the far end of this hop, it is the
    // party that failed it, so polling that bit would tell it when a session was
    // active. A ticker says the same thing about the hop while saying nothing
    // about who is using it.
    //
    // It reports the LEG, not the hatch. Whether that process is up is something
    // whatever supervises it knows better than any probe here; whether this
    // guest can reach it is a fact only this guest holds.
    //
    // A failure changes nothing but the bit. The hatch is on the cold-start path
    // (`/authorize` for the consumer surface, `/oci/*` and `/kbs/relay` from
    // `cold_compile`), and an applicant round on a warm composition never
    // touches it — so withdrawing this guest over a hatch fault would end
    // sessions that are running correctly. What to do about it is the host's
    // call, made from the whole answer.
    //
    // AFTER the attestation above, and not for convenience: the rule stated
    // there is that nothing which talks to anything may precede it, and a
    // ticker that starts earlier would be exactly such a thing. The bit answers
    // false until the first pass, which is what every other field does too.
    {
        let probe = hatch_client::HatchClient::new(&address_out)
            .await
            .unwrap_or_else(|e| {
                debug!("{e}");
                safe_logger::error_and_panic!(
                    "api: the hatch leg's address is not one this build can dial. Stopping.",
                    reason!("a constant about an address the host itself supplied")
                )
            });
        let api_health = api_health.clone();
        let (every, within) = (settings.hatch_probe, settings.hatch_probe_deadline);
        tokio::spawn(async move {
            // `interval` fires once immediately, so the first probe runs now
            // rather than one period from now. `Delay` on a missed tick because
            // the cadence is what carries the meaning: catching up on skipped
            // ticks would bunch probes together and turn a clock into a
            // reaction.
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let up = probe.probe(within).await.is_ok();
                api_health.set_hatch(up);
            }
        });
    }

    // SessionStore is hatch-client's per-session typed-field store. It is
    // transport-agnostic — it holds an `Arc<dyn SessionBackend>`, and the
    // backend built above dials the storage-CVM over RA-TLS. Shared between
    // the client API (writes metadata/status on /create and /init) and the
    // applicant API (reads/writes state on /connect and /input), so the Arc
    // is what gives both state structs the same connection underneath.
    //
    // The seal key comes from the chip: under `sev-snp`, `load_tee_seal_key`
    // calls `enclavid_attestation::derive_seal_key`, so it is bound to the
    // measurement and to firmware no older than this build's floor, and never
    // leaves the enclave. The env-var path below it is
    // the dev build only, and is compiled out of the measured image.
    let tee_seal_key = load_tee_seal_key();
    // Derive the process-lifetime shuffle key from the same TEE
    // secret. Domain-separated under a distinct info string so we
    // don't reuse the AEAD key directly for `DisplayField` shuffle
    // PRNG seeding — see `crate::shuffle` for the threat model.
    let shuffle_key = Arc::new(shuffle::ShuffleKey::from_tee_seal_key(&tee_seal_key));

    // Storage backends for the session KV + L2 cwasm cache: the trusted
    // storage-CVM over RA-TLS. This is api's ONLY durable-state backend — host
    // Redis + the host object_store cache were retired (the hatch now fronts
    // external egress only). All AEAD sealing stays TEE-side in
    // `SessionStore` / `CacheStore`; the storage-CVM sees ciphertext only. Each
    // session lives `session_ttl_secs` from its creation (`settings`).
    let (session_backend, cache_backend) = build_storage_backends(
        legs.storage,
        attestor.clone(),
        api_health.clone(),
        settings.leg_dial,
        settings.leg,
    )
    .await;
    info!("api: storage-CVM connected", reason!("a constant"));
    let session_store = Arc::new(SessionStore::new(
        session_backend,
        tee_seal_key,
        Some(settings.session_ttl_secs),
    ));
    let cache_store = CacheStore::new(cache_backend, &tee_seal_key);

    // Two listeners, two routers, one process. Topology rationale: TLS
    // terminates inside this TEE, so a host-side proxy can only route by
    // SNI on raw TCP. Each surface (clients vs applicants) gets its own
    // certificate, port, optional mTLS posture, and rate-limit policy.
    // Each surface owns its route table — see `client::router` and
    // `applicant::router` for the endpoint inventory.
    // Minted ONCE and cloned into both surfaces. `server_config` mints a fresh
    // certificate on every call, so one per surface would give this process two
    // identities and two quotes, for no reason a peer could make sense of.
    let acceptor = transport::acceptor(attestor.clone());

    let client_state = Arc::new(
        ClientState::init(
            &address_out,
            session_store.clone(),
            attestor.clone(),
            settings.authorize_deadline,
        )
        .await,
    );
    let applicant_state = Arc::new(
        AppState::init(
            &address_out,
            legs.compile_worker,
            legs.execution_worker,
            session_store,
            cache_store,
            shuffle_key,
            attestor,
            api_health.clone(),
            &settings,
        )
        .await,
    );

    let client_app = client::router(client_state);
    let applicant_app = applicant::router(applicant_state);

    // Each surface reports when its listener is BOUND, not when its task is
    // spawned — `healthy` says "I am listening", and a field that fires a few
    // microseconds before the bind would be saying it on trust.
    let (client_bound, client_is_bound) = tokio::sync::oneshot::channel();
    let (applicant_bound, applicant_is_bound) = tokio::sync::oneshot::channel();

    let client_handle = tokio::spawn({
        let addr = std::env::var("ENCLAVID_ADDRESS_IN_CLIENT").unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "api: ENCLAVID_ADDRESS_IN_CLIENT is not set. Stopping.",
                reason!("a constant naming a configuration key the host itself supplied")
            )
        });
        let acceptor = acceptor.clone();
        let accept_retry = settings.accept_retry;
        async move {
            transport::serve(client_app, &addr, client_bound, acceptor, accept_retry).await;
        }
    });
    let applicant_handle = tokio::spawn({
        let addr = std::env::var("ENCLAVID_ADDRESS_IN_APPLICANT").unwrap_or_else(|e| {
            debug!("{e}");
            safe_logger::error_and_panic!(
                "api: ENCLAVID_ADDRESS_IN_APPLICANT is not set. Stopping.",
                reason!("a constant naming a configuration key the host itself supplied")
            )
        });
        let accept_retry = settings.accept_retry;
        async move {
            transport::serve(
                applicant_app,
                &addr,
                applicant_bound,
                acceptor,
                accept_retry,
            )
            .await;
        }
    });

    // `healthy` goes true HERE, and this is the only place it can: both
    // surfaces are bound, which is the same claim a leaf's bool makes before
    // its accept loop. It is also the last field the host is waiting on before
    // it concludes ready — the peers went true as each leg came up, and the
    // hatch bit on the ticker's first pass.
    //
    // A bind that fails panics the task above, and that panic does NOT end this
    // process: nothing sets `panic = "abort"`, and `install_panic` only adds a
    // hook that logs and returns, so the unwind stops at the task boundary and
    // `main` is never told. What actually happens is that the task dies holding
    // the sender, the sender drops, and the receive below yields an error —
    // which is what the check exists for. Neither branch reaches
    // `declare_serving`, so there is no path on which this guest claims to be
    // listening and is not.
    let (client_bind, applicant_bind) = tokio::join!(client_is_bound, applicant_is_bound);
    if client_bind.is_err() || applicant_bind.is_err() {
        safe_logger::error_and_panic!(
            "api: a serving listener ended before it reported itself bound. Stopping.",
            reason!("constant text about ports on the measured command line")
        )
    }
    api_health.declare_serving();
    info!(
        "api: serving",
        reason!("a constant, and the ports are on the measured command line")
    );

    let _ = tokio::join!(client_handle, applicant_handle);
}

/// Dial the trusted storage-CVM (session KV + L2 cwasm cache) over RA-TLS and
/// hand back both backends on one connection. This is api's ONLY durable-state
/// backend — the legacy hatch/Redis + host object_store path was retired, so
/// there is no runtime selector. `addr` is `crate::fleet::legs`'; it is dialed
/// as `how` says, and this end of the leg held up as `leg` does.
async fn build_storage_backends(
    addr: String,
    attestor: Arc<dyn Attestor>,
    api_health: Arc<health::ApiHealth>,
    how: fleet::Dial,
    leg: storage_rpc::LegSettings,
) -> (Arc<dyn SessionBackend>, Arc<dyn CacheBackend>) {
    // Two clients, one connection: they go up and down together, so one
    // supervisor installs into both legs.
    let session_leg = fleet::Leg::new();
    let cache_leg = fleet::Leg::new();
    {
        let (session_leg, cache_leg) = (session_leg.clone(), cache_leg.clone());
        let addr = addr.clone();
        let attestor = attestor.clone();
        fleet::supervise(
            health::Peer::Storage,
            addr.clone(),
            how,
            api_health,
            move || {
                let (addr, attestor) = (addr.clone(), attestor.clone());
                async move { storage::connect_storage(&addr, attestor, leg).await }
            },
            move |clients| match clients {
                Some(c) => {
                    session_leg.set(Some(c.session));
                    cache_leg.set(Some(c.cache));
                }
                None => {
                    session_leg.set(None);
                    cache_leg.set(None);
                }
            },
        )
        .await;
    }

    let session: Arc<dyn SessionBackend> = Arc::new(storage::SessionCvmBackend::new(session_leg));
    let cache: Arc<dyn CacheBackend> = Arc::new(storage::CacheCvmBackend::new(cache_leg));
    (session, cache)
}

/// The 32-byte secret every sealed byte this process writes is sealed under.
///
/// Under `sev-snp` the chip derives it from a seed fused into the part, bound
/// to this image's measurement — so it is never transported, never configured,
/// and no other release can reproduce it. Everywhere else it is a hex value
/// from the environment, which is a dev convenience and nothing more: a key
/// that arrives from outside is a key whoever sent it also holds.
#[cfg(feature = "sev-snp")]
fn load_tee_seal_key() -> [u8; 32] {
    enclavid_attestation::derive_seal_key().unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "api: the chip did not return a sealing key. Stopping.",
            reason!("a constant reporting a platform state the host provisioned")
        )
    })
}

#[cfg(not(feature = "sev-snp"))]
fn load_tee_seal_key() -> [u8; 32] {
    let hex_str =
        std::env::var("ENCLAVID_TEE_KEY").expect("ENCLAVID_TEE_KEY not set (32-byte hex)");
    let bytes = hex::decode(hex_str).expect("ENCLAVID_TEE_KEY: invalid hex");
    bytes
        .try_into()
        .expect("ENCLAVID_TEE_KEY: must be 32 bytes")
}
