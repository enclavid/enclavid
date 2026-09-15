//! The `execution-worker` deployable: the SUPERVISOR of the execute side.
//!
//! It LISTENS for the orchestrator (api) and serves `engine_rpc::ExecutorService`
//! — the same api-facing contract as before — but it runs NO wasm itself. Per
//! reducer round it drives a fresh `engine-executor-child` PROCESS (spawned + bounded +
//! deadline-guarded + reaped by the shared [`engine_supervisor::ChildPool`]), primes
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
//! worker answers [`RunOutcome::CacheMiss`] and runs nothing, and the
//! orchestrator resolves the bundle under its own key and comes back on
//! `run_with_bundle`. So the OCI-pull / compile probe surface never touches the
//! worker, and the worker never names a cache slot back (L2 cache-poisoning
//! defence).
//!   * api → supervisor: the orchestrator passes a `CallbackServiceClient` into
//!     `run`.
//!   * supervisor → child: the supervisor stands up a [`RelayCallbacks`]
//!     ([`ChildCallbacks`]) that forwards the child's `media_load` /
//!     `session_change` on to the api client — so the untrusted-wasm child gets
//!     blob + state I/O but never the seal key.
//!
//! **What is domain vs supervisor.** The generic process plumbing — spawn a
//! disposable child over a socketpair, bound concurrency, enforce the per-round
//! wall-clock DEADLINE (so a wedged child can't leak its slot), kill + reap, and
//! the capability-scoped fd handoff — lives in [`engine_supervisor::ChildPool`],
//! shared with the compile-worker. What stays HERE is the executor's domain: the
//! memfd-backed L1 and the callback relay.
//!
//! **L1.** The supervisor owns the fleet's ONLY in-memory L1, one
//! [`CompositionEntry`] per `(caller measurement, composition_key)` — the caller
//! is in the key because entries are written by whoever calls and read by
//! whoever asks, and only the digest keeps one peer's bytes out of another's.
//! See [`Caller`].
//!
//! The compiled `cwasm` lives there as a single anonymous in-RAM file — a sealed
//! Linux `memfd` in prod, an unlinked tmpfile in dev — held by fd, NOT as heap
//! bytes and NOT as a named file (the two earlier copies collapse into this
//! one). On an L1 miss it returns
//! [`RunOutcome::CacheMiss`]; the orchestrator resolves the bundle under its OWN
//! `composition_key` and re-drives through `run_with_bundle`, whose bundle the
//! supervisor writes into the memfd (`try_get_with` coalesces concurrent installs
//! into ONE write) and DROPS the wire `Vec`. Each per-round child then MMAPs it via
//! a read-only fd the supervisor hands it — never a path — so no child can reach
//! another composition's code. A live `Component` never crosses the process
//! boundary; the `Component::deserialize` unsafe sink stays in the disposable child.
//!
//! Transport to api: a listener under mutual RA-TLS — TCP by default, vsock
//! under that feature, which is what the measured image builds. The
//! supervisor↔child hop is a private per-child socketpair (never leaves this
//! host).

use std::fs::File;
use std::io::Write;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;

use engine_supervisor::{ChildPool, Hardening};
use moka::future::Cache;
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use zeroize::Zeroizing;

use enclavid_boundary::{AuthN, AuthZ, Covert, Exposed, Untrusted};
use engine_executor::admission::{fd_budget, is_precompiled_component, l1_entry_weight};
use engine_executor::{Event, SessionState, compat_token};
use engine_rpc::{
    BundleRef, CallbackError, CallbackService, CallbackServiceClient, CatalogEntry, ChildCallbacks,
    ChildCallbacksServerShared, ChildService, ChildServiceClient, CompatToken, CompiledBundle,
    CompositionKey, ExecError, ExecutorServiceUntrusted, Padded, Prop, RunOutcome, RunReply,
    RunRequest, RunStatus,
};
use engine_types::composition::EmbeddedImport;
use fleet_transport::LegFailure;
use safe_logger::{debug, info, reason, safe, warn};

/// One composition's compiled artifact, resolved + cached SUPERVISOR-side and the
/// L1's value. The cwasm is a single anonymous in-RAM file held by fd — a sealed
/// Linux `memfd` (no filesystem name, RAM-backed, write-sealed) in prod, an unlinked
/// tmpfile in dev — so it is the FLEET's ONE copy of these bytes: the wire `Vec` from
/// api is written here and dropped. Each per-round child receives a read-only fd to
/// THIS file (never a path); the file's CLOEXEC + the deliberate dup2 in
/// [`engine_supervisor`] mean no child can reach another composition's fd. Freed when
/// the last fd closes — this entry dropping plus any child unmapping.
///
/// The cwasm is plaintext (possible embedded ML weights), but it is NOT scrubbed on
/// drop: SEV-SNP blinds the host to this RAM whether live or freed, and the entry is
/// legitimately resident in the cache for the whole time its composition is in use —
/// so a kernel-level in-guest attacker would read the LIVE copy regardless, and
/// zeroing the freed copy buys almost nothing for a chunk of `unsafe`. (Scrubbing is
/// spent where it pays and is safe: key material via `secrecy`, not bulk plaintext.)
struct CompositionEntry {
    /// The cwasm as an anonymous file (memfd/tmpfile); handed to the child by fd.
    cwasm: File,
    /// What this whole entry costs, in bytes — `CompiledBundle::retained_bytes`,
    /// so the two metadata fields below are charged too. The moka weigher budgets
    /// the L1 by it, subject to the per-entry floor in
    /// [`engine_executor::admission`] that stops a weightless entry from being
    /// free.
    retained: u64,
    /// Per-catalog i18n/icons import manifest (registered as strict host `Linker`
    /// instances at prime). Small in every legitimate composition, and NOT small
    /// by construction — it comes verbatim from a caller no leaf can identify, so
    /// it is charged rather than assumed.
    embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs (the registry-builder inputs). Charged for
    /// the same reason, and it is the bigger of the two.
    catalogs: Vec<CatalogEntry>,
}

/// Materialize `bytes` as the anonymous in-RAM file the child MMAPs by fd. On the
/// Linux CVM that is a sealed `memfd`: RAM-backed (never touches disk), nameless,
/// and — once written — WRITE/GROW/SHRINK-sealed so even a compromised
/// same-composition child can't mutate the shared read-only code pages other
/// children map. CLOEXEC, so an unrelated child spawn never inherits it — only
/// [`engine_supervisor`]'s deliberate dup2 hands it to the ONE target child.
#[cfg(target_os = "linux")]
fn anon_cwasm(bytes: &[u8]) -> Result<File, String> {
    let mfd = memfd::MemfdOptions::default()
        .close_on_exec(true)
        .allow_sealing(true)
        .create("enclavid-cwasm")
        .map_err(|e| format!("memfd_create: {e}"))?;
    {
        let mut w: &File = mfd.as_file();
        w.write_all(bytes)
            .map_err(|e| format!("write cwasm memfd: {e}"))?;
    }
    mfd.add_seals(&[
        memfd::FileSeal::SealShrink,
        memfd::FileSeal::SealGrow,
        memfd::FileSeal::SealWrite,
        memfd::FileSeal::SealSeal,
    ])
    .map_err(|e| format!("seal cwasm memfd: {e}"))?;
    Ok(mfd.into_file())
}

/// Dev/test (macOS) fallback: an unlinked tmpfile has the same anonymous, fd-only,
/// refcounted lifetime as a Linux memfd (no name after unlink; no sealing). Never
/// used on the Linux CVM.
#[cfg(not(target_os = "linux"))]
fn anon_cwasm(bytes: &[u8]) -> Result<File, String> {
    let mut f = tempfile::tempfile().map_err(|e| format!("tempfile: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("write cwasm tmpfile: {e}"))?;
    Ok(f)
}

/// The path a child feeds to `deserialize_file` to MMAP the inherited cwasm fd:
/// `/proc/self/fd/N` on Linux, `/dev/fd/N` on macOS — both re-open the fd the
/// supervisor installed at [`engine_supervisor::FIRST_INHERITED_FD`].
#[cfg(target_os = "linux")]
const FD_PATH_PREFIX: &str = "/proc/self/fd/";
#[cfg(not(target_os = "linux"))]
const FD_PATH_PREFIX: &str = "/dev/fd/";

/// Concurrent callback invocations the per-run relay handles. `media_load` /
/// `session_change` are serialized by the round in practice, so a small pool is
/// ample (mirrors the api-side callback server).
const CALLBACK_CONCURRENCY: usize = 4;

/// Wall-clock ceiling on ONE round in the child (tunable via
/// `ENCLAVID_ROUND_DEADLINE_SECS`; enforced by the [`ChildPool`]). A child that
/// WEDGES rather than crashes — an escaped payload that keeps its remoc reactor
/// answering keepalives while parking the `run`, or a hung upstream callback —
/// would otherwise hold its child-slot permit forever and, after `max_children`
/// such rounds, starve the WHOLE worker (the exact whole-worker blast radius this
/// split exists to bound; remoc has a dead-transport timeout but NO per-request
/// deadline). On expiry the pool kills the child and we surface
/// `ExecError::Unknown` so api returns 5xx and the applicant retries against
/// intact api-side state. Not `Policy`, even though a hanging policy is one way to
/// reach this: a spawn failure arrives the same way and is ours, and this side
/// cannot tell them apart.
/// Generous so no legitimately slow round (ML inference, OCR) is false-killed.
const DEFAULT_ROUND_DEADLINE_SECS: u64 = 120;

/// Default L1 (memfd cwasm-cache) RAM budget (tunable via
/// `ENCLAVID_BUNDLE_CACHE_BYTES`). The cache is weighed by what an entry RETAINS,
/// so this is a BYTE ceiling, not an entry count: each cwasm is ~10-15 MiB of memfd
/// RAM, so an entry-count cap would nominally admit >100 GB, and an authenticated
/// consumer minting many distinct `composition_key`s could OOM the supervisor
/// (crashing every concurrent in-flight round). 2 GiB holds ~130-200 compositions,
/// far under any deployment box.
///
/// A byte budget alone is not the whole bound, because an entry costs a DESCRIPTOR
/// as well as RAM and a degenerate cwasm costs no RAM at all. What closes that is
/// [`engine_executor::admission`]: entries are charged a floor derived from this
/// number, and a bundle that is not a composition never becomes one. And the
/// budget is charged `CompiledBundle::retained_bytes`, not the cwasm's length, so
/// the metadata an entry also keeps is inside this ceiling rather than beside it.
const DEFAULT_BUNDLE_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The `engine_rpc::ExecutorService` impl. Shared (`Arc`) across api connections;
/// each round runs in its own child, spawned + bounded + deadline-guarded by
/// [`ChildPool`].
struct Supervisor {
    /// L1: ONE [`CompositionEntry`] per composition — the cwasm as an anonymous
    /// in-RAM fd plus its small registry metadata. Long-lived across sessions +
    /// rounds; the expensive layer (OCI pull + compile + api round-trip) is what
    /// this saves. Replaces the former split byte-cache + tmpfs-file cache: the
    /// cwasm lives ONCE here, delivered to each child by fd.
    compositions: Cache<(String, String), Arc<CompositionEntry>>,
    /// The disposable per-round child pool (spawn + concurrency bound + round
    /// deadline + reap), shared with the compile-worker.
    pool: ChildPool,
    /// This runtime's cwasm ABI id, parsed ONCE at boot. Parsed rather than
    /// formatted per miss so a build whose runtime version does not fit the wire
    /// shape stops at boot, where an operator sees it, instead of failing the
    /// first round that misses.
    compat_token: CompatToken,
}

impl Supervisor {
    /// Materialize a CALLER-PROVIDED bundle into the L1 memfd cache under `slot`,
    /// coalescing concurrent installs of the same slot into ONE memfd write
    /// (`try_get_with`); errors aren't cached (a transient failure retries).
    ///
    /// `slot` is `(caller measurement, composition_key)` and is built by
    /// [`Caller`], never here — the composition half is the caller's to choose,
    /// the measurement half is not the caller's at all. That is what bounds the
    /// damage: a caller can occupy any slot it likes inside its own partition and
    /// none outside it. This used to rest on the caller BEING the orchestrator,
    /// which nothing checked; see [`Caller`] for what went wrong with that.
    ///
    /// WITH WHAT it may occupy one is the other half, and it is answered here
    /// rather than in the child: the bytes must look like a serialized component
    /// before they are given a descriptor. See [`engine_executor::admission`] for
    /// why an entry no child could ever MMAP is a whole-worker problem and not a
    /// wasted slot.
    async fn install_bundle(
        &self,
        slot: (String, String),
        bundle: CompiledBundle,
    ) -> Result<Arc<CompositionEntry>, ExecError> {
        // BEFORE `try_get_with`, so refused bytes never occupy the coalescing slot
        // and never reach `anon_cwasm`. A header read — the deserialization that
        // would act on these bytes stays in the disposable child, where it belongs.
        if !is_precompiled_component(&bundle.cwasm) {
            debug!("install_bundle: refused — not a wasmtime-serialized component");
            return Err(ExecError::Unknown);
        }
        // What the whole entry will cost, measured BEFORE the bundle is taken
        // apart: every field, not just the cwasm, because every field is retained
        // and every field came from the caller.
        let retained = bundle.retained_bytes();
        self.compositions
            .try_get_with(slot, async move {
                let CompiledBundle {
                    cwasm,
                    embedded_imports,
                    catalogs,
                } = bundle;
                // Zeroize the transient wire copy on drop: it's plaintext (possible
                // model weights) and, once written into the memfd, a needless second
                // heap copy. (The remoc/ciborium receive buffers upstream stay
                // unscrubbed — outside our control — so SEV-SNP remains the real
                // host-side guarantee; this just removes the copy we own.)
                let cwasm = Zeroizing::new(cwasm);
                let file = anon_cwasm(&cwasm).map_err(|m| {
                    debug!("materialize cwasm: {m}");
                    ExecError::Unknown
                })?;
                // The wire `Vec` drops here (zeroized) — the memfd is now the ONLY copy.
                Ok::<_, ExecError>(Arc::new(CompositionEntry {
                    cwasm: file,
                    retained,
                    embedded_imports,
                    catalogs,
                }))
            })
            .await
            .map_err(|arc: Arc<ExecError>| (*arc).clone())
    }

    /// Spawn a fresh disposable child, prime it with `entry`'s cwasm memfd, drive
    /// ONE round through the callback relay, and return the round's reply. Shared by
    /// `run` (L1 hit) and `run_with_bundle` (post-miss install).
    /// `entry` (holding the memfd open) lives across the whole `pool.run().await`, so
    /// the fd handed at fork/dup2 is valid; the child's own inherited fd then keeps
    /// the memfd alive independently.
    async fn run_in_child(
        &self,
        entry: Arc<CompositionEntry>,
        session_state: SessionState,
        event: Event,
        props: Vec<(String, Prop)>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<RunStatus, ExecError> {
        let cwasm_fd = entry.cwasm.as_fd();
        // The child re-opens its inherited fd (`/proc/self/fd/N`) and MMAPs it via
        // `deserialize_file`; the 7-15 MiB never crosses the child hop — only the
        // fd-path + small metadata do.
        let bundle_ref = BundleRef {
            cwasm_path: format!("{FD_PATH_PREFIX}{}", engine_supervisor::FIRST_INHERITED_FD),
            embedded_imports: entry.embedded_imports.clone(),
            catalogs: entry.catalogs.clone(),
        };

        // Drive ONE round in a fresh disposable child, under the pool's concurrency
        // bound + wall-clock deadline (the pool kills + reaps a wedged child so it
        // can't leak its slot). The pool installs the cwasm fd at
        // `FIRST_INHERITED_FD` in the child; the closure is the DOMAIN work: prime
        // the child (MMAP the cwasm), stand up the callback relay, run.
        let outcome = self
            .pool
            .run(
                std::slice::from_ref(&cwasm_fd),
                move |client: ChildServiceClient<Ciborium>| async move {
                    // Prime: the child MMAPs the cwasm via `deserialize_file` on its
                    // inherited fd; only the fd-path + small metadata cross the hop.
                    client.prime(bundle_ref).await?;

                    // Relay: the child's media_load / session_change forward THROUGH
                    // here to api's callbacks (the seal-key holder).
                    let relay = Arc::new(RelayCallbacks {
                        upstream: callbacks,
                    });
                    let (relay_server, relay_client) =
                        ChildCallbacksServerShared::<_, Ciborium>::new(relay, CALLBACK_CONCURRENCY);
                    tokio::spawn(async move {
                        let _ = relay_server.serve(true).await;
                    });

                    client.run(session_state, event, props, relay_client).await
                },
            )
            .await;

        // The pool returns the closure's domain `Result<RunStatus, ExecError>` on
        // success; a pool-level failure (spawn error, or the deadline killing a
        // wedged child) becomes a fail-safe `ExecError::Unknown` (api 5xx →
        // applicant retry).
        match outcome {
            Ok(domain_result) => domain_result,
            // A pool failure is NOT attributed to the policy, and the deadline is
            // the interesting case: a policy CAN provoke it by hanging, so calling
            // it `Policy` would be defensible — but a spawn failure and a
            // shutting-down pool arrive the same way and are ours. This side
            // cannot tell them apart, so it says it cannot.
            Err(pool_err) => {
                debug!("child supervisor: {pool_err}");
                Err(ExecError::Unknown)
            }
        }
    }
}

/// One caller's view of the supervisor: the shared machinery, plus WHICH peer is
/// asking.
///
/// The L1 cache is the reason this type exists. It is process-wide — one moka
/// map behind one `Supervisor`, shared by every connection — and its entries are
/// written by whoever calls `run_with_bundle`, under a key that same caller
/// chose. The comment on `install_bundle` used to carry the whole safety
/// argument: "the orchestrator both COMPUTED the key AND resolved the bundle".
/// That is a claim about WHO IS ON THE OTHER END, and nothing enforced it — the
/// leaves accept any attested guest, because they cannot pin api's measurement
/// without a cycle.
///
/// Unenforced, it fails like this: a guest the host launched calls
/// `run_with_bundle` with the key api will use next and native code of its own.
/// api's later cache-only `run` finds the slot filled, and the attacker's code
/// executes inside a real round, holding that applicant's decrypted state and
/// captures. api sees a cache hit — the fast, ordinary path — and never resolves
/// the real bundle at all.
///
/// So the premise stops being assumed and becomes structural: entries are
/// partitioned by the CALLER's measurement, and a caller cannot choose that. It
/// comes from a report the AMD Secure Processor signed, bound to the very TLS
/// key the caller proved it holds — replaying api's report needs api's ephemeral
/// private key, which never leaves api's encrypted memory and does not outlive
/// one connection. So a foreign caller lands under its own digest, always, and
/// api's partition is reachable only by something running api's image, which is
/// api.
///
/// Note what this is NOT: it decides nothing about who may call. `AcceptAny`
/// stays. It only stops callers reaching each other — the same move the child
/// sandbox makes, where untrusted wasm is contained rather than identified.
struct Caller {
    sup: Arc<Supervisor>,
    /// The peer's launch digest, read from its verified certificate — see
    /// `enclavid_ra_tls::peer_measurement` for why that is trustworthy only
    /// after the handshake, which is the only place this is built.
    measurement: String,
}

impl Caller {
    fn slot(&self, composition_key: &CompositionKey) -> (String, String) {
        (
            self.measurement.clone(),
            composition_key.as_str().to_string(),
        )
    }
}

/// Take a round's inputs out of the scope this role named.
///
/// INDIFFERENT, kind 4, and it is a property of this role's POSITION rather than
/// of the bytes. Nothing derived from a round leaves the caller's own partition:
/// the slot it names is inside that partition, the work runs in a disposable child,
/// and the answer goes back only to whoever asked. So hostile input reaches its own
/// round and its own caller, and who produced it cannot matter to anyone else.
///
/// Not "nothing outlives the call", which is the compile-worker's sentence and is
/// false here. This role HAS a cache: `run_with_bundle` files an entry under the
/// key this request named, and it is served to later calls for an hour. That is a
/// difference between the two leaves rather than a hole in this one — the compile
/// worker's statelessness and this worker's partitioning are the two ways the same
/// missing pin gets answered — but the sentence had to say which one it is using.
///
/// The decoder bounds are the PREMISE of that, not the discharge — "the whole
/// range is safe to act on" is only a sentence if the range is bounded, and until
/// this leg had bounds it was not:
///
///   * `composition_key` — `CompositionKey`'s decoder: 64 lowercase hex, so it is
///     a digest rendering and nothing else.
///   * `session_state` — `Padded`'s exact-frame decode: a frame of any other size
///     is refused outright.
///   * `props` — the count and byte bounds in its decoder. LOOSER than api's own
///     ingress cap, deliberately, so a legitimate round is never refused here;
///     what matters to this role is that the set is finite, not that it matches.
///   * `event` — the frame count and clip budget in `Clip`'s decoder, likewise.
///
/// None of that is a check on AUTHENTICITY and none of it is claimed as one —
/// `engine_rpc::keys` says as much about its own types. The thing that would make
/// authenticity checkable is a pin this leaf cannot have.
fn open_round(req: Untrusted<RunRequest, (AuthN,)>) -> RunRequest {
    req.trust_unchecked::<AuthN, _>(enclavid_boundary::reason!(
        "indifferent: nothing derived from a round leaves the caller's own partition \
         — the slot it names is inside that partition, the work runs in a disposable \
         child, and the answer goes back only to whoever asked; every field was \
         bounded by its own decoder, which is what makes that range a finite one"
    ))
    .into_inner()
}

/// What is still open on a value this role is about to release to its caller.
///
/// The same three the outbound perimeter opens everywhere, read in this role's own
/// position:
///
///   * `AuthN` — CONFIDENTIALITY: can the host read these bytes? It splices this
///     hop and counts every one of them.
///   * `AuthZ` — which party may receive this? The sharp one here, because this
///     role cannot answer "which party" at all: it runs `AcceptAny`.
///   * `Covert` — hidden bandwidth in the encoded shape. The only axis that
///     differs per value, and the only one closed by doing work.
type ToCaller<T> = Exposed<T, (AuthN, AuthZ, Covert)>;

/// The two answers that are the same for everything this role releases.
///
/// `AuthN` is IDENTIFIED in the sense the outbound perimeter uses it — the hop is
/// mutual RA-TLS terminated inside two SNP guests, so the host process that splices
/// it carries ciphertext. That this side cannot say WHICH guest is the other
/// concern's problem, not this one's.
///
/// `AuthZ` is NO-SECRET, and it is the load-bearing sentence on this whole leg.
/// This role cannot identify its caller, so "may this party receive it" has no
/// answer of the usual kind. What makes the release safe is that every input to it
/// came from that same caller: the round's arguments it just sent, and the compiled
/// code it installed itself, in a partition only it can reach.
///
/// Note the second half is not "a pure function of this call". A cache HIT serves
/// bytes an earlier call installed, and a cache MISS returns this build's own ABI
/// id, which is no function of the request at all. Both stay NO-SECRET for the same
/// underlying reason — the caller supplied the one and already holds the other —
/// but the shorter sentence would have been false.
///
/// It is the partition that carries this, which is why [`Caller`] builds the slot
/// from a measurement no caller can choose, and why the compile-worker's
/// statelessness is described as load-bearing rather than incidental. If this role
/// ever returns something derived from ANOTHER caller's input, this sentence
/// becomes false and the release becomes a leak.
fn to_caller<T>(value: T) -> Exposed<T, (Covert,)> {
    let open: ToCaller<T> = Exposed::new(value);
    open.vouch_unchecked::<AuthN, _>(reason!(
        "identified: the hop is mutual RA-TLS terminated inside two SNP guests, so \
         the host process that splices it carries ciphertext"
    ))
    .vouch_unchecked::<AuthZ, _>(reason!(
        "no-secret: computed from what this caller sent, over code this caller itself \
         installed, inside its own L1 partition — every input is one it supplied, so \
         it learns nothing it did not already hold and no answer about WHICH caller \
         is needed"
    ))
}

/// Mint a completed round's status as a released, constant-size frame.
///
/// `Covert` is TRANSFORMED, and it is done rather than promised: the peel's
/// codomain IS the wire type, so there is no path from here to a `RunOutcome::Ran`
/// that skipped the padding. Both halves of what it hides are the policy's to
/// choose — the opaque state and the resolved prompt — and this is the hop the
/// host counts.
///
/// The overflow arm is `Unknown` rather than `Policy`, and it is very nearly
/// unreachable besides. `RunStatus` and `SessionState` are framed to the SAME
/// constant while the state's encoding strictly contains this one's, and
/// `session_change` fires over the same prompt one step earlier — so a prompt that
/// would not fit here failed there first and the round already returned. Naming
/// the policy here would attribute a case this side reaches only when the earlier
/// check did not, which is a case it cannot explain.
fn outbound_ran(status: &RunStatus) -> Result<Exposed<RunOutcome, ()>, ExecError> {
    Ok(to_caller(status).vouch::<Covert, _, _, _, _>(|s| {
        Padded::seal(s).map(RunOutcome::Ran).map_err(|e| {
            debug!("framing the round's status: {e}");
            ExecError::Unknown
        })
    })?)
}

/// Mint a cache miss. `Covert` is BOUNDED rather than transformed: the reply is a
/// variant plus a [`CompatToken`], whose shape caps it at 64 characters of a fixed
/// alphabet and whose value is a constant of this measured build — so what varies
/// is nothing this side chose per call.
fn outbound_cache_miss(compat_token: CompatToken) -> Exposed<RunOutcome, ()> {
    to_caller(RunOutcome::CacheMiss { compat_token }).vouch_unchecked::<Covert, _>(reason!(
        "bounded: a variant plus this build's own ABI id, capped at 64 characters of \
         a fixed alphabet and identical on every miss this image serves"
    ))
}

/// Mint the post-miss reply. Same frame, same reasons as [`outbound_ran`] — a
/// different envelope around the identical value, because this call always runs.
fn outbound_reply(status: &RunStatus) -> Result<Exposed<RunReply, ()>, ExecError> {
    Ok(to_caller(status).vouch::<Covert, _, _, _, _>(|s| {
        Padded::seal(s)
            .map(|status| RunReply { status })
            .map_err(|e| {
                debug!("framing the round's status: {e}");
                ExecError::Unknown
            })
    })?)
}

impl ExecutorServiceUntrusted for Caller {
    /// What this role does not know about its caller.
    ///
    /// `AuthN` and nothing else. The listener runs `AcceptAny` — it cannot pin api
    /// without a cycle — so a completed handshake proves a genuine SNP guest on
    /// this part and NOT that it is api. That is the one question open here, and
    /// it is open in a way it never is on api's side of the same wire: the
    /// sentence `trust_unchecked::<AuthN>(reason!("RA-TLS against a pinned
    /// measurement"))` is true over there and false here.
    ///
    /// Not `AuthZ`: a caller reaches only its own L1 partition and the name of
    /// another's is not expressible from here, which is a shape rather than a
    /// judgement — see [`Caller`]. Not `Replay`: a round is a call with arguments,
    /// not a read from a store, so there is no version for one to be stale from.
    /// Not `Asserted`: that asks whose word a value is, and the role that can ask
    /// it about THIS one is the role receiving this one's output.
    type Scope = (AuthN,);

    /// The L1-cache path: run the composition if it is cached, else report the miss
    /// so the orchestrator resolves the bundle (under ITS OWN key) and re-drives via
    /// [`run_with_bundle`](Self::run_with_bundle). No bundle crosses on this call.
    async fn run(
        &self,
        req: Untrusted<RunRequest, Self::Scope>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<Exposed<RunOutcome, ()>, ExecError> {
        let RunRequest {
            composition_key,
            props,
            session_state,
            event,
        } = open_round(req);
        match self
            .sup
            .compositions
            .get(&self.slot(&composition_key))
            .await
        {
            // The frame comes off HERE, at the api hop, and goes back on in the
            // mint: everything between is inside this CVM, where no host counts
            // bytes. `open()` is api's frame and the mint's `seal()` is the
            // POLICY's resolved prompt, so the two failures are not the same
            // failure — the first is `Unknown` by the conversion's own default.
            Some(entry) => self
                .sup
                .run_in_child(entry, session_state.open()?, event, props, callbacks)
                .await
                .and_then(|status| outbound_ran(&status)),
            // Miss: the worker returns ONLY its ABI id — it never names the key.
            None => Ok(outbound_cache_miss(self.sup.compat_token.clone())),
        }
    }

    /// The post-miss path: the orchestrator supplies the bundle it resolved under
    /// `req.composition_key`; file it in L1 under THAT key and run. Always runs (a
    /// bundle is in hand), so it returns the [`RunReply`] directly. The worker files
    /// bytes only under the caller's own key IN THE CALLER'S OWN PARTITION, so it
    /// can poison neither another composition's slot nor another peer's.
    async fn run_with_bundle(
        &self,
        req: Untrusted<RunRequest, Self::Scope>,
        bundle: Untrusted<CompiledBundle, Self::Scope>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<Exposed<RunReply, ()>, ExecError> {
        let RunRequest {
            composition_key,
            props,
            session_state,
            event,
        } = open_round(req);
        // NO KIND FITS, and that is the honest answer rather than a gap to be
        // filled. Nothing here re-derives these bytes — this role holds no
        // Cranelift by design. Nothing binds them: a digest the caller also chose
        // is its word twice, and there is no second party on this hop to have
        // established one. The range is not harmless; it is native code. And they
        // are not contained to their author, because a later cache-only `run`
        // under the same key serves them again.
        //
        // What bounds it is structural and is named here so a reader can weigh it:
        // the entry lands in the CALLER's own partition and no other caller can
        // reach it, the bytes are refused unless they are a serialized component
        // at all, and the deserialization runs in a disposable per-round child
        // behind an address-space boundary. A standing accepted risk, which is
        // what it should look like on every audit.
        let bundle = bundle
            .trust_unchecked::<AuthN, _>(reason!(
                "no kind fits — an accepted risk, not a discharge. Not verified: no \
                 key, signature or digest this side holds covers these bytes. Not \
                 identified: the listener accepts any attested guest. Not \
                 self-produced, and not indifferent — the range is native code. \
                 Contained instead: the caller's own L1 partition, an admission \
                 check that they are a serialized component, and a disposable \
                 per-round child around the deserialize"
            ))
            .into_inner();
        let entry = self
            .sup
            .install_bundle(self.slot(&composition_key), bundle)
            .await?;
        let status = self
            .sup
            .run_in_child(entry, session_state.open()?, event, props, callbacks)
            .await?;
        outbound_reply(&status)
    }
}

/// Forwards the child's narrowed callbacks straight to api's full
/// `CallbackService` client. The upstream client method already returns the same
/// `Result<_, CallbackError>` these methods return (remoc folds transport errors
/// into `CallbackError`), so each is a one-line forward.
struct RelayCallbacks {
    upstream: CallbackServiceClient<Ciborium>,
}

impl ChildCallbacks for RelayCallbacks {
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
        self.upstream.media_load(hash).await
    }

    /// The child seam behind this call is a socketpair inside this CVM — no host
    /// on it — so the frame goes on HERE, at the hop the host splices, and not one
    /// layer earlier where it would be a megabyte of memcpy per round against no
    /// observer. This is our own measured code performing a protocol step, not a
    /// discharge written by the party a marker distrusts: `Covert` is a property
    /// of the encoding at a hop, and this process is the one holding the bytes at
    /// it.
    async fn session_change(&self, state: SessionState) -> Result<(), CallbackError> {
        self.upstream.session_change(Padded::seal(&state)?).await
    }
}

/// Locate the `engine-executor-child` binary: `ENCLAVID_EXECUTOR_CHILD_BIN` if set, else
/// the sibling of this supervisor's own executable. They SHIP together — the
/// image installs both into `/bin` — but they are built apart, each package by
/// its own cargo invocation, which is what keeps `engine-executor-child`'s
/// dependency graph the short one its manifest declares. Fails loud if neither
/// resolves — per the minimal-defaults rule.
fn child_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ENCLAVID_EXECUTOR_CHILD_BIN") {
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
        let listener = fleet_transport::health::bind(&health_addr).await;
        let health = health.clone();
        tokio::spawn(async move {
            fleet_transport::health::serve(listener, move || health.body()).await
        });
    }

    // Fail CLOSED if the kernel isn't hardened enough to keep one escaped child
    // out of a sibling child's in-flight applicant memory (the per-round isolation
    // rests on this). The real enforcement is the measured CVM image; this makes a
    // regressed image crash here instead of silently losing the guarantee.
    engine_supervisor::assert_ptrace_hardened();

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

    // Hard cap on concurrent per-round children (deployment envelope). Tunable;
    // a sane default keeps memory bounded (one process each).
    let max_children: usize = std::env::var("ENCLAVID_MAX_CHILDREN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);

    // Fail CLOSED if this process cannot open the descriptors its own two caps are
    // counted in. Here rather than beside `assert_ptrace_hardened` because the
    // budget is a function of `max_children`, which the host sets and this line has
    // only just read — a check run earlier would be checking a number nobody chose.
    engine_supervisor::assert_fd_budget(fd_budget(max_children as u64));

    let round_deadline = Duration::from_secs(
        std::env::var("ENCLAVID_ROUND_DEADLINE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_ROUND_DEADLINE_SECS),
    );
    let bundle_cache_bytes: u64 = std::env::var("ENCLAVID_BUNDLE_CACHE_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BUNDLE_CACHE_BYTES);

    // Child sandbox posture: egress seccomp is ALWAYS ON. It is a CONFIDENTIALITY
    // control and must not be disableable by the untrusted host, which provisions
    // the CVM environment (same root as tee_seal_key-from-env); it rides the
    // measured image, so disabling it is a rebuild + re-attest, not a runtime knob.
    // No RLIMIT_AS on the execute side — wasm linear memory is capped by wasmtime
    // `StoreLimits`, and wasmtime reserves large VIRTUAL memory a hard `RLIMIT_AS`
    // would break.
    let hardening = Hardening {
        seccomp_egress: true,
        address_space: None,
    };

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
        // ONE L1: the cwasm memfd + registry metadata per composition. Weigh each
        // entry by what it RETAINS — every field, not the cwasm alone — so
        // `max_capacity` is a RAM budget rather than an entry count (each cwasm is
        // ~10-15 MiB of memfd RAM). That closes the consumer-driven OOM.
        //
        // Through `l1_entry_weight`, so the charge also has a FLOOR. Weighing by
        // size alone made a small entry cheap and a zero-length one free, and an
        // entry costs a DESCRIPTOR whether or not it costs RAM — the floor is what
        // makes this one number bound both.
        compositions: Cache::builder()
            .weigher(move |_key, v: &Arc<CompositionEntry>| {
                l1_entry_weight(v.retained, bundle_cache_bytes)
            })
            .max_capacity(bundle_cache_bytes)
            .time_to_idle(Duration::from_secs(3600))
            .build(),
        pool: ChildPool::new(
            child_exe.clone(),
            max_children,
            round_deadline,
            Some(hardening),
        ),
        compat_token,
    });

    let listener = fleet_transport::bind(&addr).await.unwrap_or_else(|e| {
        debug!("{e}");
        safe_logger::error_and_panic!(
            "execution-worker: cannot bind {}. Stopping.",
            safe(&addr, reason!("on the measured command line")),
            reason!("a constant; the address is the host's own configuration")
        )
    });
    info!(
        "execution-worker (supervisor): listening on {}, engine-executor-child={}, \
         max_children={}, round_deadline={}s, bundle_cache={} MiB",
        safe(&addr, reason!("on the measured command line")),
        safe(
            &child_exe.display(),
            reason!("a location inside the measured image")
        ),
        safe(&max_children, reason!("a constant of the measured build")),
        safe(
            &round_deadline.as_secs(),
            reason!("a constant of the measured build")
        ),
        safe(
            &(bundle_cache_bytes / (1024 * 1024)),
            reason!("a constant of the measured build")
        ),
        reason!(
            "the listen address is on the measured command line; the limits and the \
             child path are constants of the measured image. Emitted at boot, before \
             any policy has been composed, let alone run"
        )
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
                if let Err(e) = serve_conn(stream, ratls, svc).await {
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

/// RA-TLS-accept one api connection, then frame it with remoc and serve `ExecutorService`.
async fn serve_conn(
    stream: fleet_transport::Stream,
    ratls: tokio_rustls::TlsAcceptor,
    svc: Arc<Supervisor>,
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
    // it delegates to — the L1 map and the child pool — stays shared, which is
    // what makes the pool ONE concurrency budget rather than one per caller.
    let caller = Arc::new(Caller {
        sup: svc,
        measurement,
    });
    // Bringing the hop up means naming the generated client, and that is the one
    // thing no crate outside engine-rpc may do — so the remoc half lives there for
    // this end too, and this one keeps what it is actually about: who connected.
    engine_rpc::serve_executor(read, write, caller, 4)
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
