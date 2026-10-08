//! The api-facing service: a round on a kept composition, or on a bundle the
//! caller streams in, each run in a disposable child.

use std::fs::File;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;

use enclavid_boundary::{AuthN, AuthZ, Covert, Exposed, Untrusted};
use engine_executor::{Event, SessionState};
use engine_rpc::{
    BundleMeta, BundleRef, BundleStream, CallbackServiceClient, ChildCallbacksServerShared,
    ChildService, ChildServiceClient, CompatToken, CompositionKey, ExecError,
    ExecutorServiceUntrusted, Padded, Prop, RunOutcome, RunReply, RunRequest, RunStatus,
};
use engine_supervisor::{ChildRunner, Exit, Fate, SupervisorError};
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;
use safe_logger::{debug, reason};
use tokio::sync::{Semaphore, SemaphorePermit, TryAcquireError};
use tokio::time::Instant;

use crate::bundles::{Bundles, Claim, CompositionEntry, LastUsed, Lease, entry_charge};
use crate::cwasm::{Cwasm, Incoming};
use crate::relay::RelayCallbacks;

/// A place for one round in this worker, taken as its handler starts and held
/// until it answers; with none free the round answers [`ExecError::Busy`] at once,
/// before it waits for anything. See [`engine_executor::admission::rounds_held`]
/// for what the count bounds.
pub(crate) fn round_place(rounds: &Semaphore) -> Result<SemaphorePermit<'_>, ExecError> {
    rounds.try_acquire().map_err(|e| match e {
        TryAcquireError::NoPermits => ExecError::Busy,
        TryAcquireError::Closed => ExecError::Unknown,
    })
}

/// What the runner's own failure tells api.
///
/// A round the runner never admitted ran nothing, and that is the one failure it
/// can name. Everything else is `Unknown`, and the deadline is the interesting
/// case: a policy CAN provoke it by hanging, so calling it `Policy` would be
/// defensible — but a spawn failure arrives the same way and is ours. This side
/// cannot tell them apart, so it says it cannot.
fn runner_failure(e: SupervisorError) -> ExecError {
    debug!("child supervisor: {e}");
    match e {
        SupervisorError::Busy(_) => ExecError::Busy,
        SupervisorError::Room(_)
        | SupervisorError::Group(_)
        | SupervisorError::Spawn(_)
        | SupervisorError::Handshake(_)
        | SupervisorError::Deadline(_) => ExecError::Unknown,
    }
}

/// The round's answer, from what the runner returned.
///
/// A child's own `Busy` is answered `Unknown`. By the time a child replies it has
/// run — it may have changed the session through `session_change` — so it is the
/// one party that cannot truthfully say nothing ran, and `Busy` tells api exactly
/// that. Only a failure this supervisor decided before spawning may carry it.
///
/// A child that died without answering reaches here as `Unknown` — the leg to it
/// closed — and the kernel's record of its life says whether the round itself
/// was the cause: killed at its own max, with the children's total never
/// reached meanwhile, is the policy's, the same as a trap; anything else stays
/// `Unknown`. Only then is the exit waited for, and never long: see
/// [`Exit::fate`]. A reply the child did send is kept whatever became of it.
async fn child_reply(
    outcome: Result<(Result<RunStatus, ExecError>, Exit), SupervisorError>,
) -> Result<RunStatus, ExecError> {
    match outcome {
        Ok((Err(ExecError::Busy), _)) => Err(ExecError::Unknown),
        Ok((Err(ExecError::Unknown), exit)) => match exit.fate().await {
            Fate::OutgrewItsMax => Err(ExecError::Policy),
            Fate::Unattributed => Err(ExecError::Unknown),
        },
        Ok((domain_result, _)) => domain_result,
        Err(e) => Err(runner_failure(e)),
    }
}

/// The `engine_rpc::ExecutorService` impl. Shared (`Arc`) across api connections;
/// each round runs in its own child, spawned + bounded + deadline-guarded by
/// [`ChildRunner`].
pub(crate) struct Supervisor {
    /// L1: ONE [`CompositionEntry`] per composition — the cwasm as an anonymous
    /// in-RAM fd plus its small registry metadata. Long-lived across sessions +
    /// rounds; the expensive layer (OCI pull + compile + api round-trip) is what
    /// this saves. The cwasm lives ONCE here, delivered to each child by fd.
    pub(crate) bundles: Bundles,
    /// One permit per round in flight, [`engine_executor::admission::rounds_held`]
    /// of the children in all, across every caller: taken without waiting as a
    /// handler starts, held until it answers.
    pub(crate) rounds: Semaphore,
    /// How long a round waits for room before it answers busy
    /// ([`engine_executor::admission::DEFAULT_CAPACITY_WAIT_SECS`]).
    pub(crate) capacity_wait: Duration,
    /// How long a bundle may take to stream in whole
    /// ([`engine_rpc::DEFAULT_BUNDLE_STREAM_DEADLINE`]).
    pub(crate) bundle_stream: Duration,
    /// How long a bundle stream may go without a new byte
    /// ([`engine_rpc::DEFAULT_BUNDLE_STREAM_IDLE`]).
    pub(crate) bundle_stream_idle: Duration,
    /// The fuel each round's child is given to burn
    /// ([`engine_executor::DEFAULT_ROUND_FUEL`]).
    pub(crate) round_fuel: u64,
    /// How many of a child's callbacks may wait on its relay
    /// ([`engine_rpc::DEFAULT_CALLBACK_REQUEST_BUFFER`]).
    pub(crate) callback_request_buffer: usize,
    /// The disposable per-round child runner (spawn + concurrency bound + round
    /// deadline + reap), shared with the compile-worker. Its slots are the child
    /// bound, and a round is admitted to one only with room for one more child
    /// under the children's total and in the guest
    /// ([`engine_executor::admission::DEFAULT_ROUND_HEADROOM_BYTES`]) — both
    /// waited for no longer than `capacity_wait` together. What each child then
    /// holds, the kernel holds it to.
    pub(crate) runner: ChildRunner,
    /// This runtime's cwasm ABI id, parsed ONCE at boot. Parsed rather than
    /// formatted per miss so a build whose runtime version does not fit the wire
    /// shape stops at boot, where an operator sees it, instead of failing the
    /// first round that misses.
    pub(crate) compat_token: CompatToken,
}

impl Supervisor {
    /// Stream a CALLER-PROVIDED bundle into the L1 under `slot`, or hand back the
    /// entry already there.
    ///
    /// `slot` is `(caller measurement, composition_key)` and is built by
    /// [`Caller`], never here — the composition half is the caller's to choose,
    /// the measurement half is not the caller's at all. That is what bounds the
    /// damage: a caller can occupy any slot it likes inside its own partition and
    /// none outside it. This used to rest on the caller BEING the orchestrator,
    /// which nothing checked; see [`Caller`] for what went wrong with that.
    ///
    /// WITH WHAT it may occupy one is the other half, and it is answered here
    /// rather than in the child: the bytes must arrive whole and look like a
    /// serialized component before they become an entry. See
    /// [`engine_executor::admission`] for why an entry no child could ever MMAP is
    /// a whole-worker problem and not a wasted slot.
    ///
    /// One round fills a slot at a time. A round that misses on a slot another
    /// round is filling waits for that fill rather than staging its own, and
    /// finds the entry when it ends; if it ended without one — refused, stalled,
    /// or its caller gone — the waiting round fills the slot from its own stream.
    /// So a failed stream fails its own round and no other, and a composition is
    /// staged once however many rounds miss on it together. Staged OUTSIDE the
    /// cache and kept only once finished, but within its budget: what the fill
    /// will hold is reserved out of it by the lengths the stream declares, before
    /// a byte is read (see [`Bundles::reserve`]). Everything a round waits for
    /// here — another's fill, room — it waits for no longer than the capacity
    /// wait in all, then answers busy.
    async fn cache_bundle(&self, slot: Slot, bundle: BundleStream) -> Result<Lease, ExecError> {
        let deadline = Instant::now() + self.capacity_wait;
        // Found kept, this round's stream is never read. Its writer sees the end
        // close, which costs it nothing — the round's outcome is the reply.
        let fill = match self.bundles.claim(&slot, deadline).await? {
            Claim::Kept(lease) => return Ok(lease),
            Claim::Fill(fill) => fill,
        };
        let (cwasm_declared, meta_declared) = bundle.declared();
        let room = self
            .bundles
            .reserve(cwasm_declared, meta_declared, deadline)
            .await?;
        let incoming = Incoming::new().map_err(|m| {
            debug!("make a file for the cwasm: {m}");
            ExecError::Unknown
        })?;
        let (cwasm_len, meta, meta_len) = {
            let mut sink: &File = incoming.writer();
            bundle
                .receive(&mut sink, self.bundle_stream, self.bundle_stream_idle)
                .await
                .map_err(|e| {
                    debug!("bundle stream: {e}");
                    ExecError::Unknown
                })?
        };
        // Every byte arrived at its declared length and digest. Only now is the
        // file sealed and read — a header read; the deserialization that would act
        // on these bytes stays in the disposable child, where it belongs.
        let cwasm = incoming.finish().map_err(|e| {
            debug!("cache_bundle: {e}");
            ExecError::Unknown
        })?;
        let BundleMeta {
            embedded_imports,
            catalogs,
        } = meta;
        let entry = CompositionEntry {
            cwasm,
            charged: entry_charge(cwasm_len, meta_len),
            embedded_imports: embedded_imports.into(),
            catalogs: catalogs.into(),
            used: LastUsed::now(),
        };
        self.bundles.keep(fill, room, entry)
    }

    /// Spawn a fresh disposable child, prime it with the leased entry's cwasm
    /// memfd, drive ONE round through the callback relay, and return the round's
    /// reply. Shared by `run` (L1 hit) and `run_with_bundle` (post-miss cache
    /// fill). The lease goes to the runner with the child, which lets go of it once
    /// the child has exited: the child maps the memfd through the fd it inherits,
    /// which the entry holds open until then, so the entry stays in the budget
    /// for as long as its memory is in use.
    async fn run_in_child(
        &self,
        lease: Lease,
        session_state: SessionState,
        event: Event,
        props: Vec<(String, Prop)>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<RunStatus, ExecError> {
        let entry = lease.entry().clone();
        let cwasm_fd = entry.cwasm.as_fd();
        // References to the entry's metadata, not copies of it: the child's
        // `prime` request shares the entry's catalogs, so a round holds none of
        // its own, waiting or running.
        let (embedded_imports, catalogs) = (entry.embedded_imports.clone(), entry.catalogs.clone());
        let (fuel, callback_buffer) = (self.round_fuel, self.callback_request_buffer);

        // Drive ONE round in a fresh disposable child, under the runner's
        // concurrency bound + wall-clock deadline (the runner kills + reaps a wedged
        // child so it can't leak its slot), admitted — a slot, and room for the
        // child — within the capacity wait. The runner installs the cwasm fd at
        // `INHERITED_FD` in the child; the closure is the DOMAIN work: prime the
        // child (MMAP the cwasm), stand up the callback relay, run.
        let outcome = self
            .runner
            .run(
                Some(cwasm_fd),
                lease,
                move |client: ChildServiceClient<Ciborium>| async move {
                    // Prime: the child re-opens its inherited fd
                    // (`/proc/self/fd/N`) and MMAPs it via `deserialize_file`; the
                    // cwasm never crosses the child hop — only the fd-path + small
                    // metadata do.
                    let bundle_ref = BundleRef {
                        cwasm_path: Cwasm::path_in_child(),
                        embedded_imports,
                        catalogs,
                    };
                    client.prime(bundle_ref).await?;

                    // Relay: the child's media_load / session_change forward THROUGH
                    // here to api's callbacks (the seal-key holder).
                    let relay = Arc::new(RelayCallbacks {
                        upstream: callbacks,
                    });
                    let (relay_server, relay_client) =
                        ChildCallbacksServerShared::<_, Ciborium>::new(relay, callback_buffer);
                    tokio::spawn(async move {
                        let _ = relay_server.serve(true).await;
                    });

                    client
                        .run(session_state, event, props, fuel, relay_client)
                        .await
                },
            )
            .await;

        // The runner returns the closure's domain `Result<RunStatus, ExecError>`
        // beside how the child ended; a runner-level failure becomes `Busy` if the
        // round was never admitted, and a fail-safe `Unknown` otherwise (api 5xx
        // → applicant retry).
        child_reply(outcome).await
    }
}

/// One caller's view of the supervisor: the shared machinery, plus WHICH peer is
/// asking.
///
/// The L1 cache is the reason this type exists. It is process-wide — one
/// [`Bundles`] behind one `Supervisor`, shared by every connection — and its entries are
/// written by whoever calls `run_with_bundle`, under a key that same caller
/// chose. The comment on `cache_bundle` used to carry the whole safety
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
pub(crate) struct Caller {
    pub(crate) sup: Arc<Supervisor>,
    /// The peer's launch digest, read from its verified certificate — see
    /// `enclavid_ra_tls::peer_measurement` for why that is trustworthy only
    /// after the handshake, which is the only place this is built.
    pub(crate) measurement: String,
}

impl Caller {
    fn slot(&self, composition_key: &CompositionKey) -> Slot {
        Slot {
            caller: self.measurement.clone(),
            composition: composition_key.clone(),
        }
    }
}

/// Which L1 entry: the measurement the caller that filled it proved, and the
/// composition it named. Its fields are this module's, so the only way to one
/// is [`Caller::slot`], from a measurement read off a verified handshake — a
/// caller names any composition it likes in its own partition, and nothing
/// names one in another's.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct Slot {
    caller: String,
    composition: CompositionKey,
}

#[cfg(test)]
impl Slot {
    /// A slot for a test that has no handshake to read a caller from.
    pub(crate) fn of(caller: &str, composition: CompositionKey) -> Self {
        Self {
            caller: caller.to_owned(),
            composition,
        }
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
/// key this request named, and it is served to later calls for as long as it is
/// kept. That is a difference between the two leaves rather than a hole in this
/// one — the compile worker's statelessness and this worker's partitioning are the
/// two ways the same missing pin gets answered — but the sentence had to say which
/// one it is using.
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
/// code it cached itself, in a partition only it can reach.
///
/// Note the second half is not "a pure function of this call". A cache HIT serves
/// bytes an earlier call cached, and a cache MISS returns this build's own ABI
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
         cached, inside its own L1 partition — every input is one it supplied, so \
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
    to_caller(status).vouch::<Covert, _, _, _, _>(|s| {
        Padded::seal(s).map(RunOutcome::Ran).map_err(|e| {
            debug!("framing the round's status: {e}");
            ExecError::Unknown
        })
    })
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
    to_caller(status).vouch::<Covert, _, _, _, _>(|s| {
        Padded::seal(s)
            .map(|status| RunReply { status })
            .map_err(|e| {
                debug!("framing the round's status: {e}");
                ExecError::Unknown
            })
    })
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
        let _round = round_place(&self.sup.rounds)?;
        let RunRequest {
            composition_key,
            props,
            session_state,
            event,
        } = open_round(req);
        match self.sup.bundles.lease(&self.slot(&composition_key)) {
            // The frame comes off HERE, at the api hop, and goes back on in the
            // mint: everything between is inside this CVM, where no host counts
            // bytes. `open()` is api's frame and the mint's `seal()` is the
            // POLICY's resolved prompt, so the two failures are not the same
            // failure — the first is `Unknown` by the conversion's own default.
            Some(lease) => self
                .sup
                .run_in_child(lease, session_state.open()?, event, props, callbacks)
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
        bundle: Untrusted<BundleStream, Self::Scope>,
        callbacks: CallbackServiceClient<Ciborium>,
    ) -> Result<Exposed<RunReply, ()>, ExecError> {
        // Before the cache fill as well as the child: a round waiting for either
        // holds its request.
        let _round = round_place(&self.sup.rounds)?;
        let RunRequest {
            composition_key,
            props,
            session_state,
            event,
        } = open_round(req);
        // NO KIND FITS, and that is the honest answer rather than a gap to be
        // filled. Nothing here re-derives these bytes — this role holds no
        // Cranelift by design. Nothing binds them: the stream's length and digest
        // are the caller's own word about its own bytes, its word twice, and there
        // is no second party on this hop to have established one. The range is not
        // harmless; it is native code. And they are not contained to their author,
        // because a later cache-only `run` under the same key serves them again.
        //
        // What bounds it is structural and is named here so a reader can weigh it:
        // the entry lands in the CALLER's own partition and no other caller can
        // reach it, the bytes are refused unless they arrive at their declared
        // length and digest and the sealed file reads as a serialized component,
        // and the deserialization runs in a disposable per-round child behind an
        // address-space boundary. A standing accepted risk, which is what it should
        // look like on every audit.
        let bundle = bundle
            .trust_unchecked::<AuthN, _>(reason!(
                "no kind fits — an accepted risk: no key or pin covers these bytes, \
                 their length and digest are the sender's own word, and the range is \
                 native code. Contained by the caller's own L1 partition and a \
                 disposable child around the deserialize; admitted only whole, \
                 digest-matched and component-shaped"
            ))
            .into_inner();
        let lease = self
            .sup
            .cache_bundle(self.slot(&composition_key), bundle)
            .await?;
        let status = self
            .sup
            .run_in_child(lease, session_state.open()?, event, props, callbacks)
            .await?;
        outbound_reply(&status)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::Semaphore;

    use engine_executor::admission::{DEFAULT_WAITING_PER_CHILD, rounds_held};
    use engine_executor::{Decision, Prompt};
    use engine_rpc::{ExecError, RunStatus};
    use engine_supervisor::{Exit, Fate, SpawnError, SupervisorError};

    use super::{child_reply, round_place, runner_failure};

    /// Every place taken: the next round answers busy without waiting, and a
    /// place handed back is free for the round after it.
    #[test]
    fn a_round_with_no_place_answers_busy_at_once() {
        let places = rounds_held(1, DEFAULT_WAITING_PER_CHILD);
        let rounds = Semaphore::new(places);
        let held: Vec<_> = (0..places)
            .map(|_| round_place(&rounds).expect("a place is free"))
            .collect();
        assert_eq!(round_place(&rounds).err(), Some(ExecError::Busy));
        drop(held);
        assert_eq!(rounds.available_permits(), places);
        assert!(round_place(&rounds).is_ok());
    }

    /// Of the runner's failures, only a round it never admitted is busy.
    #[test]
    fn only_an_unadmitted_round_is_busy() {
        let d = Duration::from_secs(1);
        assert_eq!(runner_failure(SupervisorError::Busy(d)), ExecError::Busy);
        for e in [
            SupervisorError::Room(std::io::Error::other("room")),
            SupervisorError::Group(std::io::Error::other("group")),
            SupervisorError::Spawn(SpawnError::Closed),
            SupervisorError::Handshake(d),
            SupervisorError::Deadline(d),
        ] {
            assert_eq!(runner_failure(e), ExecError::Unknown);
        }
    }

    fn unattributed() -> Exit {
        Exit::known(Fate::Unattributed)
    }

    /// A child has run by the time it answers, so its `Busy` is not passed on;
    /// the supervisor's own is, and a child's other answers are untouched.
    #[tokio::test]
    async fn a_child_cannot_answer_busy() {
        assert_eq!(
            child_reply(Ok((Err(ExecError::Busy), unattributed())))
                .await
                .err(),
            Some(ExecError::Unknown)
        );
        assert_eq!(
            child_reply(Ok((Err(ExecError::Policy), unattributed())))
                .await
                .err(),
            Some(ExecError::Policy)
        );
        assert_eq!(
            child_reply(Err(SupervisorError::Busy(Duration::from_secs(1))))
                .await
                .err(),
            Some(ExecError::Busy)
        );
    }

    /// A child that died unanswered, killed at its own max while the
    /// children's total was never reached, is the policy's — the answer a trap
    /// gets.
    #[tokio::test]
    async fn a_child_killed_at_its_own_max_is_the_policy() {
        let exit = Exit::known(Fate::OutgrewItsMax);
        assert_eq!(
            child_reply(Ok((Err(ExecError::Unknown), exit))).await.err(),
            Some(ExecError::Policy)
        );
    }

    /// Any other death says nothing about the round: the runner killed it, the
    /// total or the guest ran short, or the record does not settle it.
    #[tokio::test]
    async fn a_child_killed_for_any_other_reason_is_unknown() {
        assert_eq!(
            child_reply(Ok((Err(ExecError::Unknown), unattributed())))
                .await
                .err(),
            Some(ExecError::Unknown)
        );
    }

    /// What a child did answer is its answer: a kill recorded afterwards — on
    /// its way out, or by the runner — changes none of it.
    #[tokio::test]
    async fn a_reply_is_kept_whatever_the_childs_fate() {
        let answered = child_reply(Ok((
            Ok(RunStatus::Completed(Decision::Approved)),
            Exit::known(Fate::OutgrewItsMax),
        )))
        .await;
        assert!(matches!(
            answered,
            Ok(RunStatus::Completed(Decision::Approved))
        ));
        let awaiting = child_reply(Ok((
            Ok(RunStatus::AwaitingInput(Prompt::Media(Default::default()))),
            Exit::known(Fate::OutgrewItsMax),
        )))
        .await;
        assert!(matches!(awaiting, Ok(RunStatus::AwaitingInput(_))));
        assert_eq!(
            child_reply(Ok((
                Err(ExecError::Policy),
                Exit::known(Fate::OutgrewItsMax)
            )))
            .await
            .err(),
            Some(ExecError::Policy)
        );
    }
}
