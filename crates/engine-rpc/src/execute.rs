//! Execute boundary — run + mid-call callbacks (the bidirectional case).
//!
//! Gated behind the `execute` feature: an execution-worker built with only
//! this feature links the executor + callback contract + `hatch-client` +
//! `engine-types` (the run needs the composition catalogs), and NOT the
//! compiler contract — least-knowledge for its measured image, and NO Cranelift.
//!
//! ## Who caches what
//!
//! The execution-worker owns the ONLY in-memory L1 (deserialized components,
//! keyed by `composition_key`). The orchestrator owns L2 (sealed cwasm files;
//! it holds `tee_seal_key`, the keyless worker cannot). On an L1 miss the worker
//! does not pull anything: it ANSWERS, returning
//! [`RunOutcome::CacheMiss`] with its `compat_token` and running nothing. The
//! orchestrator then resolves the bundle under its own key — from L2, or by
//! compiling on an L2 miss (OCI pull + compile-worker) and sealing the result
//! into L2 — and calls [`ExecutorService::run_with_bundle`]. The bundle streams
//! beside that call ([`BundleStream`]), so the request is the round alone.
//!
//! The direction is the point. A callback the worker could call to ask for a
//! composition would be a probe surface on the key-holding side, driven by the
//! keyless one; a return value is not. `compat_token` keys L2, so a fleet
//! version bump repartitions the cache instead of feeding a stale cwasm to an
//! incompatible runtime.

use serde::{Deserialize, Serialize};
pub use serde_bytes::ByteBuf;

use hatch_client::{Decision, Event, Prompt, SessionState};

use crate::BundleRef;
use crate::keys::{CompatToken, CompositionKey};
use crate::padded::{Framed, Padded};
use crate::stream::BundleStream;

/// serde mirror of the bindgen `enclavid:host/types.prop` — the consumer's
/// static-config scalar the policy reads via `context.props`. api builds this
/// from the session's JSON config (`enclavid-api::input`); the worker maps it
/// back to the bindgen `Prop` before the run. Defined here (not a bindgen
/// re-export) so the client-only orchestrator builds props without wasmtime.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Prop {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
}

/// serde mirror of the engine's `RunStatus` — one round's outcome. Wraps the
/// hatch_client domain `Prompt`/`Decision` (already serde; both are sealed
/// into `SessionState`). The worker maps `engine_executor::RunStatus` into this
/// at the boundary; the orchestrator projects it into the applicant view, and
/// checks a terminal one against the decision the round committed, without
/// pulling wasmtime.
#[derive(Debug, Serialize, Deserialize)]
pub enum RunStatus {
    /// Policy rendered a prompt and is awaiting the matching applicant input.
    AwaitingInput(Prompt),
    /// Policy finished with a terminal decision.
    Completed(Decision),
}

/// A run failure, in the distinctions the applicant's screen turns on.
///
/// It used to be `Run(String)`, built as `format!("{e:#}")` over the entire anyhow
/// chain. That chain interpolates text adversary-authored wasm supplied — a policy
/// calling `i18n::get(k)` with an undeclared `k` put `k` verbatim into the message
/// — so the POLICY chose the reply's byte count, on a hop a host process splices
/// and counts. The framing that closes that channel on a round which SUCCEEDS did
/// not cover the round that traps, and a policy can trap deliberately and retry.
///
/// Two values a POLICY can reach, and the number is the design rather than an
/// accident of how many things can go wrong. Every additional variant is a value
/// the policy can SELECT by choosing how to fail, so the cardinality here should
/// be exactly what the receiving side acts on — and api acts on one thing: whether
/// to tell the applicant that the fault is not theirs.
///
/// The third, [`Busy`](ExecError::Busy), is not one of those: it is decided
/// before a child exists, so no policy is running to choose it, and api acts on
/// it separately — nothing ran, so the answer is "the same request, later". The
/// worker keeps it its own: a child that sends it back is answered `Unknown`.
///
/// **The bit is CHEAP, and an earlier draft of this doc said otherwise.** It
/// claimed "trapping yields `Policy` and hanging yields `Unknown`, so the channel
/// runs at a bit per two minutes". A policy reaches `Unknown` without hanging: an
/// oversized resolved prompt overflows the state frame during `session_change`,
/// which fires BEFORE the reply is built, and a failed callback is `Unknown` by
/// design. So a policy picks either value in one ordinary round.
///
/// What that costs, stated properly: a policy already chooses whether a round
/// fails at all, which is one bit nothing can take away. This variant makes the
/// failing case two-valued, so the round carries `log2(3)` rather than `log2(2)` —
/// about half a bit more. It is bought deliberately, and what it buys is the
/// applicant being told the fault is not theirs instead of staring at a 500.
///
/// Deliberately carries NO diagnostic detail, in either variant, and that is a
/// real cost rather than a free win. What went wrong is authored by the consumer's
/// own wasm, and the roles that could describe it speak only INWARD — a worker's
/// per-round `warn!` would be a channel to the host, which is the same party as
/// the policy's author when they are the same party. Boot-time reporting is not:
/// it names constants of the measured image, before any applicant exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecError {
    /// The CONSUMER's policy failed where this side can SEE that it was the
    /// policy: it trapped, exhausted its fuel, asked the host for something it
    /// never declared, or was killed at its round's own memory max while
    /// the round children's total was not reached.
    ///
    /// api turns this into a 4xx so the applicant is told the fault is not theirs
    /// and can report it. Attributing it is safe in the direction that matters:
    /// this side does not say WHAT the policy did, only that the policy is what
    /// failed.
    Policy,
    /// Something else failed and this side cannot attribute it: a bundle that
    /// would not load, a spawn that did not happen, a leg that went away, a frame
    /// that did not fit, a child killed while the guest's memory was short.
    ///
    /// It is the honest answer for several failures a policy CAN cause — hanging
    /// past the round deadline, and overflowing a frame with an oversized prompt —
    /// because the mechanism that catches each of those catches ours the same way
    /// and this side cannot tell them apart. Attributing them to the policy would
    /// be a guess, and a guess that reads as an accusation on the applicant's
    /// screen. Capping the resolved prompt where the policy PRODUCES it would move
    /// that case into [`Policy`](ExecError::Policy) honestly; it is not done.
    ///
    /// Named for what it is rather than for a cause it does not know. api answers
    /// 5xx.
    Unknown,
    /// Nothing ran: the worker had no room for this round — no place for it to
    /// wait, or within its wait no cache fill slot or no memory for one more child.
    ///
    /// Decided before a child is spawned, so the round's policy never ran and
    /// cannot have chosen it; what it reports is load on the worker, which the
    /// host carrying this hop sees anyway. The session is exactly where it was,
    /// so api answers 503 and the same request later is the whole of the
    /// recovery.
    Busy,
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Policy => write!(f, "the policy failed"),
            ExecError::Unknown => write!(f, "the round failed"),
            ExecError::Busy => write!(f, "no room for the round"),
        }
    }
}
impl std::error::Error for ExecError {}
impl From<remoc::rtc::CallError> for ExecError {
    fn from(_: remoc::rtc::CallError) -> Self {
        ExecError::Unknown
    }
}

/// A callback failed. That is the whole of it, and the absence of a payload is the
/// design.
///
/// It used to be `CallbackError(pub String)`, and it travelled api → worker over
/// the same multiplexed connection the run does — so the same host process spliced
/// and counted it. api's producers interpolated SIZES into that string:
/// `persister`'s pad failure named the encoded `SessionState`'s actual byte count,
/// and its envelope failure named the disclosure's. Those are the very numbers
/// [`Padded`] and the seal padding exist to keep off a wire. A policy that could
/// make a `session_change` fail therefore read its own state's true length back out
/// of the traffic — the channel reopened on the failure path, exactly as it had on
/// the round-reply path before [`ExecError`] was fixed.
///
/// Carries nothing now, for the same reason that one carries two values: the
/// cardinality of a wire error should be what the RECEIVER acts on, and here that
/// is nothing at all. Both of the child's relays map any callback failure to the
/// same thing (see `round_failure` in `engine-executor-child`), so every byte of
/// the old string was a byte no reader used and a host could count.
///
/// The detail stays with the producer, on its own inward log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackError;

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the callback failed")
    }
}
impl std::error::Error for CallbackError {}
impl From<remoc::rtc::CallError> for CallbackError {
    fn from(_: remoc::rtc::CallError) -> Self {
        CallbackError
    }
}

/// A callback failure, as this contract's own error.
///
/// `Unknown` and not `Policy`: what failed is the leg back to the seal-key holder,
/// so the policy is not what this side would be attributing it to. The callback's
/// own text is dropped rather than relayed — a string built on the far side of a
/// keyless process has no business setting this reply's byte count, and api's
/// producers put SIZES in it.
///
/// The SHIPPED path does not come through here. A child's relay turns a
/// `CallbackError` into a `wasmtime::Error` so it unwinds the running policy, and
/// the child's own mapping is what picks the variant — see `round_failure` there.
/// This impl serves the in-crate test mock, and states which variant a callback
/// failure is, which that mapping matches.
impl From<CallbackError> for ExecError {
    fn from(_: CallbackError) -> Self {
        ExecError::Unknown
    }
}

/// One reducer round's inputs on the wire. `session_state`/`event`/`props` are the
/// round's already-decrypted inputs (the seal key stays orchestrator-side).
///
/// `deny_unknown_fields`, for the reason [`CompiledBundle`](crate::CompiledBundle)
/// carries it: the two ends of this hop are the same binary version, so a field
/// one side does not know is version skew and must fail closed rather than be
/// silently dropped into a round that then runs on a partial request.
///
/// Every field is bounded by its own decoder — the key by its shape, the props by
/// count and bytes, the state by its exact frame, the event's frames by the
/// ingress budget. That is what lets the serving role write a discharge that names
/// a check instead of naming its caller.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    /// Names the fused component in the worker's L1 cache. Computed by the
    /// ORCHESTRATOR and authoritative end-to-end — the worker only ever caches /
    /// serves under this key and never names a key back, so it cannot steer which
    /// slot a compile lands in (L2 cache-poisoning defence).
    pub composition_key: CompositionKey,
    /// Static consumer config the policy reads via `context.props`. Bounded on
    /// decode — see the `props` module below.
    #[serde(deserialize_with = "props::deserialize")]
    pub props: Vec<(String, Prop)>,
    /// FRAMED: `state` and `current_prompt` are both policy-chosen lengths, and a
    /// host process splices this hop byte-for-byte. See [`Padded`].
    pub session_state: Padded<SessionState>,
    pub event: Event,
}

/// What a round request carries besides the clip's bytes, the state frame and the
/// bundle header: the key, the props, the frames' and the event's CBOR heads, and
/// remoc's own envelope with the reply, callback and two bundle-stream ports. About
/// 10 KiB with every field at its bound; the rest is margin.
pub(crate) const RUN_REQUEST_HEADROOM: usize = 64 * 1024;

// A round request travels as ONE remoc item, and an item past the limit fails the
// channel it was sent on for good. The bundle does not ride in it — it streams
// beside the call — so what has to fit is the round itself plus the header naming
// the bundle. `run` sends the same request without the header.
const _: () = assert!(
    hatch_client::MAX_CLIP_BYTES
        + <SessionState as Framed>::FRAME
        + crate::stream::BUNDLE_HEADER_MAX_ENCODED
        + RUN_REQUEST_HEADROOM
        <= remoc::rch::DEFAULT_MAX_ITEM_SIZE,
    "a round request at its bounds no longer fits one remoc item"
);

/// The bound on [`RunRequest::props`], applied where the value is decoded.
///
/// It exists on this side because the worker cannot see api's ingress cap and must
/// not assume its caller is api: the leaves accept any attested guest. The numbers
/// are `engine_types::limits`' restatement of api's `MAX_MATCH_INPUT_SIZE`, and
/// the derivation is written there.
mod props {
    use super::Prop;
    use engine_types::limits::{MAX_PROPS, MAX_PROPS_BYTES};
    use serde::de::{self, SeqAccess, Visitor};

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<(String, Prop)>, D::Error> {
        struct Props;

        impl<'de> Visitor<'de> for Props {
            type Value = Vec<(String, Prop)>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most {MAX_PROPS} static config entries")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                // No `with_capacity` off the size hint: the hint is the sender's
                // claim about how much this side should allocate, which is the
                // thing being bounded.
                let mut out: Vec<(String, Prop)> = Vec::new();
                let mut bytes = 0usize;
                while let Some((k, v)) = seq.next_element::<(String, Prop)>()? {
                    if out.len() == MAX_PROPS {
                        return Err(de::Error::custom(format!(
                            "more than {MAX_PROPS} static config entries"
                        )));
                    }
                    bytes = bytes.saturating_add(k.len());
                    if let Prop::String(s) = &v {
                        bytes = bytes.saturating_add(s.len());
                    }
                    if bytes > MAX_PROPS_BYTES {
                        return Err(de::Error::custom(format!(
                            "static config over {MAX_PROPS_BYTES} bytes"
                        )));
                    }
                    out.push((k, v));
                }
                Ok(out)
            }
        }

        d.deserialize_seq(Props)
    }
}

/// One reducer round's result on the API hop: the next [`RunStatus`], framed.
///
/// State is NOT returned — it is persisted mid-run via
/// [`CallbackService::session_change`] (the orchestrator holds the seal key),
/// and the orchestrator discards the engine's vestigial returned copy, exactly
/// as the in-process path did.
///
/// The envelope exists for this hop alone. [`ChildService::run`] returns a bare
/// [`RunStatus`], because the seam behind it is a socketpair inside the
/// execution-worker with no host on it — framing there would be a megabyte of
/// memcpy per round against no observer.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReply {
    /// FRAMED: the resolved prompt is policy-chosen in length, and the VARIANT is
    /// legible by size too — a terminal `Completed` is a few bytes where an
    /// `AwaitingInput` is a whole screen.
    pub status: Padded<RunStatus>,
}

/// The result of `ExecutorService::run` (the cache-only path): either the round
/// ran from the worker's L1, or the composition is NOT cached. On
/// [`CacheMiss`](RunOutcome::CacheMiss) the orchestrator resolves the compiled
/// bundle under ITS OWN `composition_key` (L2 read or cold compile) and calls
/// `run_with_bundle`. Because the orchestrator
/// both computes the key AND supplies the bundle, the worker never names a cache
/// slot — a compromised worker cannot poison another session's compiled-code cache.
/// `compat_token` is the worker's cwasm ABI id, so the orchestrator resolves/keys L2
/// for a cwasm THIS runtime can deserialize.
#[derive(Serialize, Deserialize)]
pub enum RunOutcome {
    Ran(Padded<RunStatus>),
    CacheMiss {
        /// A [`CompatToken`] rather than a `String` because this is the one field
        /// on the hop that travels the OTHER way and ends up in a NAME: api joins
        /// it with the key it computed to address an L2 blob. See the type.
        compat_token: CompatToken,
    },
}

/// The orchestrator-served CALLBACK boundary the keyless execution-worker calls
/// BACK DURING a run: the worker holds no seal key, so blob rehydration
/// (`media_load`) and state persistence (`session_change`) happen orchestrator-
/// side. Bundle resolution is NOT here — the composition is known before the run,
/// so the orchestrator resolves it UP FRONT (see [`RunOutcome::CacheMiss`]) under
/// its own key, keeping the OCI-pull / compile probe surface off the worker
/// entirely. A [`CallbackServiceClient`] is passed to the worker as an argument to
/// `ExecutorService::run` — remoc multiplexes these callbacks over the SAME
/// connection as the in-flight run, so the key never crosses to the worker.
#[remoc::rtc::remote]
pub trait CallbackService {
    /// Rehydrate a stored blob by content hash (orchestrator unseals). `None` =
    /// miss (unknown / never-stored ref) — the worker's `from-blob-ref` traps
    /// on it, same as the in-process gate.
    ///
    /// The blob crosses as one CBOR byte string. As ciborium's integer array a
    /// capture cost close to twice its length, and the length on this hop — which
    /// the host splices — then varied with how many of the image's bytes fell
    /// under 0x18.
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<ByteBuf>, CallbackError>;

    /// Seal + persist the post-round session state and, on the round that
    /// finishes, the policy's decision — the owned form of the engine's borrowed
    /// `SessionChange`, committed in ONE write under the seal key the worker
    /// never holds. One write, so a reply lost after it leaves a session that
    /// reads as finished rather than one whose state has finished while it
    /// still reads as running.
    ///
    /// Neither what a round DISCLOSED nor what it CAPTURED travels here. The
    /// orchestrator holds both already: the disclosure it derives from the prompt
    /// it rendered and the event it built, the captures it read off `/input` and
    /// sent this side in that same event. Taking either back would be accepting,
    /// from the process that executes adversary-supplied code, a copy of
    /// something already in hand.
    ///
    /// Both FRAMED, for the same reason the outbound copy of the state is: this
    /// is the same value coming back over the same host-spliced hop, and `Covert`
    /// cannot be asked about it from api's side — api is the receiver here. The
    /// decision is framed apart from the state because its encoding is a variant
    /// NAME, whose length differs per value, and its absence is shorter still.
    async fn session_change(
        &self,
        state: Padded<SessionState>,
        decision: Padded<Option<Decision>>,
    ) -> Result<(), CallbackError>;
}

/// The execute boundary as a remote trait. The execution-worker serves it; the
/// orchestrator calls it with a [`CallbackServiceClient`] pointing at its own
/// callback server so the keyless worker can rehydrate media / persist state
/// mid-round without ever holding the seal key. Two methods split the cache paths
/// cleanly:
///
///   * [`run`](ExecutorService::run) — the L1-cache path, NO bundle: `Ran` on a
///     hit, [`RunOutcome::CacheMiss`] on a miss.
///   * [`run_with_bundle`](ExecutorService::run_with_bundle) — the post-miss path:
///     the orchestrator supplies the bundle it resolved under its OWN key; the
///     worker files it in L1 and runs. Always runs, so it returns the [`RunReply`]
///     directly (no cache-miss outcome).
///
/// The worker only ever caches / serves under the orchestrator's `composition_key`
/// and never names one back, so a compromised worker cannot poison another
/// session's cache slot.
#[remoc::rtc::remote]
pub trait ExecutorService {
    async fn run(
        &self,
        req: RunRequest,
        callbacks: CallbackServiceClient<remoc::codec::Ciborium>,
    ) -> Result<RunOutcome, ExecError>;

    /// `bundle` streams beside the request rather than riding in it — a header in
    /// the call, the bytes on two `bin` ends — so the request is the round alone
    /// and stays one bounded item whatever the bundle weighs. The caller writes
    /// while it awaits the reply; the reply is the round's outcome, and how the
    /// writing went is not.
    ///
    /// Cancellable like any other call: the stream cannot finish without its
    /// writer, so a caller that goes away takes the install with it.
    async fn run_with_bundle(
        &self,
        req: RunRequest,
        bundle: BundleStream,
        callbacks: CallbackServiceClient<remoc::codec::Ciborium>,
    ) -> Result<RunReply, ExecError>;
}

/// The supervisor↔child seam (INTERNAL to the execution-worker host — remoc over
/// a per-child socketpair, never over the api hop).
///
/// The execution-worker is a SUPERVISOR: it holds the bundle-byte L1 and runs NO
/// wasm itself. Per reducer round it spawns a fresh [`ChildService`] PROCESS,
/// [`prime`](ChildService::prime)s it once with the compiled bundle, drives
/// exactly one [`run`](ChildService::run), and discards the child. Untrusted
/// policy wasm — and the `Component::deserialize` unsafe sink — execute ONLY in
/// that disposable per-round process, so a sandbox escape is confined to one
/// round's plaintext (one applicant) behind an OS address-space boundary, with no
/// cross-round persistence.
#[remoc::rtc::remote]
pub trait ChildService {
    /// MMAP the cwasm (via `Component::deserialize_file` on `bundle.cwasm_path`)
    /// and build the reusable `InstancePre` (the engine's `prime`). The 7-15 MiB
    /// cwasm is NOT shipped — only the [`BundleRef`] path + small metadata cross
    /// the hop — so the child hop stays tiny. A deserialize failure (toolchain
    /// skew / tampered file) surfaces as [`ExecError::Unknown`] — the bundle is
    /// not the policy, so it is not attributed to one.
    ///
    /// A child killed at its own memory max while priming is answered as
    /// the policy's, like one killed during the round: what prime holds beside
    /// the engine is the composition and its catalogs as decoded, and both are
    /// the consumer's.
    async fn prime(&self, bundle: BundleRef) -> Result<(), ExecError>;

    /// Drive one reducer round against the primed composition.
    /// `session_state`/`event`/`props` are the round's already-decrypted inputs
    /// (the seal key never reaches this process), and `fuel` is what the round
    /// may burn — the supervisor's setting, the same for every round it runs.
    /// `callbacks` points at the
    /// SUPERVISOR's relay, which forwards `media_load` / `session_change` on to
    /// api — so this keyless process rehydrates blobs + persists state without
    /// the seal key, and with no way to ask for a composition at all.
    ///
    /// Nothing on this seam is framed, and the status comes back bare rather than
    /// in a [`RunReply`]: the hop is a socketpair between two processes inside one
    /// CVM, so the host that counts bytes on the api hop is not on it. The
    /// supervisor frames at the hop it actually reaches.
    async fn run(
        &self,
        session_state: SessionState,
        event: Event,
        props: Vec<(String, Prop)>,
        fuel: u64,
        callbacks: ChildCallbacksClient<remoc::codec::Ciborium>,
    ) -> Result<RunStatus, ExecError>;
}

/// The supervisor-served callback boundary a per-round engine-executor-child calls BACK
/// during a run. The supervisor already resolved and primed the bundle before
/// spawning the child, so the process running UNTRUSTED wasm has nothing to ask
/// for and is handed no way to ask — blast-radius minimization. The supervisor's
/// relay implements this and forwards each call to its own upstream
/// [`CallbackServiceClient`] (→ api, which holds the seal key). The two traits
/// carry the same pair of methods, `media_load` / `session_change`, so the relay
/// is a straight forward.
#[remoc::rtc::remote]
pub trait ChildCallbacks {
    /// Rehydrate a stored blob by content hash (api unseals). `None` = miss.
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<ByteBuf>, CallbackError>;

    /// Seal + persist the post-round state and, if the round finished, its
    /// decision — relayed to api's `session_change`, committed together under the
    /// seal key this process never holds. Neither the round's disclosure nor its
    /// captures are carried; see [`CallbackService::session_change`].
    async fn session_change(
        &self,
        state: SessionState,
        decision: Option<Decision>,
    ) -> Result<(), CallbackError>;
}

#[cfg(test)]
mod execute_tests {
    use super::*;
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;
    use std::sync::{Arc, Mutex};
    use tokio::io::split;

    /// Orchestrator-side callback target: records the media / state calls it
    /// receives and returns canned media, so the test can assert the worker called
    /// BACK with the right arguments mid-run.
    struct MockCallbacks {
        media_calls: Mutex<Vec<[u8; 32]>>,
        state_calls: Mutex<Vec<Option<Decision>>>,
    }

    impl CallbackService for MockCallbacks {
        async fn media_load(&self, hash: [u8; 32]) -> Result<Option<ByteBuf>, CallbackError> {
            self.media_calls.lock().unwrap().push(hash);
            Ok(Some(ByteBuf::from(vec![0xAB, 0xCD])))
        }
        async fn session_change(
            &self,
            _state: Padded<SessionState>,
            decision: Padded<Option<Decision>>,
        ) -> Result<(), CallbackError> {
            let decision = decision.open().map_err(|_| CallbackError)?;
            self.state_calls.lock().unwrap().push(decision);
            Ok(())
        }
    }

    /// Worker-side executor: `run` (cache-only) always MISSES in this mock (naming
    /// only its ABI id, NEVER the composition_key); `run_with_bundle` runs — calling
    /// the passed-in callback client (media_load + session_change) BACK — and replies.
    struct MockExecutor;

    impl ExecutorService for MockExecutor {
        async fn run(
            &self,
            _req: RunRequest,
            _callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunOutcome, ExecError> {
            // Cache-only path: always a miss in this mock (no L1). The worker returns
            // its ABI id and NEVER names the composition_key.
            Ok(RunOutcome::CacheMiss {
                compat_token: CompatToken::parse("test-token").expect("a legal token shape"),
            })
        }

        async fn run_with_bundle(
            &self,
            req: RunRequest,
            bundle: BundleStream,
            callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunReply, ExecError> {
            let mut cwasm = Vec::new();
            bundle
                .receive(
                    &mut cwasm,
                    crate::DEFAULT_BUNDLE_STREAM_DEADLINE,
                    crate::DEFAULT_BUNDLE_STREAM_IDLE,
                )
                .await
                .map_err(|_| ExecError::Unknown)?;
            if cwasm.is_empty() {
                return Err(ExecError::Unknown);
            }
            // Bundle in hand: run, calling BACK for media + state persistence.
            let bytes = callbacks.media_load([9u8; 32]).await?;
            if bytes != Some(ByteBuf::from(vec![0xAB, 0xCD])) {
                return Err(ExecError::Unknown);
            }
            callbacks
                .session_change(
                    req.session_state.clone(),
                    Padded::seal(&Some(Decision::Approved)).map_err(ExecError::from)?,
                )
                .await?;
            Ok(RunReply {
                status: Padded::seal(&RunStatus::Completed(Decision::Approved))
                    .map_err(ExecError::from)?,
            })
        }
    }

    type ExecCli = ExecutorServiceClient<Ciborium>;

    /// `run()` crosses to the worker WITH a callback client; on an L1 miss the
    /// worker returns `CacheMiss` (naming only its ABI id), the orchestrator
    /// resolves the bundle under ITS OWN key and re-drives with `bundle = Some(..)`,
    /// and only THEN does the keyless worker call `media_load` + `session_change`
    /// BACK, multiplexed over the ONE remoc connection. The worker never names the
    /// composition_key — the poison-a-foreign-slot vector is gone.
    #[tokio::test]
    async fn cache_miss_then_run_with_orchestrator_supplied_bundle() {
        let callbacks = Arc::new(MockCallbacks {
            media_calls: Mutex::new(Vec::new()),
            state_calls: Mutex::new(Vec::new()),
        });

        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = split(a);
        let (b_r, b_w) = split(b);

        // Worker end: serve the executor.
        let server_task = tokio::spawn(async move {
            let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(
                remoc::Cfg::default(),
                a_r,
                a_w,
            )
            .await
            .unwrap();
            tokio::spawn(conn);
            let (server, client) =
                ExecutorServiceServerShared::<_, Ciborium>::new(Arc::new(MockExecutor), 4);
            tx.send(client).await.unwrap();
            server.serve(true).await.unwrap();
        });

        // Orchestrator end: receive the executor client, stand up its OWN
        // callback server on the same connection, pass the callback client into
        // run().
        let (conn, _tx, mut rx) =
            remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(remoc::Cfg::default(), b_r, b_w)
                .await
                .unwrap();
        tokio::spawn(conn);
        let exec_client = rx.recv().await.unwrap().unwrap();

        let (cb_server, cb_client) =
            CallbackServiceServerShared::<_, Ciborium>::new(callbacks.clone(), 4);
        tokio::spawn(async move {
            let _ = cb_server.serve(true).await;
        });

        let mk_req = || RunRequest {
            composition_key: CompositionKey::from_digest([0x11; 32]),
            props: vec![("age".into(), Prop::Int(30))],
            session_state: Padded::seal(&SessionState::default()).expect("fits the frame"),
            event: Event::Start,
        };

        // Phase 1: cache-only run → miss, and NOTHING runs (no callbacks fire).
        match exec_client.run(mk_req(), cb_client.clone()).await.unwrap() {
            RunOutcome::CacheMiss { compat_token } => {
                assert_eq!(compat_token.as_str(), "test-token")
            }
            RunOutcome::Ran(_) => panic!("expected CacheMiss on the cache-only run"),
        }

        // Phase 2: orchestrator resolved the bundle under ITS OWN composition_key
        // and re-drives via run_with_bundle, writing the bundle beside the call
        // while it waits; now the round runs and calls back once.
        let (stream, writer) =
            BundleStream::split(crate::bundle::sample_bundle()).expect("the sample splits");
        let (reply, ()) = tokio::join!(
            exec_client.run_with_bundle(mk_req(), stream, cb_client),
            writer
        );
        let RunReply { status } = reply.unwrap();
        assert!(matches!(
            status.open().expect("the reply's frame decodes"),
            RunStatus::Completed(Decision::Approved)
        ));
        assert_eq!(
            callbacks.media_calls.lock().unwrap().as_slice(),
            &[[9u8; 32]]
        );
        // One commit, carrying the decision the reply reports.
        assert_eq!(
            callbacks.state_calls.lock().unwrap().as_slice(),
            &[Some(Decision::Approved)]
        );

        drop(exec_client);
        server_task.abort();
    }

    fn a_request() -> RunRequest {
        RunRequest {
            composition_key: CompositionKey::from_digest([0x11; 32]),
            props: Vec::new(),
            session_state: Padded::seal(&SessionState::default()).expect("fits the frame"),
            event: Event::Start,
        }
    }

    /// The mock executor served on one end of a real connection, and the other
    /// end's client — taken as `Cli`, which may be a wire-identical stand-in — plus
    /// a callback client for the calls to carry.
    async fn serve_mock<Cli: remoc::RemoteSend>() -> (Cli, CallbackServiceClient<Ciborium>) {
        serve::<Cli, _>(Arc::new(MockExecutor)).await
    }

    /// [`serve_mock`] with the executor named by the test.
    async fn serve<Cli: remoc::RemoteSend, E: ExecutorService + Send + Sync + 'static>(
        executor: Arc<E>,
    ) -> (Cli, CallbackServiceClient<Ciborium>) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (a_r, a_w) = split(a);
        let (b_r, b_w) = split(b);
        tokio::spawn(async move {
            let (conn, mut tx, _rx) = remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(
                crate::connection_cfg(&crate::LegSettings::default()),
                a_r,
                a_w,
            )
            .await
            .unwrap();
            tokio::spawn(conn);
            let (server, client) = ExecutorServiceServerShared::<_, Ciborium>::new(executor, 4);
            tx.send(client).await.unwrap();
            let _ = server.serve(true).await;
        });
        let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(
            crate::connection_cfg(&crate::LegSettings::default()),
            b_r,
            b_w,
        )
        .await
        .unwrap();
        tokio::spawn(conn);
        let client = rx.recv().await.unwrap().unwrap();
        let (cb_server, cb_client) = CallbackServiceServerShared::<_, Ciborium>::new(
            Arc::new(MockCallbacks {
                media_calls: Mutex::new(Vec::new()),
                state_calls: Mutex::new(Vec::new()),
            }),
            4,
        );
        tokio::spawn(async move {
            let _ = cb_server.serve(true).await;
        });
        (client, cb_client)
    }

    /// Long enough that a leg which did close would have said so.
    const STILL_OPEN: std::time::Duration = std::time::Duration::from_millis(100);

    /// The header naming `cwasm` beside empty metadata, and that metadata encoded.
    fn header_for(cwasm: &[u8]) -> (crate::stream::BundleHeader, Vec<u8>) {
        use fleet_stream::BlobHeader;

        let mut meta = Vec::new();
        ciborium::into_writer(
            &crate::bundle::BundleMeta {
                embedded_imports: Vec::new(),
                catalogs: Vec::new(),
            },
            &mut meta,
        )
        .unwrap();
        let header = crate::stream::BundleHeader {
            cwasm: BlobHeader::of(cwasm).unwrap(),
            meta: BlobHeader::of(&meta).unwrap(),
        };
        (header, meta)
    }

    /// A bundle stream that does not arrive whole fails ITS round — and only that.
    /// The leg under it is not the request channel remoc closes for good on an
    /// oversized item: the next call on the same client is served.
    #[tokio::test]
    async fn a_truncated_bundle_fails_its_own_round_and_the_leg_serves_the_next() {
        use fleet_stream::bin;

        let (client, cb) = serve_mock::<ExecCli>().await;
        let full = vec![0x5Au8; 100_000];
        let (header, meta) = header_for(&full);

        // Ends one byte short.
        let (cwasm_tx, cwasm_rx) = bin::channel();
        let (meta_tx, meta_rx) = bin::channel();
        let stream = BundleStream {
            header,
            cwasm: cwasm_rx,
            meta: meta_rx,
        };
        let short = full[..full.len() - 1].to_vec();
        let (reply, _) = tokio::join!(
            client.run_with_bundle(a_request(), stream, cb.clone()),
            async {
                tokio::join!(
                    fleet_stream::send(cwasm_tx, short),
                    fleet_stream::send(meta_tx, meta.clone())
                )
            }
        );
        assert!(matches!(reply, Err(ExecError::Unknown)));

        // Abandoned part-way: the sender goes away with its message unfinished.
        let (cwasm_tx, cwasm_rx) = bin::channel();
        let (meta_tx, meta_rx) = bin::channel();
        let stream = BundleStream {
            header,
            cwasm: cwasm_rx,
            meta: meta_rx,
        };
        let (reply, _) = tokio::join!(
            client.run_with_bundle(a_request(), stream, cb.clone()),
            async {
                tokio::join!(
                    async {
                        let mut raw = cwasm_tx.into_inner().await.unwrap();
                        let part = raw
                            .send_chunks()
                            .send(full[..1000].to_vec().into())
                            .await
                            .unwrap();
                        drop(part);
                        drop(raw);
                    },
                    fleet_stream::send(meta_tx, meta.clone())
                )
            }
        );
        assert!(matches!(reply, Err(ExecError::Unknown)));

        assert!(
            tokio::time::timeout(STILL_OPEN, remoc::rtc::Client::closed(&client))
                .await
                .is_err(),
            "a failed stream closed the leg's request channel"
        );
        assert!(matches!(
            client.run(a_request(), cb).await,
            Ok(RunOutcome::CacheMiss { .. })
        ));
    }

    /// Sets its flag when dropped, however the future that held it ended.
    struct DropFlag(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A worker whose install says when it began and when it was let go. It does
    /// what the real one does before anything runs: reads the bundle.
    struct WatchedExecutor {
        started: tokio::sync::Notify,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ExecutorService for WatchedExecutor {
        async fn run(
            &self,
            req: RunRequest,
            callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunOutcome, ExecError> {
            MockExecutor.run(req, callbacks).await
        }

        async fn run_with_bundle(
            &self,
            _req: RunRequest,
            bundle: BundleStream,
            _callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunReply, ExecError> {
            let _held = DropFlag(self.dropped.clone());
            self.started.notify_one();
            bundle
                .receive(
                    &mut Vec::new(),
                    crate::DEFAULT_BUNDLE_STREAM_DEADLINE,
                    crate::DEFAULT_BUNDLE_STREAM_IDLE,
                )
                .await
                .map_err(|_| ExecError::Unknown)?;
            Err(ExecError::Unknown)
        }
    }

    /// A caller that goes away mid-stream takes the install with it: the worker
    /// drops the handler, and with it whatever the install holds, though the
    /// stream never failed and its idle deadline is far off. The leg serves the
    /// next call. What a worker's install permit rests on.
    #[tokio::test]
    async fn a_caller_gone_mid_stream_ends_the_install() {
        use fleet_stream::bin;
        use std::sync::atomic::{AtomicBool, Ordering};

        let worker = Arc::new(WatchedExecutor {
            started: tokio::sync::Notify::new(),
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let (client, cb) = serve::<ExecCli, _>(worker.clone()).await;
        let full = vec![0x5Au8; 100_000];
        let (header, meta) = header_for(&full);
        let (cwasm_tx, cwasm_rx) = bin::channel();
        let (meta_tx, meta_rx) = bin::channel();
        let stream = BundleStream {
            header,
            cwasm: cwasm_rx,
            meta: meta_rx,
        };

        // Part of the cwasm, then neither finished nor dropped: nothing but the
        // caller's going away can end the worker's read.
        let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            let cwasm = async {
                let Ok(mut raw) = cwasm_tx.into_inner().await else {
                    return;
                };
                let Ok(_part) = raw.send_chunks().send(full[..1000].to_vec().into()).await else {
                    return;
                };
                let _ = sent_tx.send(());
                std::future::pending::<()>().await;
            };
            let _ = tokio::join!(cwasm, fleet_stream::send(meta_tx, meta));
        });

        let call = client.run_with_bundle(a_request(), stream, cb.clone());
        tokio::select! {
            _ = call => panic!("a stream held open let its round finish"),
            () = async {
                worker.started.notified().await;
                sent_rx.await.expect("part of the cwasm was sent");
            } => {}
        }
        // The call went with the select, and nothing else has run since.
        assert!(
            !worker.dropped.load(Ordering::SeqCst),
            "the install ended before its caller did"
        );

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !worker.dropped.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the worker kept the install after its caller was gone");
        writer.abort();
        assert!(matches!(
            client.run(a_request(), cb).await,
            Ok(RunOutcome::CacheMiss { .. })
        ));
    }

    /// The same contract with no bound on the header's lengths, so a test can
    /// send what [`BundleStream`] will not encode. The wire form is derived from
    /// the method names and argument shapes, so its client speaks to the real
    /// server.
    mod loose {
        use super::{CallbackServiceClient, Ciborium, ExecError, RunOutcome, RunReply, RunRequest};
        use fleet_stream::bin;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        pub struct LooseBlob {
            pub len: u64,
            pub sha256: [u8; 32],
        }
        #[derive(Serialize, Deserialize)]
        pub struct LooseHeader {
            pub cwasm: LooseBlob,
            pub meta: LooseBlob,
        }
        #[derive(Serialize, Deserialize)]
        pub struct LooseStream {
            pub header: LooseHeader,
            pub cwasm: bin::Receiver,
            pub meta: bin::Receiver,
        }

        #[remoc::rtc::remote]
        pub trait ExecutorService {
            async fn run(
                &self,
                req: RunRequest,
                callbacks: CallbackServiceClient<Ciborium>,
            ) -> Result<RunOutcome, ExecError>;

            async fn run_with_bundle(
                &self,
                req: RunRequest,
                bundle: LooseStream,
                callbacks: CallbackServiceClient<Ciborium>,
            ) -> Result<RunReply, ExecError>;
        }
    }

    /// A header claiming more than the hop accepts is refused where it is
    /// decoded, before a byte of its stream is read — and a request that does not
    /// decode fails that call, not the leg.
    #[tokio::test]
    async fn a_header_past_its_bound_fails_its_call_and_not_the_leg() {
        use fleet_stream::bin;
        use loose::{ExecutorService as _, LooseBlob, LooseHeader, LooseStream};

        let (client, cb) = serve_mock::<loose::ExecutorServiceClient<Ciborium>>().await;
        let (cwasm_tx, cwasm_rx) = bin::channel();
        let (meta_tx, meta_rx) = bin::channel();
        let stream = LooseStream {
            header: LooseHeader {
                cwasm: LooseBlob {
                    len: crate::MAX_CWASM_BYTES + 1,
                    sha256: [0; 32],
                },
                meta: LooseBlob {
                    len: 0,
                    sha256: [0; 32],
                },
            },
            cwasm: cwasm_rx,
            meta: meta_rx,
        };
        let (reply, (cwasm_sent, _)) =
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                tokio::join!(
                    client.run_with_bundle(a_request(), stream, cb.clone()),
                    async {
                        tokio::join!(
                            fleet_stream::send(cwasm_tx, vec![0u8; 16]),
                            fleet_stream::send(meta_tx, Vec::new())
                        )
                    }
                )
            })
            .await
            .expect("a refused call and its writer both end");
        assert!(matches!(reply, Err(ExecError::Unknown)));
        assert!(
            cwasm_sent.is_err(),
            "nobody read the stream, so it cannot have been sent"
        );

        assert!(
            tokio::time::timeout(STILL_OPEN, remoc::rtc::Client::closed(&client))
                .await
                .is_err(),
            "a request that did not decode closed the leg's request channel"
        );
        assert!(matches!(
            client.run(a_request(), cb).await,
            Ok(RunOutcome::CacheMiss { .. })
        ));
    }
}

/// What a `RunRequest` decoder refuses.
///
/// Every one of these is a value some peer could put on the wire, and every one
/// of them is what a serving role's discharge NAMES. A cap nobody tests is a
/// sentence in a doc comment.
#[cfg(test)]
mod request_bound_tests {
    use super::*;
    use engine_types::limits::{MAX_PROPS, MAX_PROPS_BYTES};
    use hatch_client::{Clip, MAX_CLIP_FRAMES, MediaResult};
    use serde::Serialize;

    /// A stand-in with the same field names and no bounds, so a test can put on
    /// the wire what the real type will not produce.
    #[derive(Serialize)]
    struct LooseRequest<'a> {
        composition_key: &'a str,
        props: &'a [(String, Prop)],
        session_state: Padded<SessionState>,
        event: Event,
    }

    fn frame() -> Padded<SessionState> {
        Padded::seal(&SessionState::default()).expect("the default state fits its frame")
    }

    fn decode(req: &LooseRequest<'_>) -> Result<RunRequest, ()> {
        let mut b = Vec::new();
        ciborium::into_writer(req, &mut b).expect("the loose shape encodes");
        ciborium::from_reader(&b[..]).map_err(|_| ())
    }

    fn loose<'a>(key: &'a str, props: &'a [(String, Prop)], event: Event) -> LooseRequest<'a> {
        LooseRequest {
            composition_key: key,
            props,
            session_state: frame(),
            event,
        }
    }

    fn a_key() -> String {
        CompositionKey::from_digest([0x5A; 32]).as_str().to_string()
    }

    #[test]
    fn the_ordinary_round_decodes() {
        let key = a_key();
        let props = [("age".to_string(), Prop::Int(30))];
        let req = decode(&loose(&key, &props, Event::Start)).expect("a legal round decodes");
        assert_eq!(req.composition_key.as_str(), key);
        assert_eq!(req.props.len(), 1);
    }

    #[test]
    fn a_key_that_is_not_a_digest_rendering_is_refused() {
        let props: [(String, Prop); 0] = [];
        assert!(decode(&loose("whatever-i-like", &props, Event::Start)).is_err());
    }

    #[test]
    fn more_props_than_the_config_can_yield_are_refused() {
        let props: Vec<(String, Prop)> = (0..=MAX_PROPS)
            .map(|i| (format!("k{i}"), Prop::Null))
            .collect();
        assert!(decode(&loose(&a_key(), &props, Event::Start)).is_err());
    }

    /// Few entries, each enormous — the shape a count bound alone would admit.
    #[test]
    fn props_over_the_byte_bound_are_refused() {
        let props = vec![
            (
                "k".to_string(),
                Prop::String("x".repeat(MAX_PROPS_BYTES / 2)),
            ),
            (
                "k".to_string(),
                Prop::String("x".repeat(MAX_PROPS_BYTES / 2)),
            ),
            (
                "k".to_string(),
                Prop::String("x".repeat(MAX_PROPS_BYTES / 2)),
            ),
        ];
        assert!(decode(&loose(&a_key(), &props, Event::Start)).is_err());
    }

    /// The event's frames are bounded by their own type, and the request decoder
    /// inherits that rather than restating it.
    #[test]
    fn an_event_over_the_capture_bound_is_refused() {
        let props: [(String, Prop); 0] = [];
        let event = Event::Media(MediaResult {
            slot: 0,
            clip: Clip {
                frames: vec![vec![1u8]; MAX_CLIP_FRAMES + 1],
            },
        });
        assert!(decode(&loose(&a_key(), &props, event)).is_err());
    }

    /// Version skew fails closed rather than running a round on a request this
    /// build only partly understood.
    #[test]
    fn an_unknown_field_is_refused() {
        #[derive(Serialize)]
        struct Plus<'a> {
            composition_key: &'a str,
            props: &'a [(String, Prop)],
            session_state: Padded<SessionState>,
            event: Event,
            future_field: u32,
        }
        let key = a_key();
        let props: [(String, Prop); 0] = [];
        let mut b = Vec::new();
        ciborium::into_writer(
            &Plus {
                composition_key: &key,
                props: &props,
                session_state: frame(),
                event: Event::Start,
                future_field: 1,
            },
            &mut b,
        )
        .expect("the loose shape encodes");
        assert!(ciborium::from_reader::<RunRequest, _>(&b[..]).is_err());
    }
}

/// What the two-value shape refuses.
#[cfg(test)]
mod exec_error_tests {
    use super::*;
    use serde::Serialize;

    /// Stand-ins for shapes this contract deliberately does not have, so a test
    /// can put them on the wire and watch them be refused.
    #[derive(Serialize)]
    enum LooseError {
        /// The variant that carried a key. It went away because wasm picks that
        /// string and it could be a function of the applicant's data.
        UndeclaredRef { kind: String, key: String },
        /// A variant from a build this one does not know.
        SomethingNewer(u32),
    }

    fn encode<T: Serialize>(v: &T) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).expect("the value encodes");
        b
    }

    #[test]
    fn every_value_round_trips() {
        for e in [ExecError::Policy, ExecError::Unknown, ExecError::Busy] {
            assert_eq!(
                ciborium::from_reader::<ExecError, _>(&encode(&e)[..]).unwrap(),
                e
            );
        }
    }

    /// THE property the shape exists for. Every failure encodes to one of three
    /// fixed sizes, one of which no policy can reach, so what a policy can make a
    /// host count is still one bit.
    #[test]
    fn a_failure_reply_has_no_length_a_policy_can_set() {
        let sizes: Vec<usize> = [ExecError::Policy, ExecError::Unknown, ExecError::Busy]
            .iter()
            .map(|e| encode(e).len())
            .collect();
        assert!(
            sizes.iter().all(|&n| n < 16),
            "a failure encoded to {sizes:?} bytes — something carries a payload"
        );
    }

    /// A peer sending the shape that was removed is refused. `UndeclaredRef` is no
    /// longer a VARIANT at all, so serde's externally-tagged representation refuses
    /// it as an unknown one — there is no struct variant left for a stray field to
    /// be dropped from, which is also why this enum carries no
    /// `deny_unknown_fields` (it reaches only struct variants, and would be inert).
    #[test]
    fn the_shape_that_carried_a_key_no_longer_decodes() {
        for key in [
            "consent_reason",
            "<script>alert(1)</script>",
            "x' is not registered '",
        ] {
            let bytes = encode(&LooseError::UndeclaredRef {
                kind: "localized".to_string(),
                key: key.to_string(),
            });
            assert!(
                ciborium::from_reader::<ExecError, _>(&bytes[..]).is_err(),
                "a reply carrying {key:?} decoded"
            );
        }
    }

    /// Version skew fails closed — serde's externally-tagged representation is
    /// what refuses an unknown variant.
    #[test]
    fn an_unknown_variant_is_refused() {
        let bytes = encode(&LooseError::SomethingNewer(1));
        assert!(ciborium::from_reader::<ExecError, _>(&bytes[..]).is_err());
    }
}
