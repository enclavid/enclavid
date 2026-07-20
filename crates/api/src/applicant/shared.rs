//! Shared helpers and ambient TEE-side secrets used by the applicant
//! handlers. Keep tightly scoped — anything reused by multiple handlers
//! belongs here, anything used by exactly one belongs in that handler's
//! own file.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use axum::extract::{FromRequestParts, Path};
use axum::http::StatusCode;
use axum::http::request::Parts;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use hatch_client::{
    AuthN, AuthZ, Client, Event, Key, Metadata, PluginPin, Replay, SessionMetadata, SessionState,
    State as StateField, public_session_id, reason,
};
use engine_types::composition::PluginInstance;
// The run wire mirrors: props api builds + ships, the outcome + error it gets
// back from the execution-worker.
use engine_rpc::{CompiledBundle, ExecError, Prop, RunStatus};

use crate::cwasm_cache;
use crate::error::ApiError;
use crate::input::parse_input;
use crate::locale::Locale;
use crate::policy_pull;

use crate::state::AppState;

use super::auth::CallerKey;
use super::callbacks::CallbackServer;
use super::media_store::HatchMediaStore;
use super::persister::SessionPersister;
use super::views::{progress_from, SessionProgress};

pub(super) async fn fetch_metadata(
    state: &AppState,
    session_id: &str,
) -> Result<SessionMetadata, StatusCode> {
    // Applicant flow has no per-session info to cross-check metadata
    // against — security relies on the bearer-key auth layer plus
    // AEAD-sealed metadata (`tee_seal_key`, AAD=session_id) so any
    // host-side tampering breaks the seal at unwrap time. We accept
    // the host's existence claim and content at face value here; the
    // trust delegation is concentrated in `trust_unchecked` so callers
    // don't have to repeat the analysis.
    let ((metadata,), _version) = state
        .session_store
        .read(public_session_id(session_id), (Metadata,))
        .await
        .map_err(|e| {
            eprintln!(
                "fetch_metadata: session_store.read failed for {session_id}: {e}",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    metadata
        .trust_unchecked::<AuthZ, _>(reason!(r#"
Applicant flow doesn't authenticate per-tenant, so we have
no principal to cross-check here. Security relies on the
bearer-key auth layer at the route plus AEAD-binding on state
under applicant_session_token.
        "#))
        .trust_unchecked::<Replay, _>(reason!(r#"
Applicant flow uses metadata only for engine-resource fields
(client_disclosure_pubkey, policy_digest, input). Their
staleness has no security impact — these fields are stable
across the session lifetime.
        "#))
        .into_inner()
        .ok_or_else(|| {
            eprintln!("fetch_metadata: metadata is None for {session_id}");
            StatusCode::NOT_FOUND
        })
}

/// Build the static `props` list the policy reads via
/// `context.props`, from the consumer's config bytes in metadata.
pub(super) fn parse_props(
    metadata: &SessionMetadata,
) -> Result<Vec<(String, Prop)>, StatusCode> {
    parse_input(&metadata.input).map_err(|e| {
        eprintln!("parse_props: parse_input failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Pre-flight context shared by `/connect` and `/input`. The extractor
/// fetches metadata, reads + integrity-trusts the previously-persisted
/// session state under the caller's bearer key, looks up the compiled
/// policy, and prepares the per-run persister + engine resources.
///
/// Handlers receive a fully-loaded ctx, decide on the inbound
/// [`Event`] (connect: `Event::Start` on a fresh `SessionState`;
/// input: the event matched against the loaded state's
/// `current_prompt`), and dispatch both back via
/// [`SessionRunCtx::run`]. That's where the connect / input flows
/// diverge: connect tolerates a missing state (default-init), input
/// requires it (409) and validates the submitted input against the
/// prompt the session is awaiting.
pub(super) struct SessionRunCtx {
    state: Arc<AppState>,
    pub(super) session_id: String,
    /// State previously persisted under this `applicant_session_token`. `None`
    /// for a session whose `/connect` has never reached this far —
    /// connect treats that as "fresh start", input as 409.
    pub(super) session_state: Option<SessionState>,
    /// Applicant's preferred locale (from `Accept-Language` header).
    /// Text-ref resolution happens server-side so the wire payload is
    /// a plain string per ref — frontend doesn't carry i18n logic.
    locale: Locale,
    /// SOLE strong owner of the applicant token for this round. The persister
    /// and media store hold only `Weak`s to it, so the plaintext token's
    /// lifetime is exactly this context: it drops (and zeroizes) when the run
    /// ends. MUST outlive `executor.run().await` — see [`SessionRunCtx::run`].
    applicant_session_token: Arc<SecretBox<Vec<u8>>>,
    persister: Arc<SessionPersister>,
    /// The per-round media store — becomes the `media_load` half of the
    /// [`CallbackServer`] the keyless worker calls back into. Holds the seal key
    /// + a `Weak` to the applicant token.
    media_store: Arc<HatchMediaStore>,
    props: Vec<(String, Prop)>,
    /// Composition cache key — names the fused component in the execution-worker's
    /// L1 cache, and (with the worker's `compat_token`) keys the orchestrator's
    /// L2. Passed to the worker on the run; echoed back in `load_component`.
    composition_key: String,
    /// This session's metadata — moved into the per-run [`CallbackServer`] so
    /// `load_component` can cold-compile (OCI pull + fuse) on an L2 miss.
    metadata: SessionMetadata,
}

impl SessionRunCtx {
    /// Drive one reducer round: feed `event` against `session_state`
    /// into the policy, persist the returned state (done by the
    /// persister via the engine's `on_session_change` hook), finalize
    /// the session on a terminal decision, and project the result into
    /// the JSON view returned to the applicant. Consumes self —
    /// handlers call it once per request.
    pub(super) async fn run(
        self,
        session_state: SessionState,
        event: Event,
    ) -> Result<SessionProgress, ApiError> {
        let SessionRunCtx {
            state,
            session_id,
            locale,
            // Bound (not dropped into `..`) ON PURPOSE: this is the sole strong
            // ref to the applicant token, and the persister / media store hold
            // only `Weak`s. It MUST stay alive across `executor.run().await`
            // below so their `upgrade()`s succeed while the worker calls back to
            // seal state / open media. Dropping it early makes those upgrades
            // return `None` and the round fails. It drops (and zeroizes) at the
            // end of this fn.
            applicant_session_token: _token_owner,
            persister,
            media_store,
            props,
            composition_key,
            metadata,
            ..
        } = self;
        // The keyless execution-worker calls back into this per-round
        // CallbackService for compiled-bundle resolution (`load_component`), blob
        // rehydration (`media_load`) + state persistence (`session_change`); it
        // holds the seal key + the token weak + the L2/compile context, so none
        // of those ever cross to the worker.
        let callbacks = Arc::new(CallbackServer {
            persister: persister.clone(),
            media_store,
            state: state.clone(),
            metadata,
            session_id: session_id.clone(),
        });
        let status = state
            .executor
            .run(&composition_key, session_state, event, props, callbacks)
            .await
            .map_err(|e| classify_run_error(&session_id, &e))?;
        // No-op while the run is still awaiting input; flips status to
        // Completed atomically (metadata + host-plaintext Status) when
        // the run terminated.
        persister.finalize(&status).await?;
        // On a terminal decision, drop this session's pull-through media cache
        // — the captures aren't needed post-completion (the consumer never
        // reads the media store; disclosures are a separate age-sealed channel).
        if matches!(status, RunStatus::Completed(_)) {
            state.media_cache.purge(&session_id).await;
        }
        Ok(progress_from(status, &locale))
    }
}

/// Classify the [`ExecError`] coming back from `executor.run` into an HTTP-facing
/// status. Two kinds:
///
///   * [`ExecError::Config`] — a config-resolution failure relayed from the
///     worker's `load_component` (OCI pull / compile / digest). It is a pure
///     function of the pinned config (no applicant input, no PII), so its HTTP
///     `status` is surfaced VERBATIM — e.g. 410 GONE on a removed artifact — not
///     flattened to 500. This is the fidelity the typed error channel preserves.
///   * [`ExecError::Run`] — an opaque trap / host-fn / transport failure → 500,
///     with ONE well-known exception worth a structured 422:
///     * Unregistered text-ref — policy pushed without the matching
///       `manifest.json` layer. Detected by substring against the engine's
///       `ensure_registered` message (`"... text-ref '<key>' is not registered
///       ..."`), which the worker relayed verbatim. Fragile by nature; if the
///       engine rewords the trap this degrades silently to 500 — an accepted
///       trade-off against typed-error plumbing all the way through the wasm trap.
fn classify_run_error(session_id: &str, e: &ExecError) -> ApiError {
    match e {
        ExecError::Config { status, message } => {
            eprintln!("session_run_ctx: config resolution failed for {session_id}: {message}");
            ApiError::Status(
                StatusCode::from_u16(*status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            )
        }
        ExecError::Run(chain) => {
            eprintln!("session_run_ctx: executor.run failed for {session_id}: {chain}");
            if let Some(missing) = extract_unregistered_text_ref(chain) {
                return ApiError::with_body(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    serde_json::json!({
                        "error": "policy_uses_unregistered_text_ref",
                        "missing": missing,
                        "hint": "policy references a text-ref that isn't declared in its \
                                 manifest. Ensure `manifest.json` lists the ref under \
                                 `disclosure_fields` or `localized`, and that the manifest \
                                 was pushed (run `enclavid policy push` with `manifest.json` \
                                 next to the artifact, or `--manifest <path>`).",
                    }),
                );
            }
            ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Pull `<key>` out of an `... text-ref '<key>' is not registered ...`
/// message embedded anywhere in the error chain. Walks the marker
/// substring; isolates the most-recent `'<key>'` pair preceding it.
/// Returns None when the marker isn't present — caller falls back to
/// generic 500.
fn extract_unregistered_text_ref(msg: &str) -> Option<String> {
    let marker_pos = msg.find("is not registered")?;
    let prefix = &msg[..marker_pos];
    let close = prefix.rfind('\'')?;
    let before = &prefix[..close];
    let open = before.rfind('\'')?;
    Some(prefix[open + 1..close].to_string())
}

impl FromRequestParts<Arc<AppState>> for SessionRunCtx {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Variable-shape routes — extract path params as a map and
        // pull the `id` key. Lets the same extractor work for
        // /connect (`{id}` only) and /input/{slot_id} alike without
        // committing to a per-route Path tuple shape here.
        let Path(params) =
            Path::<HashMap<String, String>>::from_request_parts(parts, state)
                .await
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        let session_id = params
            .get("id")
            .cloned()
            .ok_or(StatusCode::BAD_REQUEST)?;
        let CallerKey(applicant_session_token) =
            CallerKey::from_request_parts(parts, state).await?;
        // Applicant locale from `Accept-Language` — captured once per
        // request and threaded through view construction so every
        // text-ref resolves to the user's preferred language.
        let locale = Locale::from_request_parts(parts, state).await?;

        let metadata = fetch_metadata(state, &session_id).await?;
        let props = parse_props(&metadata)?;

        // Existence claim is host-controlled; content of Some is
        // AEAD-integrity-verified at decode (AuthN cleared, AuthZ
        // implicit by holding the right applicant_session_token). The version
        // seeds the persister's per-call writes within this run.
        let ((state_opt,), version) = state
            .session_store
            .read(
                public_session_id(&session_id),
                (StateField {
                    applicant_session_token: applicant_session_token.expose_secret(),
                },),
            )
            .await
            .map_err(|e| {
                // A state blob that won't open under this bearer is a wrong key /
                // different-device claim (the inner AEAD layer is keyed by the
                // applicant token) — the durable, cryptographic first-claim guard.
                // Surface it as 403 so the frontend offers `/reset`; everything
                // else (transport, codec) is a real 500. An ABSENT state is
                // `Ok(None)`, not an error, so a first `/connect` still proceeds.
                if matches!(e, hatch_client::BridgeError::Crypto(_)) {
                    return StatusCode::FORBIDDEN;
                }
                eprintln!(
                    "session_run_ctx: session_store.read(State) failed for {session_id}: {e}",
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let session_state = state_opt
            .trust_unchecked::<Replay, _>(reason!(r#"
Stale state is bounded by per-call version-CAS during the run.
The first write on a stale snapshot fails with VersionMismatch
and the run aborts cleanly — replay from the latest persisted
state on retry.
            "#))
            .into_inner();

        let version = version
            .trust_unchecked::<AuthN, _>(reason!(r#"
Version is a CAS token only. A lying host either fails our
writes (DoS) or stomps a concurrent winner (UX regression). No
data leak path.
            "#))
            .trust_unchecked::<AuthZ, _>(reason!(r#"
Version counter is not an ownership signal — fed back as
expected_version on the next write, no access decision hangs on it.
            "#))
            .trust_unchecked::<Replay, _>(reason!(r#"
Staleness on the version manifests as CAS mismatch on first
persist; same containment as above.
            "#))
            .into_inner();

        // Compute the composition cache key — names the fused component in the
        // worker's L1 and keys the orchestrator's L2. The pull + compile is LAZY:
        // driven by the worker's `load_component` callback into `resolve_bundle`
        // on an L1 miss, so nothing is compiled on the extractor path.
        let composition_key = session_composition_key(&session_id, &metadata)?;

        // Per-run persister: the worker calls `session_change` once per
        // reducer round, persister seals any consented disclosure to
        // the client recipient pubkey then writes (SetState +
        // AppendDisclosures) in one atomic SessionStore.write.
        // Concurrent /input or /connect for the same
        // session bumps the version past us; our next write fails
        // with VersionMismatch and the run aborts cleanly — replay
        // from latest persisted state on retry.
        let disclosure_pubkey = metadata
            .client
            .as_ref()
            .map(|c| c.disclosure_pubkey.clone())
            .ok_or_else(|| {
                eprintln!(
                    "session_run_ctx: metadata.client missing for {session_id}",
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        let persister = Arc::new(SessionPersister {
            session_store: state.session_store.clone(),
            session_id: session_id.clone(),
            // Weak: the strong lives in the SessionRunCtx below (sole owner).
            applicant_session_token: Arc::downgrade(&applicant_session_token),
            client_disclosure_pubkey: disclosure_pubkey,
            current_version: AtomicU64::new(version),
            metadata: Mutex::new(metadata.clone()),
            shuffle_key: state.shuffle_key.clone(),
        });
        // The live host blob store: the worker's `blob::from-blob-ref` reads
        // sealed captures back through this (via the `media_load` callback) — a
        // pull-through cache over the hatch backing, gated by the session's
        // captured-hash set (from sealed metadata, prior rounds) so a fabricated
        // ref is refused without a hatch read. Same session keys as the
        // persister that WROTE them.
        let captured: HashSet<[u8; 32]> = metadata
            .captured_media
            .iter()
            .filter_map(|h| <[u8; 32]>::try_from(h.as_slice()).ok())
            .collect();
        let media_store = Arc::new(HatchMediaStore {
            session_store: state.session_store.clone(),
            session_id: session_id.clone(),
            // Weak: the strong lives in the SessionRunCtx below (sole owner).
            applicant_session_token: Arc::downgrade(&applicant_session_token),
            cache: state.media_cache.clone(),
            captured,
        });

        Ok(SessionRunCtx {
            state: state.clone(),
            session_id,
            session_state,
            locale,
            // Move the sole strong ref in — the persister / media store above
            // hold only `Weak`s downgraded from it.
            applicant_session_token,
            persister,
            media_store,
            props,
            composition_key,
            metadata,
        })
    }
}

/// Compute the composition cache key for a session — `sha256(policy_ref ‖
/// ordered plugin pins ‖ access authority)`. It is a pure function of the pinned
/// artifacts (nothing session-specific), so it (a) names the fused component in
/// the execution-worker's L1 cache — every session pinning the same policy +
/// plugins shares ONE compile — and (b) keys the orchestrator's L2 (paired with
/// the worker's `compat_token`). NO pull or compile happens here; that is lazy,
/// driven by [`resolve_bundle`] when the worker's `load_component` callback fires
/// on an L1 miss.
fn session_composition_key(
    session_id: &str,
    metadata: &SessionMetadata,
) -> Result<String, StatusCode> {
    let client = metadata.client.as_ref().ok_or_else(|| {
        eprintln!("session_composition_key: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(composition_key(
        &metadata.policy_ref,
        metadata.policy_key.as_ref(),
        &client.registry_auth,
        &client.plugins,
    ))
}

/// Resolve the compiled bundle for `(composition_key, compat_token)` — the api
/// side of the worker's `load_component` pull. L2 hit → return the (unsealed)
/// bundle; L2 miss → cold-compile (OCI pull + compile-worker), store to L2
/// (best-effort), return. This is the ONE place a compile is now triggered — the
/// orchestrator holds no in-memory component cache, so it recomputes from L2 (or
/// compiles) each time the worker's L1 misses. Coalescing of concurrent misses
/// happens on the WORKER side (its L1 `try_get_with`); a cross-worker race just
/// re-reads L2 or double-compiles (idempotent write), acceptable and rare.
pub(super) async fn resolve_bundle(
    state: &AppState,
    composition_key: &str,
    compat_token: &str,
    session_id: &str,
    metadata: &SessionMetadata,
) -> Result<CompiledBundle, StatusCode> {
    if let Some(bundle) =
        cwasm_cache::try_load(&state.cache_store, composition_key, compat_token).await
    {
        return Ok(bundle);
    }
    let client = metadata.client.as_ref().ok_or_else(|| {
        eprintln!("resolve_bundle: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let bundle = cold_compile(state, session_id, metadata, client).await?;
    cwasm_cache::store(&state.cache_store, composition_key, compat_token, &bundle).await;
    Ok(bundle)
}

/// Cold path: pull the policy + pinned plugins (the orchestrator owns OCI +
/// registry auth), then hand the bytes to the [`Compiler`](crate::compiler::Compiler)
/// boundary, which fuses + compiles + parses sections into a [`CompiledBundle`].
/// Runs only on an L2 miss — [`resolve_bundle`] calls this, then stores the
/// result to L2. The bundle then flows back to the worker via `load_component`.
///
/// Errors map to HTTP-ish statuses (now surfaced by the worker as a run failure
/// via `load_component` → `ExecError`, which `classify_run_error` maps):
///   * 410 Gone — registry pull / decrypt failed (artifact removed / malformed)
///   * 5xx — composition / infra problems
async fn cold_compile(
    state: &AppState,
    session_id: &str,
    metadata: &SessionMetadata,
    client: &Client,
) -> Result<CompiledBundle, StatusCode> {
    // Look up the bearer for the policy registry by hostname. Same
    // lookup applies per plugin below. Missing entry collapses to an
    // empty slice ⇒ anonymous pull (host attaches no Authorization
    // header).
    let policy_bearer =
        policy_pull::bearer_for_ref(&client.registry_auth, &metadata.policy_ref);

    // Context for the `kbs` key path: the hatch relay client that
    // couriers each RCAR leg. Shared by the policy and every plugin pull;
    // inline / plaintext artifacts ignore it.
    let kbs_ctx = crate::keyprovider::KbsContext { kbs: &state.kbs };

    // Run the policy pull and every plugin pull concurrently so the
    // /connect critical path is bounded by the slowest fetch instead
    // of paying linear network latency. Each future is independent
    // and only the final outputs feed `Runner::run`.
    let policy_fut = policy_pull::pull_policy(
        &state.registry,
        &metadata.policy_ref,
        policy_bearer,
        metadata.policy_key.as_ref(),
        Some(&kbs_ctx),
    );

    let plugin_futs = client.plugins.iter().map(|pin| {
        let bearer = policy_pull::bearer_for_ref(&client.registry_auth, &pin.impl_ref);
        let registry = &state.registry;
        let kbs_ctx = &kbs_ctx;
        async move {
            policy_pull::pull_plugin(registry, &pin.impl_ref, bearer, pin.key.as_ref(), Some(kbs_ctx))
                .await
                .map(|art| (pin.package.clone(), art))
        }
    });
    let (policy_res, plugin_results) =
        futures::future::join(policy_fut, futures::future::join_all(plugin_futs)).await;

    let artifact = policy_res.map_err(|e| {
        eprintln!(
            "lookup_policy: pull_and_decrypt failed for session {session_id} \
             (policy_ref={}): {e}",
            metadata.policy_ref,
        );
        StatusCode::GONE
    })?;

    let mut plugin_instances: Vec<PluginInstance> = Vec::with_capacity(plugin_results.len());
    for res in plugin_results {
        let (package, art) = res.map_err(|e| {
            eprintln!(
                "lookup_policy: pull_plugin failed for session {session_id}: {e}",
            );
            StatusCode::GONE
        })?;
        // Keep the raw component bytes — the compiler fuses on bytes, not a
        // pre-compiled `Component`, and parses each plugin's embedded catalog
        // itself (content-hash keyed, so strict per-component resolution lines
        // up). The compile-worker does this in `Compiler::compile_to_parts`.
        plugin_instances.push(PluginInstance {
            package,
            wasm: art.wasm_bytes,
        });
    }

    // Hand the pulled bytes to the COMPILE boundary: the compile-worker fuses +
    // compiles + parses sections into a `CompiledBundle` (cwasm + i18n/icons
    // import manifest + per-component catalogs, composition order) over rpc.
    // `PolicyCache::get_or_compute` persists the bundle to L2 and reconstructs
    // the L1 `PolicyEntry` from it.
    state
        .compiler
        .compile(artifact.wasm_bytes, plugin_instances)
        .await
        .map_err(|e| {
            eprintln!(
                "lookup_policy: compile failed for {session_id} (policy_ref {}): {e}",
                metadata.policy_ref,
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// Content-address of a fused composition: each artifact (policy + ORDERED
/// plugins) as `(ref, ACCESS-AUTHORITY)`. The compiled [`PolicyEntry`] (fused
/// `Component` + `EmbeddedRegistry` + import manifest) is a pure function of the
/// pulled-and-decrypted artifact bytes and nothing session-specific, so it is
/// the right cache key — two sessions pinning the same artifacts (and equally
/// authorized to OBTAIN them) share one pull + fuse + Cranelift compile.
///
/// **Access authority is in the key, because a cache HIT bypasses the two gates
/// a MISS goes through** (download, then decrypt) — it hands back the already
/// pulled-and-decrypted component with no credential presented. Keying by
/// artifact identity ALONE would let a consumer who could neither download nor
/// decrypt an artifact obtain its compiled form via another consumer's entry. So
/// per artifact we mix in BOTH gates:
///   * **Download authority** — the per-hostname OCI bearer
///     ([`policy_pull::bearer_for_ref`]). For a third-party LICENSED plugin this
///     IS the license: the author grants pull only to licensed clients. Empty
///     (anonymous / public) → all share; non-empty → `sha256(bearer)` so only
///     credential-holders share and a non-holder misses → pulls → fails closed.
///   * **Decrypt authority** — the [`Key`]: `None` (plaintext) shares; `Inline`
///     (owner secret) mixes `sha256(bytes)`; `Kbs` a marker only. Encryption's
///     job is secrecy from the PLATFORM (KBS releases only to the attested TEE),
///     NOT per-client licensing — that's the download gate above — so `Kbs`
///     needs no per-client credential here. (A future metered/licensed KBS model
///     keeps its license token OUT of this key too: the KBS is consulted EVERY
///     session as the license/metering gate, and a successful response is the
///     precondition to REUSE the cached compile — the cache only ever skips the
///     decrypt+compile, never the per-session license check.)
/// Both secrets are HASHED, never embedded raw (the cache is TEE-only anyway).
///
/// Order matters (fusion order fixes merged first-match), so pins are hashed in
/// `client.plugins` order; every field is length-prefixed against
/// delimiter-collision. wasmtime version is excluded (in-process, one `Runner`
/// engine; a restart empties the cache). Assumes refs are effectively immutable
/// content-addresses (digest-pinned); a consumer pinning a MUTABLE tag could be
/// served a stale compilation within the cache TTL — a freshness tradeoff.
fn composition_key(
    policy_ref: &str,
    policy_key: Option<&Key>,
    registry_auth: &HashMap<String, Vec<u8>>,
    plugins: &[PluginPin],
) -> String {
    let mut h = Sha256::new();
    hash_artifact(
        &mut h,
        policy_ref,
        policy_key,
        policy_pull::bearer_for_ref(registry_auth, policy_ref),
    );
    h.update((plugins.len() as u64).to_le_bytes());
    for p in plugins {
        h.update((p.package.len() as u64).to_le_bytes());
        h.update(p.package.as_bytes());
        hash_artifact(
            &mut h,
            &p.impl_ref,
            p.key.as_ref(),
            policy_pull::bearer_for_ref(registry_auth, &p.impl_ref),
        );
    }
    hex::encode(h.finalize())
}

/// Feed one artifact's `(ref, download authority, decrypt authority)` into the
/// composition hash. See [`composition_key`] for the rationale.
fn hash_artifact(h: &mut Sha256, artifact_ref: &str, key: Option<&Key>, download_cred: &[u8]) {
    h.update((artifact_ref.len() as u64).to_le_bytes());
    h.update(artifact_ref.as_bytes());
    // Download authority: empty (anonymous / public) shares; otherwise partition
    // by sha256(bearer) so only credential-holders share (the license gate for
    // a download-gated third-party artifact).
    if download_cred.is_empty() {
        h.update([0x00u8]);
    } else {
        h.update([0x01u8]);
        let digest = Sha256::digest(download_cred);
        h.update((digest.len() as u64).to_le_bytes());
        h.update(digest);
    }
    // Decrypt authority.
    match key {
        None => h.update([0x00u8]),
        Some(Key::Inline(bytes)) => {
            h.update([0x01u8]);
            let digest = Sha256::digest(bytes);
            h.update((digest.len() as u64).to_le_bytes());
            h.update(digest);
        }
        Some(Key::Kbs(_)) => h.update([0x02u8]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(package: &str, impl_ref: &str) -> PluginPin {
        PluginPin {
            package: package.into(),
            impl_ref: impl_ref.into(),
            key: None,
        }
    }

    /// Empty registry-auth map = anonymous pull for every artifact.
    fn no_auth() -> HashMap<String, Vec<u8>> {
        HashMap::new()
    }

    #[test]
    fn composition_key_deterministic_and_order_sensitive() {
        let plugins = [pin("enclavid:well-known", "reg/wk@sha256:11"), pin("enclavid:face-age", "reg/fa@sha256:22")];
        let key = composition_key("reg/policy@sha256:aa", None, &no_auth(), &plugins);

        // Same composition → same key (the whole point: cross-session sharing).
        assert_eq!(key, composition_key("reg/policy@sha256:aa", None, &no_auth(), &plugins));

        // Plugin ORDER is significant (fusion order fixes merged first-match) →
        // reversing must change the key.
        let reversed = [plugins[1].clone(), plugins[0].clone()];
        assert_ne!(key, composition_key("reg/policy@sha256:aa", None, &no_auth(), &reversed));

        // Different policy ref → different key.
        assert_ne!(key, composition_key("reg/policy@sha256:bb", None, &no_auth(), &plugins));

        // Different plugin set (dropping one) → different key.
        assert_ne!(key, composition_key("reg/policy@sha256:aa", None, &no_auth(), &plugins[..1]));
    }

    #[test]
    fn composition_key_length_prefixed_no_delimiter_collision() {
        // Without length-prefixing, field boundaries could be ambiguous: a
        // policy ref "ab" + package "c" would concat-collide with ref "a" +
        // package "bc". Length-prefixing must keep them distinct.
        let a = composition_key("ab", None, &no_auth(), &[pin("c", "r")]);
        let b = composition_key("a", None, &no_auth(), &[pin("bc", "r")]);
        assert_ne!(a, b);
    }

    #[test]
    fn composition_key_partitions_by_decryption_authority() {
        use hatch_client::{KbsKey, Key};
        let plugins = [pin("p", "r")];
        let none = composition_key("policy", None, &no_auth(), &plugins);
        let inline_a = composition_key("policy", Some(&Key::Inline(vec![1, 2, 3])), &no_auth(), &plugins);
        let inline_b = composition_key("policy", Some(&Key::Inline(vec![9, 9, 9])), &no_auth(), &plugins);

        // Plaintext (None) and encrypted (Inline) are distinct scopes, and two
        // different Inline keys never share — a non-holder can't hit a holder's
        // entry (the whole point: a cache hit must not bypass decrypt auth).
        assert_ne!(none, inline_a);
        assert_ne!(inline_a, inline_b);
        // Same Inline key → same key: key-holders DO share.
        assert_eq!(inline_a, composition_key("policy", Some(&Key::Inline(vec![1, 2, 3])), &no_auth(), &plugins));

        // Kbs is attestation-gated (every TEE session equally authorized), so it
        // does NOT partition by endpoint — that would only reduce sharing.
        let kbs_a = composition_key("policy", Some(&Key::Kbs(KbsKey { endpoint: "a".into() })), &no_auth(), &plugins);
        let kbs_b = composition_key("policy", Some(&Key::Kbs(KbsKey { endpoint: "b".into() })), &no_auth(), &plugins);
        assert_eq!(kbs_a, kbs_b);
    }

    #[test]
    fn composition_key_partitions_by_download_authority() {
        // The OCI download bearer is the license for a download-gated third-party
        // artifact: a cache HIT skips the pull, so a non-holder must not hit a
        // holder's entry.
        let pol = "reg.example.com/policy@sha256:aa";
        let plugins = [pin("p", "reg.example.com/plug@sha256:11")];

        let anon = composition_key(pol, None, &no_auth(), &plugins);

        let mut auth_a = HashMap::new();
        auth_a.insert("reg.example.com".to_string(), b"licensed-A".to_vec());
        let holder_a = composition_key(pol, None, &auth_a, &plugins);
        // A bearer-holder computes a DIFFERENT key than the anonymous non-holder.
        assert_ne!(anon, holder_a);

        // A different bearer → a different scope (different licenses don't share).
        let mut auth_b = HashMap::new();
        auth_b.insert("reg.example.com".to_string(), b"licensed-B".to_vec());
        assert_ne!(holder_a, composition_key(pol, None, &auth_b, &plugins));

        // Same bearer → same key (co-licensed clients share the compile).
        assert_eq!(holder_a, composition_key(pol, None, &auth_a, &plugins));
    }
}
