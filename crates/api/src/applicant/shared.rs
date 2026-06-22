//! Shared helpers and ambient TEE-side secrets used by the applicant
//! handlers. Keep tightly scoped — anything reused by multiple handlers
//! belongs here, anything used by exactly one belongs in that handler's
//! own file.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use axum::extract::{FromRequestParts, Path};
use axum::http::StatusCode;
use axum::http::request::Parts;
use secrecy::ExposeSecret;
use tokio::sync::Mutex;

use enclavid_engine::{
    Component, EmbeddedRegistry, EvalArgs, PluginInstance, RunInputs, SessionListener,
    SessionState,
};
use broker_client::{
    AuthN, AuthZ, Metadata, Replay, SessionMetadata, State as StateField, public_session_id,
    reason,
};

use crate::error::ApiError;
use crate::input::parse_input;
use crate::locale::Locale;
use crate::policy_pull;
use crate::runtime::PolicyEntry;
use crate::state::AppState;

use super::auth::CallerKey;
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

pub(super) fn parse_args(
    metadata: &SessionMetadata,
) -> Result<Vec<(String, EvalArgs)>, StatusCode> {
    parse_input(&metadata.input).map_err(|e| {
        eprintln!("parse_args: parse_input failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Build per-run resources for the engine. Listener: side-effect
/// channel — fires after every committed CallEvent, seals + persists
/// state and disclosures atomically. Embedded registry: composition-
/// wide `EmbeddedRegistry`, constructed once at policy-cache build
/// time (see [`lookup_policy`]) and threaded into both engine (slot-
/// bound resolve + use-site reverse-lookup) and api view-layer (ref →
/// user-facing text) so all consumers agree on slot attribution.
pub(super) fn build_run_inputs(
    listener: Arc<dyn SessionListener>,
    embedded: Arc<EmbeddedRegistry>,
) -> RunInputs {
    RunInputs { listener, embedded }
}

/// Pre-flight context shared by `/connect` and `/input`. The extractor
/// fetches metadata, reads + integrity-trusts the previously-persisted
/// session state under the caller's bearer key, looks up the compiled
/// policy, and prepares the per-run persister + engine resources.
///
/// Handlers receive a fully-loaded ctx and dispatch the (possibly
/// transformed) `SessionState` back via [`SessionRunCtx::run`]. That's
/// where the connect / input flows diverge: connect tolerates a
/// missing state (default-init), input requires it (404), and input
/// also runs `apply_input` over the loaded state before submitting.
pub(super) struct SessionRunCtx {
    state: Arc<AppState>,
    pub(super) session_id: String,
    /// State previously persisted under this `applicant_session_token`. `None`
    /// for a session whose `/connect` has never reached this far —
    /// connect treats that as "fresh start", input as 404.
    pub(super) session_state: Option<SessionState>,
    /// Composition-wide `EmbeddedRegistry`. Handlers project slot-
    /// tagged refs inside suspended requests / consent disclosures
    /// through this when assembling JSON for the frontend or the
    /// consumer SDK; same `Arc` is also threaded into the engine
    /// via `RunInputs`.
    pub(super) embedded: Arc<EmbeddedRegistry>,
    /// Applicant's preferred locale (from `Accept-Language` header).
    /// Text-ref resolution happens server-side so the wire payload is
    /// a plain string per ref — frontend doesn't carry i18n logic.
    locale: Locale,
    persister: Arc<SessionPersister>,
    args: Vec<(String, EvalArgs)>,
    policy: Arc<Component>,
    /// Plugin components the policy depends on, pinned at session
    /// create and compiled on first /connect (see
    /// [`lookup_policy`]). Shared by Arc with the cache entry — the
    /// list itself is immutable for the session's lifetime.
    plugins: Arc<Vec<PluginInstance>>,
    run_inputs: RunInputs,
}

impl SessionRunCtx {
    /// Run the policy with the provided session state, finalize the
    /// persister, and project the result into the JSON view returned
    /// to the applicant. Consumes self — handlers call it once per
    /// request.
    pub(super) async fn run(
        self,
        session_state: SessionState,
    ) -> Result<SessionProgress, ApiError> {
        let SessionRunCtx {
            state,
            session_id,
            embedded,
            locale,
            persister,
            args,
            policy,
            plugins,
            run_inputs,
            ..
        } = self;
        let (status, _session_state) = state
            .runner
            .run(&policy, &plugins, session_state, args, run_inputs)
            .await
            .map_err(|e| classify_run_error(&session_id, &e))?;
        // No-op for Suspended; flips status to Completed atomically
        // (metadata + host-plaintext Status) when the run terminated.
        persister.finalize(&status).await?;
        Ok(progress_from(status, &embedded, &locale))
    }
}

/// Inspect a wasmtime/anyhow chain coming out of `runner.run`. Most
/// failures are opaque to the API consumer — surface as 500. Two
/// classes are well-known and worth turning into structured 422s:
///
///   * Unregistered text-ref — policy was pushed without the matching
///     `manifest.json` manifest layer (or the manifest doesn't declare
///     a ref the policy uses). Surface as 422 + missing-ref key, so
///     frontend can show "policy X needs manifest entry Y" instead
///     of a blank "internal error".
///
/// The detection is substring-based against the engine's
/// `ensure_registered` message format ([`engine::sanitize`] →
/// `"... text-ref '<key>' is not registered in prepare-localized-texts"`).
/// Fragile by nature — if engine rewords the trap, this detection
/// degrades silently to 500. Acceptable trade-off given the
/// alternative (typed error all the way through wasmtime trap →
/// host fn → engine → applicant) is significantly more code.
fn classify_run_error(session_id: &str, e: &enclavid_engine::RunError) -> ApiError {
    // `{e:#}` walks the anyhow chain — without this we only see the
    // top-level "wasm error / trap" line and miss the underlying
    // `ensure_registered` message buried below the wasm backtrace.
    let chain = format!("{e:#}");
    eprintln!("session_run_ctx: runner.run failed for {session_id}: {chain}");
    if let Some(missing) = extract_unregistered_text_ref(&chain) {
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
        let args = parse_args(&metadata)?;

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

        // Resolve the policy and its registered text constants
        // before the persister is built — the persister consults the
        // embedded registry to project slot-tagged disclosure-field-
        // refs back to their machine identifiers when sealing the
        // envelope to the consumer SDK.
        let policy_entry = lookup_policy(state, &session_id, &metadata).await?;
        // PolicyEntry is reference-counted in the cache; cheap to
        // unpack its inner Arcs into per-run fields.
        let policy = policy_entry.component.clone();
        let embedded = policy_entry.embedded.clone();
        let plugins = policy_entry.plugins.clone();

        // Per-run persister: engine fires `on_session_change` after
        // each committed CallEvent, persister seals disclosures to
        // the client recipient pubkey then writes (SetState +
        // AppendDisclosures) in one atomic SessionStore.write per
        // host call. Concurrent /input or /connect for the same
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
            applicant_session_token: applicant_session_token.expose_secret().to_vec(),
            client_disclosure_pubkey: disclosure_pubkey,
            current_version: AtomicU64::new(version),
            metadata: Mutex::new(metadata.clone()),
            embedded: embedded.clone(),
            shuffle_key: state.shuffle_key.clone(),
        });
        // Engine takes one strong ref via the listener; we keep our
        // own so `finalize` lands on the same persister after the run
        // completes (engine drops its ref when Store is consumed).
        let run_inputs = build_run_inputs(persister.clone(), embedded.clone());

        Ok(SessionRunCtx {
            state: state.clone(),
            session_id,
            session_state,
            embedded,
            locale,
            persister,
            args,
            policy,
            plugins,
            run_inputs,
        })
    }
}

/// Look up the compiled policy for a session, compiling lazily on
/// cache miss. The first /connect for a session pays the
/// pull+compile cost; subsequent calls and /input rounds hit the
/// cache.
///
/// On cache miss the policy artifact is pulled from the registry by
/// the pinned ref baked into metadata and compiled into a
/// `Component`.
///
/// Errors map to HTTP statuses the handler can pass through directly:
///   * 410 Gone — registry pull / compile failed (artifact has been
///     removed or is malformed)
///   * 5xx — transport / infra problems
async fn lookup_policy(
    state: &AppState,
    session_id: &str,
    metadata: &SessionMetadata,
) -> Result<Arc<PolicyEntry>, StatusCode> {
    if let Some(e) = state.policies.get(session_id).await {
        return Ok(e);
    }
    let client = metadata.client.as_ref().ok_or_else(|| {
        eprintln!("lookup_policy: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    // Look up the bearer for the policy registry by hostname. Same
    // lookup applies per plugin below. Missing entry collapses to an
    // empty slice ⇒ anonymous pull (host attaches no Authorization
    // header).
    let policy_bearer =
        policy_pull::bearer_for_ref(&client.registry_auth, &metadata.policy_ref);

    // Context for the `kbs` key_source: relay client + attestor + session
    // id (bound into the ephemeral-key quote). Shared by the policy and
    // every plugin pull. `Plaintext`/`inbound` artifacts ignore it.
    let kbs_ctx = crate::keyprovider::KbsContext {
        kbs: &state.kbs,
        attestor: state.attestor.as_ref(),
    };

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
    let mut plugin_decls: Vec<enclavid_engine::ComponentDecls> =
        Vec::with_capacity(plugin_results.len());
    for res in plugin_results {
        let (package, art) = res.map_err(|e| {
            eprintln!(
                "lookup_policy: pull_plugin failed for session {session_id}: {e}",
            );
            StatusCode::GONE
        })?;
        // Parse the plugin's embedded sections before the wasm bytes
        // get dropped. Each plugin occupies its own slot in the
        // composition's `EmbeddedRegistry` (slot `idx + 1` in
        // `plugin_instances` order); these decls populate that slot
        // so the plugin can resolve refs for its declared keys via the
        // slot-bound closures `register_for_slot` wires up.
        let decls = enclavid_engine::load_embedded(&art.wasm_bytes).map_err(|e| {
            eprintln!(
                "lookup_policy: load_embedded failed for plugin {package} \
                 (session {session_id}): {e}",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let component = Arc::new(state.runner.compile(&art.wasm_bytes).map_err(|e| {
            eprintln!(
                "lookup_policy: plugin wasm compile failed for {session_id} \
                 (package {package}): {e}",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?);
        plugin_instances.push(PluginInstance { package, component });
        plugin_decls.push(decls);
    }

    let component = Arc::new(state.runner.compile(&artifact.wasm_bytes).map_err(
        |e| {
            eprintln!(
                "lookup_policy: wasm compile failed for {session_id}: {e}",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        },
    )?);
    // Parse the policy's embedded sections directly from the
    // decrypted wasm component — both
    // `enclavid:embedded.disclosure-fields.v1` and
    // `enclavid:embedded.i18n.v1` custom sections are optional, and
    // either / both / neither may be present.
    let policy_decls = enclavid_engine::load_embedded(&artifact.wasm_bytes).map_err(|e| {
        eprintln!(
            "lookup_policy: load_embedded failed for {session_id} \
             (policy_ref {}): {e}",
            metadata.policy_ref,
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    // Build the composition-wide `EmbeddedRegistry`. Slot 0 = policy
    // decls; slots 1..N = plugin decls in the same order as
    // `plugin_instances` (mirrors `client.plugins`). Engine's
    // `Runner::run` iterates `plugins` with the same order and calls
    // `register_for_slot(plugin_linker, idx + 1, ...)` per plugin —
    // slot attribution between api builder and engine Linker hooks
    // is the iteration order of `plugin_instances`.
    //
    // `policy_ref_key` is HKDF-derived from `tee_seal_key +
    // policy_ref` (see `crate::ref_key`). Stable across all sessions
    // of this policy artifact (refs round-trip across `/connect`
    // → `/input` rounds), distinct from every other policy's
    // ref_key — cross-policy ref replay is cryptographically
    // infeasible.
    let policy_ref_key = state.ref_key.derive_for_policy(&metadata.policy_ref);
    let mut embedded_builder = EmbeddedRegistry::builder(policy_ref_key);
    embedded_builder.add_component(policy_decls);
    for decls in plugin_decls {
        embedded_builder.add_component(decls);
    }
    let embedded = Arc::new(embedded_builder.build());
    let entry = Arc::new(PolicyEntry {
        component,
        embedded,
        plugins: Arc::new(plugin_instances),
    });
    state
        .policies
        .insert(session_id.to_string(), entry.clone())
        .await;
    Ok(entry)
}
