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
use tokio::sync::Mutex;

use enclavid_engine::{
    Component, EmbeddedRegistry, MediaStore, PluginInstance, Prop, RunInputs, RunStatus,
    SessionListener, SessionState,
};

use super::media_store::BrokerMediaStore;
use broker_client::{
    AuthN, AuthZ, Event, Metadata, Replay, SessionMetadata, State as StateField, public_session_id,
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

/// Build per-run resources for the engine. Listener: side-effect
/// channel — fires once per reducer round, seals + persists state and
/// any consented disclosure atomically. Embedded registry: composition-
/// wide `EmbeddedRegistry`, constructed once at policy-cache build
/// time (see [`lookup_policy`]) and threaded into both engine (slot-
/// bound resolve + use-site reverse-lookup) and api view-layer (ref →
/// user-facing text) so all consumers agree on slot attribution.
pub(super) fn build_run_inputs(
    listener: Arc<dyn SessionListener>,
    embedded: Arc<EmbeddedRegistry>,
    media_store: Arc<dyn MediaStore>,
) -> RunInputs {
    RunInputs {
        listener,
        embedded,
        media_store,
    }
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
    /// ends. MUST outlive `runner.run().await` — see [`SessionRunCtx::run`].
    applicant_session_token: Arc<SecretBox<Vec<u8>>>,
    persister: Arc<SessionPersister>,
    props: Vec<(String, Prop)>,
    /// The fused policy component (policy + pinned plugins, wac
    /// single-store fused on first /connect — see [`lookup_policy`]).
    /// Shared by Arc with the cache entry; immutable for the session's
    /// lifetime.
    policy: Arc<Component>,
    /// Manifest of distinct per-catalog i18n/icons imports the engine
    /// registers on the host `Linker` for this fused component. Shared
    /// by Arc with the cache entry.
    embedded_imports: Arc<Vec<enclavid_engine::EmbeddedImport>>,
    run_inputs: RunInputs,
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
            // only `Weak`s. It MUST stay alive across `runner.run().await` below
            // so their `upgrade()`s succeed while the engine seals state / opens
            // media. Dropping it early makes those upgrades return `None` and the
            // round traps. It drops (and zeroizes) at the end of this fn.
            applicant_session_token: _token_owner,
            persister,
            props,
            policy,
            embedded_imports,
            run_inputs,
            ..
        } = self;
        let (status, _session_state) = state
            .runner
            .run(&policy, &embedded_imports, session_state, event, props, run_inputs)
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
                if matches!(e, broker_client::BridgeError::Crypto(_)) {
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

        // Resolve the policy and its registered text constants
        // before the persister is built — the persister consults the
        // embedded registry to project slot-tagged disclosure-field-
        // refs back to their machine identifiers when sealing the
        // envelope to the consumer SDK.
        let policy_entry = lookup_policy(state, &session_id, &metadata).await?;
        // PolicyEntry is reference-counted in the cache; cheap to
        // unpack its inner Arcs into per-run fields.
        let policy = policy_entry.component.clone();
        let embedded_imports = policy_entry.embedded_imports.clone();
        let embedded = policy_entry.embedded.clone();

        // Per-run persister: engine fires `on_session_change` once per
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
        // The live host blob store: the engine's `blob::from-blob-ref` reads
        // sealed captures back through this — a pull-through cache over the
        // broker backing, gated by the session's captured-hash set (from sealed
        // metadata, prior rounds) so a fabricated ref is refused in-TEE without
        // a broker read. Same session keys as the persister that WROTE them.
        let captured: HashSet<[u8; 32]> = metadata
            .captured_media
            .iter()
            .filter_map(|h| <[u8; 32]>::try_from(h.as_slice()).ok())
            .collect();
        let media_store = Arc::new(BrokerMediaStore {
            session_store: state.session_store.clone(),
            session_id: session_id.clone(),
            // Weak: the strong lives in the SessionRunCtx below (sole owner).
            applicant_session_token: Arc::downgrade(&applicant_session_token),
            cache: state.media_cache.clone(),
            captured,
        });
        // Engine takes one strong ref via the listener; we keep our
        // own so `finalize` lands on the same persister after the run
        // completes (engine drops its ref when Store is consumed).
        let run_inputs = build_run_inputs(persister.clone(), embedded.clone(), media_store);

        Ok(SessionRunCtx {
            state: state.clone(),
            session_id,
            session_state,
            locale,
            // Move the sole strong ref in — the persister / media store above
            // hold only `Weak`s downgraded from it.
            applicant_session_token,
            persister,
            props,
            policy,
            embedded_imports,
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

    // Context for the `kbs` key path: the broker relay client that
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
    let mut plugin_catalogs: Vec<enclavid_engine::EmbeddedCatalog> =
        Vec::with_capacity(plugin_results.len());
    for res in plugin_results {
        let (package, art) = res.map_err(|e| {
            eprintln!(
                "lookup_policy: pull_plugin failed for session {session_id}: {e}",
            );
            StatusCode::GONE
        })?;
        // Parse the plugin's embedded sections before the wasm bytes
        // are moved into the `PluginInstance`. The catalog's
        // content-hash keys its entries in the `EmbeddedRegistry` — the
        // same hash the fuser routes this plugin's imports under, so
        // strict per-component resolution lines up.
        let catalog = enclavid_engine::load_embedded(&art.wasm_bytes).map_err(|e| {
            eprintln!(
                "lookup_policy: load_embedded failed for plugin {package} \
                 (session {session_id}): {e}",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        // Keep the raw component bytes — fusion (`Runner::compose`)
        // runs on bytes, not a pre-compiled `Component`.
        plugin_instances.push(PluginInstance {
            package,
            wasm: art.wasm_bytes,
        });
        plugin_catalogs.push(catalog);
    }

    // Fuse the policy with its pinned plugins into ONE component (wac
    // single-store fusion) and compile it, along with the manifest of
    // distinct per-catalog i18n/icons imports the host Linker must wire.
    // With no plugins this is a plain compile of the policy bytes and an
    // empty manifest.
    let composition = state
        .runner
        .compose(&artifact.wasm_bytes, &plugin_instances)
        .map_err(|e| {
            eprintln!(
                "lookup_policy: policy+plugin composition failed for {session_id}: {e}",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let component = Arc::new(composition.component);
    let embedded_imports = Arc::new(composition.embedded_imports);
    // Parse the policy's embedded sections directly from the
    // decrypted wasm component — both
    // `enclavid:embedded.disclosure-fields.v1` and
    // `enclavid:embedded.i18n.v1` custom sections are optional, and
    // either / both / neither may be present.
    let policy_catalog = enclavid_engine::load_embedded(&artifact.wasm_bytes).map_err(|e| {
        eprintln!(
            "lookup_policy: load_embedded failed for {session_id} \
             (policy_ref {}): {e}",
            metadata.policy_ref,
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    // Build the composition-wide `EmbeddedRegistry`, keyed by each
    // component's catalog content-hash. Policy first (composition order,
    // which fixes the merged-path first-match order), then plugins in
    // `plugin_instances` order (mirrors `client.plugins`).
    let mut embedded_builder = EmbeddedRegistry::builder();
    embedded_builder.add_component(policy_catalog.hash, policy_catalog.decls);
    for catalog in plugin_catalogs {
        embedded_builder.add_component(catalog.hash, catalog.decls);
    }
    let embedded = Arc::new(embedded_builder.build());
    let entry = Arc::new(PolicyEntry {
        component,
        embedded_imports,
        embedded,
    });
    state
        .policies
        .insert(session_id.to_string(), entry.clone())
        .await;
    Ok(entry)
}
