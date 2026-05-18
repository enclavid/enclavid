//! Shared helpers and ambient TEE-side secrets used by the applicant
//! handlers. Keep tightly scoped — anything reused by multiple handlers
//! belongs here, anything used by exactly one belongs in that handler's
//! own file.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use age::x25519::Identity;
use axum::extract::{FromRequestParts, Path};
use axum::http::StatusCode;
use axum::http::request::Parts;
use secrecy::ExposeSecret;
use tokio::sync::Mutex;

use enclavid_engine::policy::RunResources;
use enclavid_engine::{Component, EvalArgs, SessionListener, SessionState};
use enclavid_host_bridge::{
    AuthN, AuthZ, Metadata, Replay, SessionMetadata, State as StateField, reason,
};

use crate::error::ApiError;
use crate::input::parse_input;
use crate::locale::Locale;
use crate::policy_pull;
use crate::runtime::PolicyEntry;
use crate::state::AppState;
use crate::text_registry::TextRegistry;

use super::auth::CallerKey;
use super::persister::SessionPersister;
use super::views::{progress_from, SessionProgress};

pub(super) async fn fetch_metadata(
    state: &AppState,
    session_id: &str,
) -> Result<SessionMetadata, StatusCode> {
    // Applicant flow has no per-session info to cross-check metadata
    // against — security relies on the bearer-key auth layer plus the
    // client_policy_key encryption chain ensuring host-side metadata tampering
    // breaks the policy decryption / attestation chain. We accept the
    // host's existence claim and content at face value here; the trust
    // delegation is concentrated in `trust_unchecked` so callers don't
    // have to repeat the analysis.
    let ((metadata,), _version) = state
        .session_store
        .read(session_id, (Metadata,))
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

/// Build per-run resources for the engine. The listener is the only
/// side-effect channel — it fires after every committed CallEvent and
/// is responsible for sealing + persisting state and disclosures
/// atomically. Engine itself holds no keys; encryption lives on the
/// listener side, symmetric with how state/metadata are sealed inside
/// host-bridge.
pub(super) fn build_resources(
    listener: Arc<dyn SessionListener>,
    texts: &TextRegistry,
) -> RunResources {
    RunResources {
        listener,
        registered_text_refs: texts.registered_keys(),
    }
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
    /// Localized text dictionary registered by the policy at load
    /// time. Handlers resolve `text-ref` strings inside suspended
    /// requests / consent disclosures through this when assembling
    /// JSON for the frontend or the consumer SDK.
    pub(super) texts: Arc<TextRegistry>,
    /// Applicant's preferred locale (from `Accept-Language` header).
    /// Text-ref resolution happens server-side so the wire payload is
    /// a plain string per ref — frontend doesn't carry i18n logic.
    locale: Locale,
    persister: Arc<SessionPersister>,
    args: Vec<(String, EvalArgs)>,
    policy: Arc<Component>,
    resources: RunResources,
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
            texts,
            locale,
            persister,
            args,
            policy,
            resources,
            ..
        } = self;
        let (status, _session_state) = state
            .runner
            .run(&policy, session_state, args, resources)
            .await
            .map_err(|e| classify_run_error(&session_id, &e))?;
        // No-op for Suspended; flips status to Completed atomically
        // (metadata + host-plaintext Status) when the run terminated.
        persister.finalize(&status).await?;
        Ok(progress_from(status, &texts, &locale))
    }
}

/// Inspect a wasmtime/anyhow chain coming out of `runner.run`. Most
/// failures are opaque to the API consumer — surface as 500. Two
/// classes are well-known and worth turning into structured 422s:
///
///   * Unregistered text-ref — policy was pushed without the matching
///     `policy.json` manifest layer (or the manifest doesn't declare
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
                         manifest. Ensure `policy.json` lists the ref under \
                         `disclosure_fields` or `localized`, and that the manifest \
                         was pushed (run `enclavid policy push` with `policy.json` \
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
                &session_id,
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
            .trust_unchecked::<Replay, _>(reason!(r#"
Staleness on the version manifests as CAS mismatch on first
persist; same containment as above.
            "#))
            .into_inner();

        // Resolve the policy and its registered text constants
        // before the persister is built — the persister needs
        // `texts` to embed resolved labels into outbound disclosure
        // envelopes (the consumer SDK doesn't have access to the
        // policy's registry).
        let policy_entry = lookup_policy(state, &session_id, &metadata).await?;
        // PolicyEntry is reference-counted in the cache; cheap to
        // unpack its inner Arcs into per-run fields.
        let policy = policy_entry.component.clone();
        let texts = policy_entry.texts.clone();

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
        });
        // Engine takes one strong ref via the listener; we keep our
        // own so `finalize` lands on the same persister after the run
        // completes (engine drops its ref when Store is consumed).
        let resources = build_resources(persister.clone(), &texts);

        Ok(SessionRunCtx {
            state: state.clone(),
            session_id,
            session_state,
            texts,
            locale,
            persister,
            args,
            policy,
            resources,
        })
    }
}

/// Look up the compiled policy for a session, compiling lazily on
/// cache miss. The first /connect for a session pays the
/// pull+decrypt+compile cost; subsequent calls and /input rounds
/// hit the cache.
///
/// On cache miss the metadata's `client_policy_key` field is parsed as an
/// age identity, used to decrypt the policy artifact pulled from
/// the registry, and the resulting wasm is compiled into a
/// `Component`. client_policy_key lives in TEE memory only for the duration
/// of this function — once the `Component` is in the cache, client_policy_key
/// is dropped.
///
/// Errors map to HTTP statuses the handler can pass through directly:
///   * 410 Gone — registry pull / decrypt / compile failed (the
///     session was created with the wrong client_policy_key, or the policy
///     artifact has been removed)
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
    let client_policy_key_str = std::str::from_utf8(&client.policy_key).map_err(|e| {
        eprintln!("lookup_policy: client_policy_key not utf8 for {session_id}: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let client_policy_key = Identity::from_str(client_policy_key_str).map_err(|e| {
        eprintln!("lookup_policy: client_policy_key age::Identity parse failed for {session_id}: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let artifact = policy_pull::pull_and_decrypt(
        &state.registry,
        &metadata.policy_ref,
        &client.registry_auth,
        &client_policy_key,
    )
    .await
    .map_err(|e| {
        eprintln!(
            "lookup_policy: pull_and_decrypt failed for session {session_id} \
             (policy_ref={}): {e}",
            metadata.policy_ref,
        );
        StatusCode::GONE
    })?;
    let component = Arc::new(state.runner.compile(&artifact.wasm_bytes).map_err(
        |e| {
            eprintln!(
                "lookup_policy: wasm compile failed for {session_id}: {e}",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        },
    )?);
    // Parse the policy manifest from its OCI layer (plain JSON,
    // sibling of the encrypted wasm). The manifest layer is
    // mandatory — `enclavid policy push` refuses to ship an artifact
    // without it, and `pull_and_decrypt` surfaces `NoPolicyManifestLayer`
    // when missing. Policies without UI strings still ship an empty
    // `{"version": 1}` to satisfy the requirement.
    let decls = enclavid_engine::load_manifest(&artifact.manifest_bytes).map_err(|e| {
        eprintln!(
            "lookup_policy: load_manifest failed for {session_id} \
             (policy_ref {}): {e}",
            metadata.policy_ref,
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let texts = Arc::new(TextRegistry::from_decls(decls));
    let entry = Arc::new(PolicyEntry { component, texts });
    state
        .policies
        .insert(session_id.to_string(), entry.clone())
        .await;
    Ok(entry)
}
