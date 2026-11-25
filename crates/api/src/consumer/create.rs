use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{MethodRouter, post};
use base64ct::{Base64, Encoding};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use enclavid_attestation::ReportData;
use enclavid_boundary::{Covert, reason};
use session_types::{
    Consumer, ConsumerAccess, Key, PluginPin, SessionMetadata, SessionQuote, SessionStatus,
    Webhook, is_wit_name,
};
use storage_client::boundary::Storage;
use storage_client::{MetadataOp, SetMetadata};

use crate::dto::{PluginView, ResolvedPolicyView};
use crate::init;
use crate::limits::{
    MAX_CONSUMER_REF_LEN, MAX_PLUGINS, MAX_REGISTRY_AUTH_LEN, MAX_WEBHOOK_URL_LEN,
    SESSION_ID_RANDOM_BYTES, SESSION_TOKEN_BYTES, WEBHOOK_SECRET_BYTES,
};
use crate::policy_pull;
use crate::props;

use hatch_client::SessionTerms;

use super::auth::{Principal, Terms};
use super::state::ConsumerState;

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    /// Full pinned OCI reference for the policy artifact:
    /// `<registry>/<repository>@sha256:<hex>`. Tag-form rejected at
    /// parse — TEE only ever asks the registry by digest. The
    /// registry hostname is part of the ref, so any OCI-compliant
    /// registry works (our Angos by default; ghcr, ECR, etc. via
    /// PR4 once `registry_auth` is wired up).
    pub policy: String,
    /// Disclosure recipient pubkey: applicant-consented data is
    /// encrypted to this. Provided as age recipient string `age1...`.
    pub disclosure_pubkey: String,
    /// Opaque consumer-side identifier for this verification — proxied
    /// back in webhook payloads and `GET /sessions/:id`. NOT
    /// indexed: consumers reconcile `consumer_ref → session_id` on their
    /// own side. Optional. Validated at deserialization (length and
    /// charset) so a malformed value surfaces as a serde error → 400
    /// before the handler even runs.
    #[serde(default, deserialize_with = "deserialize_external_ref")]
    pub consumer_ref: Option<String>,
    /// Per-hostname registry bearer map. Key = registry hostname
    /// (authority portion of an OCI ref, e.g. `closed.vendor.com`);
    /// value = the full `Authorization` header value the host should
    /// attach when pulling from that registry (e.g. `"Bearer <token>"`).
    /// Applies uniformly to the policy ref AND every plugin's
    /// `impl_ref`.
    ///
    /// Missing hostname / empty value ⇒ anonymous pull. The
    /// `Authorization` this request is made with is never taken for a
    /// registry: a registry gets only the bearer named for it here.
    ///
    /// Total serialized size bounded by [`MAX_REGISTRY_AUTH_LEN`]
    /// (sum of all values) to keep session metadata blobs cheap.
    #[serde(default)]
    pub registry_auth: BTreeMap<String, String>,

    /// Plugin pins declared by the consumer at session creation. One
    /// entry per non-host-provided WIT package the policy imports.
    /// Each `impl_ref` MUST be digest-pinned (`@sha256:<hex>`).
    /// Hostname portion of `impl_ref` drives the
    /// [`Self::registry_auth`] lookup at pull time.
    ///
    /// Empty when the policy has no plugin imports.
    #[serde(default)]
    pub plugins: Vec<PluginRequest>,

    /// The policy artifact's decryption key. Omit ⇒ not encrypted. See
    /// [`KeyRequest`].
    #[serde(default)]
    pub policy_key: Option<KeyRequest>,

    /// The props the policy reads for this session, as the JSON value of the
    /// type the policy declares for them (`enclavid-ext:policy/props`): an
    /// object keyed by its field names for a record, as a rule, or a number, a
    /// string, an array. Omit for a policy that takes none, or none to give.
    /// At most [`MAX_PROPS_SIZE`](crate::limits::MAX_PROPS_SIZE) bytes as
    /// compact JSON; whether they fit is the type the policy declares to say,
    /// when the session is prepared to run.
    #[serde(default)]
    pub props: Option<serde_json::Value>,

    /// Prepare the session to run as soon as it is created — its pins checked,
    /// its composition compiled, kept and held by the execution-worker, its
    /// props read against the policy's type — so the applicant's first round
    /// does not wait for any of it, and a session that cannot run is marked so
    /// before anyone connects. The response does not wait for it. The same as
    /// `POST /api/v1/sessions/{id}/warmup` on the session once it is created.
    #[serde(default)]
    pub warmup: bool,

    /// The consumer's webhook, told when the session ends — its policy gave a
    /// decision, or it could not be prepared to run. Omit for none.
    #[serde(default)]
    pub webhook: Option<WebhookSetup>,
}

/// A webhook as a creation gives it. Every field is required.
#[derive(Deserialize)]
pub struct WebhookSetup {
    /// The endpoint: an `https://` URL; `http://` only in a build that is not
    /// measured, and, in one that is, at a public address. Kept as the hatch
    /// reads it — scheme in lowercase, host in ASCII — and at most
    /// [`MAX_WEBHOOK_URL_LEN`] bytes so.
    pub url: String,
    /// The Standard Webhooks signing secret: `whsec_`, then its key in base64.
    pub secret: String,
    /// The X25519 public key, as 64 hex digits, that `sealed_session_id` is
    /// sealed to. A pair of the webhook's own, not the disclosures', with the id
    /// opened only once the signature checks: a forged webhook then gets nothing
    /// opened.
    pub pubkey: String,
}

/// The webhook `setup` asks for, as the session keeps it; a 400 where any part
/// of it is not as [`WebhookSetup`] says.
fn webhook(setup: WebhookSetup) -> Result<Webhook, StatusCode> {
    let WebhookSetup {
        url,
        secret,
        pubkey,
    } = setup;
    // Read as the hatch reads it, and refused where reading it took a guess: a
    // slash too many, a backslash, a character a URL does not carry.
    let guessed = std::cell::Cell::new(false);
    let parsed = url::Url::options()
        .syntax_violation_callback(Some(&|_| guessed.set(true)))
        .parse(&url)
        .ok()
        .filter(|_| !guessed.get())
        .ok_or(StatusCode::BAD_REQUEST)?;
    // The endpoint is reached from the hatch, where TLS ends: in the clear, the
    // host would read what the webhook carries.
    let scheme = match parsed.scheme() {
        "https" => true,
        "http" => !cfg!(feature = "sev-snp"),
        _ => false,
    };
    let url = String::from(parsed);
    // The measured hatch sends only to a public address: a URL that writes
    // another, or names localhost, is refused here, where the consumer hears of
    // it. A name that resolves to one only the hatch can tell.
    if !scheme
        || url.len() > MAX_WEBHOOK_URL_LEN
        || !url.chars().all(|c| c.is_ascii_graphic())
        || (cfg!(feature = "sev-snp") && !hatch_rpc::public_as_written(&url))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let secret = secret
        .strip_prefix("whsec_")
        .and_then(|key| Base64::decode_vec(key).ok())
        .filter(|key| WEBHOOK_SECRET_BYTES.contains(&key.len()))
        .ok_or(StatusCode::BAD_REQUEST)?;
    let pubkey = hex::decode(&pubkey)
        .ok()
        .filter(|key| key.len() == 32)
        .ok_or(StatusCode::BAD_REQUEST)?;
    Ok(Webhook {
        id: generate_webhook_id(),
        url,
        secret,
        pubkey: hex::encode(pubkey),
    })
}

/// One plugin pin in the create-session request. Mirrors the sealed
/// `domain::PluginPin` with serde-friendly field types; converted before
/// persistence.
#[derive(Deserialize)]
pub struct PluginRequest {
    /// WIT package id this pin satisfies, e.g. `vendor:plugin@0.1.0`.
    pub package: String,
    /// Full pinned OCI reference, e.g.
    /// `closed.vendor.com/plugin@sha256:<hex>`. Tag-form rejected at
    /// the handler.
    pub impl_ref: String,
    /// This plugin's decryption key. Omit ⇒ not encrypted. See
    /// [`KeyRequest`].
    #[serde(default)]
    pub key: Option<KeyRequest>,
}

/// Consumer-supplied artifact key. Either the key itself as a base64 string
/// (`"key": "<base64>"`, owner-supplied) or a KBS reference
/// (`"key": { "kbs": { endpoint } }`). The KBS resource URI naming the key
/// lives in the artifact's digest-pinned `enc.keys.*` annotation, so the
/// consumer supplies only which KBS to dial. Converted to the sealed
/// [`session_types::Key`] before persistence (the secrets then only ride
/// inside AEAD-sealed metadata).
#[derive(Deserialize)]
#[serde(untagged)]
pub enum KeyRequest {
    /// `"key": "<base64>"` — the symmetric layer key, supplied inline.
    Inline(String),
    /// `"key": { "kbs": { ... } }` — released by an attestation-gated KBS.
    Kbs { kbs: KbsKeyRequest },
}

#[derive(Deserialize)]
pub struct KbsKeyRequest {
    /// KBS origin the hatch dials, e.g. `https://kbs.vendor.com:8080`.
    pub endpoint: String,
}

impl KeyRequest {
    /// Convert to the sealed domain form, decoding base64 key material.
    /// `None` ⇒ not encrypted. Bad base64 ⇒ `Err(BAD_REQUEST)`.
    fn into_domain(this: Option<Self>) -> Result<Option<session_types::Key>, StatusCode> {
        use session_types::{KbsKey, Key};
        Ok(match this {
            None => None,
            Some(KeyRequest::Inline(key)) => {
                let key = Base64::decode_vec(&key).map_err(|_| StatusCode::BAD_REQUEST)?;
                if key.is_empty() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                Some(Key::Inline(key))
            }
            Some(KeyRequest::Kbs { kbs }) => {
                // The evidence api presents a broker carries no hardware signature
                // (`keyprovider`), and a broker that releases on it releases to
                // anyone: the measured build takes no broker-released key.
                if cfg!(feature = "sev-snp") {
                    return Err(StatusCode::BAD_REQUEST);
                }
                // A broker is reached over http(s), as the hatch reaches it: an
                // endpoint written any other way is one no handshake ever answers.
                let host = kbs
                    .endpoint
                    .strip_prefix("https://")
                    .or_else(|| kbs.endpoint.strip_prefix("http://"));
                if host.is_none_or(str::is_empty) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                Some(Key::Kbs(KbsKey {
                    endpoint: kbs.endpoint,
                }))
            }
        })
    }
}

/// What a creation pins — the policy, its plugins, their keys, and the bearers
/// to pull them with — validated as one.
struct Pins {
    policy_ref: String,
    /// The policy's digest, the hex after `@sha256:`.
    policy_digest: String,
    plugins: Vec<PluginPin>,
    policy_key: Option<Key>,
    registry_auth: HashMap<String, Vec<u8>>,
}

/// Validate what a request pins. Every refusal is a 400, before anything is
/// kept or compiled.
fn pins(
    policy: String,
    plugin_requests: Vec<PluginRequest>,
    registry_auth_requests: BTreeMap<String, String>,
    policy_key: Option<KeyRequest>,
) -> Result<Pins, StatusCode> {
    // Validate the ref shape up-front — tag-form (no `@sha256:`) or
    // bad-algo refs trap here with a clean 400, instead of failing
    // later inside policy_pull with an opaque error. The TEE only ever
    // runs digest-pinned artifacts; a consumer wanting `:latest`
    // ergonomics resolves the tag to a digest in their own control plane.
    let policy_digest = policy_pull::split_pinned_ref(&policy)
        .map(|(_, d)| d.to_string())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // The hostname-keyed bearer map, as the body names it — which hostname
    // gets which bearer (covers heterogeneous "policy in our Angos, plugin in
    // ghcr" deployments). Only as it names it: the credential this request is
    // made with is for this API, and is never handed to a registry, which is
    // whoever the pins name. Length-bound the SUM of values so a malicious
    // consumer can't bloat session metadata.
    let registry_auth: HashMap<String, Vec<u8>> = registry_auth_requests
        .into_iter()
        .map(|(host, bearer)| (host, bearer.into_bytes()))
        .collect();
    let total_bearer_bytes: usize = registry_auth.values().map(Vec::len).sum();
    if total_bearer_bytes > MAX_REGISTRY_AUTH_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate every plugin ref is digest-pinned (`@sha256:<hex>`)
    // before persistence — surfaces typos as a clean 400 instead of
    // an opaque pull error at /connect. Also dedupe-checks on
    // package id — two pins for the same WIT package would create
    // ambiguity at link time and is almost certainly a caller bug.
    // The package is spelled as a WIT package name is: it is what the
    // session's init error names a plugin by.
    if plugin_requests.len() > MAX_PLUGINS {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut seen_packages: std::collections::HashSet<&str> = Default::default();
    for pr in &plugin_requests {
        if !is_wit_name(&pr.package) || pr.impl_ref.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if policy_pull::split_pinned_ref(&pr.impl_ref).is_none() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if !seen_packages.insert(pr.package.as_str()) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let plugins: Vec<PluginPin> = plugin_requests
        .into_iter()
        .map(|pr| {
            Ok(PluginPin {
                package: pr.package,
                impl_ref: pr.impl_ref,
                key: KeyRequest::into_domain(pr.key)?,
            })
        })
        .collect::<Result<_, StatusCode>>()?;

    // The hatch reads a ref's scheme only as `http://` or `https://` in
    // lowercase, once at its front: a ref written another way is one it cannot
    // pull.
    let schemed = |r: &str| {
        let rest = r
            .strip_prefix("http://")
            .or_else(|| r.strip_prefix("https://"))
            .unwrap_or(r);
        !rest.contains("://")
    };
    if !schemed(&policy) || plugins.iter().any(|p| !schemed(&p.impl_ref)) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // A registry written `http://` is reached in the clear, across the host's
    // network: a bearer for it would cross there too, readable by the host. So
    // plain HTTP is for anonymous pulls alone, and a bearer the consumer names
    // for one is refused.
    let in_clear = |r: &str| {
        r.starts_with("http://") && !policy_pull::bearer_for_ref(&registry_auth, r).is_empty()
    };
    if in_clear(&policy) || plugins.iter().any(|p| in_clear(&p.impl_ref)) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // The measured hatch pulls only from a public registry: one a ref names by
    // another address, or as localhost, is refused here, where the consumer
    // hears of it. A name that resolves to one only the hatch can tell.
    let public = |r: &str| {
        policy_pull::registry_hostname(r)
            .is_some_and(|host| hatch_rpc::public_as_written(&format!("https://{host}/")))
    };
    if cfg!(feature = "sev-snp")
        && !(public(&policy) && plugins.iter().all(|p| public(&p.impl_ref)))
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Pins {
        policy_ref: policy,
        policy_digest,
        plugins,
        policy_key: KeyRequest::into_domain(policy_key)?,
        registry_auth,
    })
}

/// Length-bound + printable-ASCII gate on `consumer_ref`. Empty
/// strings collapse to `None` (treated identically to "missing").
/// The restricted charset avoids host-side key parsing surprises
/// and disallows zero-width / RTL-override confusables that could
/// spoof reconciliation on the consumer's dashboard.
fn deserialize_external_ref<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let opt = <Option<String>>::deserialize(d)?;
    let Some(s) = opt else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    if s.len() > MAX_CONSUMER_REF_LEN {
        return Err(serde::de::Error::custom(format!(
            "must not exceed {MAX_CONSUMER_REF_LEN} bytes"
        )));
    }
    if s.chars().any(|c| !c.is_ascii_graphic()) {
        return Err(serde::de::Error::custom(
            "must consist of printable ASCII only (no whitespace, no control chars)",
        ));
    }
    Ok(Some(s))
}

#[derive(Serialize)]
pub struct AttestationView {
    pub format: String,
    /// Base64-standard encoding of `Quote::quote_blob`.
    pub quote: String,
    /// Hex-encoded TEE measurement.
    pub measurement: String,
}

#[derive(Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    /// Per-session bearer the consumer MUST present in the `X-Session-Token`
    /// header on every subsequent `GET /sessions/:id*` call. Base64-
    /// standard encoded 32 random bytes. Generated by the TEE here,
    /// returned **only** in this TLS-encrypted response (host doesn't
    /// see it). The consumer should persist it alongside `session_id` —
    /// losing it means losing read access to that session (TTL bounded
    /// to session lifetime).
    pub session_token: String,
    pub resolved_policy: ResolvedPolicyView,
    pub attestation: AttestationView,
}

/// The terms the consumer's limits asked for, each held to the fleet's own
/// ceiling: what this build compiles and runs at most, how long the store keeps
/// a session (`ttl`, `None` for no end), how long a pull may take
/// (`pull_deadline`). A term asked for above its ceiling is the ceiling; one
/// not asked for stays the fleet's own.
fn held(
    asked: SessionTerms,
    ttl: Option<u64>,
    pull_deadline: std::time::Duration,
) -> session_types::Terms {
    let under =
        |term: Option<u64>, ceiling: Option<u64>| term.map(|t| ceiling.map_or(t, |c| t.min(c)));
    session_types::Terms {
        components_bytes: under(
            asked.components_bytes,
            Some(engine_rpc::MAX_COMPONENTS_BYTES),
        ),
        cwasm_bytes: under(asked.cwasm_bytes, Some(engine_rpc::MAX_CWASM_BYTES)),
        session_ttl_secs: under(asked.session_ttl_secs, ttl),
        pull_deadline_secs: under(asked.pull_deadline_secs, Some(pull_deadline.as_secs())),
    }
}

/// Route factory: bare `post(handler)` MethodRouter. Auth is attached
/// at the router level via `.layer(auth(op))` — see `consumer::router`.
pub(super) fn post_create() -> MethodRouter<Arc<ConsumerState>> {
    post(create)
}

/// POST /api/v1/sessions — full session-creation flow in one shot.
///
/// 1. Parse + validate `policy` reference, `consumer_ref`, plugin pins.
/// 2. Mint an attestation quote binding the session id to this TEE
///    measurement — the one the session's applicant page is served too, so it
///    binds nothing else (see `ReportData::Session`). That the request reached
///    this TEE as it was sent is the channel's to show: the gateway's quote
///    over its own key.
/// 3. Write the sealed metadata, its status Running and the quote with it, to
///    the store.
///
/// The persisted metadata blob is AEAD'd with the TEE-side key,
/// AAD=session_id, so the host sees opaque bytes only.
async fn create(
    State(state): State<Arc<ConsumerState>>,
    Principal(principal): Principal,
    Terms(asked): Terms,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, StatusCode> {
    let pins = pins(
        body.policy,
        body.plugins,
        body.registry_auth,
        body.policy_key,
    )?;
    let Pins {
        policy_ref,
        policy_digest,
        plugins,
        policy_key,
        registry_auth,
    } = pins;

    // Snapshot the plugin set for the create response before the pins move into
    // the sealed metadata below — the full set of digest-pinned artifacts that
    // will build the cwasm, echoed to the consumer alongside the policy.
    let plugin_views: Vec<PluginView> = plugins.iter().map(PluginView::from_pin).collect();

    // Held to their size here, before persistence; whether they fit the type
    // the policy declares is read when the session is prepared.
    let props = props::encode(body.props.as_ref()).ok_or(StatusCode::BAD_REQUEST)?;
    let webhook = body.webhook.map(webhook).transpose()?;

    let session_id = generate_session_id();

    // Per-session capability bearer. Returned to the consumer below
    // (TLS-encrypted, host doesn't see); stored only as SHA-256 hash
    // in the sealed metadata so tee_seal_key compromise alone doesn't
    // leak the token (pre-image resistance on 256-bit input). The consumer
    // presents the raw bytes in `X-Session-Token` on read endpoints;
    // TEE recomputes the hash, constant-time compares with stored.
    // SecretBox so plaintext zeroizes on drop and is redacted from
    // Debug output.
    let session_token = generate_session_token();
    let session_token_hash = Sha256::digest(session_token.expose_secret()).to_vec();

    let report_data = ReportData::session(session_id.clone());
    let quote = state
        .attestor
        .mint(&report_data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let consumer = Consumer {
        // Per-session access gate (defense-in-depth) — see
        // ConsumerAccess proto doc.
        access: Some(ConsumerAccess {
            // Principal is crypto-pinned here for the TEE-side
            // cross-tenant check on reads. There is NO plaintext host
            // copy: the storage-CVM is blind, so host-side tenant
            // indexing is gone (see the metadata-only write below).
            principal: principal.clone(),
            // SHA-256 of the bearer we returned to the consumer in the
            // POST /sessions response.
            session_token_hash,
        }),
        disclosure_pubkey: body.disclosure_pubkey,
        r#ref: body.consumer_ref.unwrap_or_default(),
        registry_auth,
        plugins,
        webhook,
    };
    let metadata = SessionMetadata {
        policy_ref: policy_ref.clone(),
        props,
        consumer: Some(consumer),
        // TEE-trusted lifecycle status — the sole copy there is.
        status: SessionStatus::Running,
        created_at,
        // Persister increments this atomically with each
        // AppendDisclosure write — see SessionPersister.
        disclosure_count: 0,
        // Empty leaf list: the persister pushes a per-entry hash on each
        // AppendDisclosure; the disclosures handler commits over this list and
        // compares to the host-served set to detect tampering. The empty-set
        // commitment is implicit (verify recomputes it), so no seed is needed.
        disclosure_entry_hashes: Vec::new(),
        policy_key,
        // No media captured yet — the `from-blob-ref` gate set starts empty and
        // the persister appends each capture's hash as rounds run.
        captured_media: Vec::new(),
        // Set with `Completed`, when the policy gives it.
        decision: None,
        // Prepared before the first round, not here: see `crate::init`.
        prepared: None,
        // Set with `InitFailed`, if preparing the session fails: see `crate::init`.
        init_error: None,
        terms: held(asked, state.session_store.ttl_secs(), state.pull_deadline),
        // The same bytes the consumer is answered with below, kept for the
        // session's applicant page.
        quote: Some(SessionQuote {
            format: quote.format.clone(),
            blob: quote.quote_blob.clone(),
        }),
        // No applicant holds the session yet: the first `/connect` locks a data
        // key under its key.
        data_key_lock: None,
    };
    // Write ONLY the sealed metadata. The plaintext STATUS byte and PRINCIPAL
    // host hooks are gone: TTL is enforced inside the storage-CVM (its sweeper,
    // fed the deadline over RA-TLS), and the TEE-trusted status + principal
    // already live crypto-pinned in `metadata` (status / consumer.access.principal).
    // A blind storage-CVM exposes no host query surface, so a plaintext copy would
    // leak lifecycle + tenant identity for zero benefit.
    let set_metadata = SetMetadata(Storage::expose_builder::<MetadataOp, _>(&metadata).vouch(
        reason!(
            Covert::NotChosen,
            "initial /create write before any policy runs; fields are consumer-controlled, not policy-controlled — zero covert bandwidth"
        ),
    ));
    let ops = state
        .session_store
        .seal(&session_id, &[&set_metadata])
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .vouch(reason!(
            Covert::NotChosen,
            "no policy has run at /create — the single metadata op is fixed, not policy bandwidth"
        ));
    // A session lives as long as its terms say, where they say: its deadline
    // is set by this write, once.
    let version = match metadata.terms.session_ttl_secs {
        Some(ttl) => state.session_store.create(ttl, ops).await,
        None => state.session_store.write(None, ops).await,
    }
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // After the write, so a warmup never prepares a session that does not
    // exist; not awaited, so the response does not wait for the compile.
    if body.warmup {
        init::warm_in_background(
            state.compositions.clone(),
            state.session_store.clone(),
            session_id.clone(),
            version,
            metadata,
        );
    }

    Ok(Json(CreateSessionResponse {
        session_id,
        session_token: Base64::encode_string(session_token.expose_secret()),
        resolved_policy: ResolvedPolicyView {
            reference: policy_ref,
            digest: policy_digest,
            plugins: plugin_views,
        },
        attestation: AttestationView {
            format: quote.format,
            quote: Base64::encode_string(&quote.quote_blob),
            measurement: quote.measurement,
        },
    }))
}

fn generate_session_id() -> String {
    let mut bytes = [0u8; SESSION_ID_RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("ses_{}", hex::encode(bytes))
}

fn generate_webhook_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("msg_{}", hex::encode(bytes))
}

/// Mint a fresh 32-byte per-session bearer for consumer reads. Wrapped
/// in `SecretBox` so the plaintext zeroizes on drop and never lands in
/// debug logs.
fn generate_session_token() -> SecretBox<Vec<u8>> {
    let mut bytes = vec![0u8; SESSION_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    SecretBox::new(Box::new(bytes))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const PULL: Duration = Duration::from_secs(30);

    fn pinned(at: &str) -> String {
        format!("{at}/team/p@sha256:{}", "ab".repeat(32))
    }

    /// A bearer is never pinned to a registry reached in the clear: plain HTTP
    /// is for anonymous pulls, and a bearer over TLS stands, as it was named.
    #[test]
    fn a_bearer_is_never_sent_in_the_clear() {
        let plugin = |impl_ref: String| PluginRequest {
            package: "vendor:plugin@0.1.0".into(),
            impl_ref,
            key: None,
        };
        let auth = |host: &str| BTreeMap::from([(host.to_string(), "Bearer t".to_string())]);
        let ask = |policy: String, plugins, registry_auth| {
            pins(policy, plugins, registry_auth, None).map(|pins| pins.registry_auth)
        };
        // Plain HTTP with a bearer the consumer names for its host: the
        // policy's, or a plugin's.
        assert_eq!(
            ask(pinned("http://r.example"), vec![], auth("r.example")),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            ask(
                pinned("s.example"),
                vec![plugin(pinned("http://r.example"))],
                auth("r.example")
            ),
            Err(StatusCode::BAD_REQUEST)
        );
        // Over TLS with a bearer, and in the clear without one, both stand.
        let named = Ok(HashMap::from([(
            "r.example".to_string(),
            b"Bearer t".to_vec(),
        )]));
        assert_eq!(ask(pinned("r.example"), vec![], auth("r.example")), named);
        assert_eq!(
            ask(pinned("https://r.example"), vec![], auth("r.example")),
            named
        );
        assert!(
            ask(
                pinned("http://r.example"),
                vec![plugin(pinned("s.example"))],
                auth("s.example")
            )
            .is_ok()
        );
        assert_eq!(
            ask(pinned("http://r.example"), vec![], BTreeMap::new()),
            Ok(HashMap::new())
        );
    }

    /// In the measured build a ref names a public registry: the policy's and
    /// each plugin's, by address or as localhost refused.
    #[test]
    fn a_registry_is_one_the_hatch_reaches() {
        let plugin = |impl_ref: String| PluginRequest {
            package: "vendor:plugin@0.1.0".into(),
            impl_ref,
            key: None,
        };
        let kept = |policy: String, plugins| pins(policy, plugins, BTreeMap::new(), None).is_ok();
        for private in ["127.0.0.1:5000", "http://10.0.0.5:5000", "localhost:5000"] {
            assert_eq!(
                kept(pinned(private), vec![]),
                !cfg!(feature = "sev-snp"),
                "{private}"
            );
            assert_eq!(
                kept(pinned("r.example"), vec![plugin(pinned(private))]),
                !cfg!(feature = "sev-snp"),
                "{private}"
            );
        }
        assert!(kept(
            pinned("r.example"),
            vec![plugin(pinned("1.1.1.1:5000"))]
        ));
        assert!(kept("enclavid/policy@sha256:00".into(), vec![]));
        // A scheme the hatch does not read, in any build.
        for unread in [
            "HTTP://r.example",
            "Https://r.example",
            "http://http://r.example",
            "oci://r.example",
        ] {
            assert!(!kept(pinned(unread), vec![]), "{unread}");
            assert!(
                !kept(pinned("r.example"), vec![plugin(pinned(unread))]),
                "{unread}"
            );
        }
    }

    /// A broker's key names a broker reached over http(s); the measured build
    /// takes none.
    #[test]
    fn a_brokers_key_names_a_broker_it_can_reach() {
        let kbs = |endpoint: &str| {
            KeyRequest::into_domain(Some(KeyRequest::Kbs {
                kbs: KbsKeyRequest {
                    endpoint: endpoint.into(),
                },
            }))
        };
        for unreachable in ["", "kbs.example:8080", "ftp://kbs.example", "https://"] {
            assert!(
                matches!(kbs(unreachable), Err(StatusCode::BAD_REQUEST)),
                "{unreachable}"
            );
        }
        for reachable in ["https://kbs.example:8080", "http://kbs.example"] {
            assert_eq!(
                kbs(reachable).is_ok(),
                !cfg!(feature = "sev-snp"),
                "{reachable}"
            );
        }
    }

    /// A webhook is kept only whole: an https endpoint, a Standard Webhooks
    /// secret, and a 32-byte key in hex.
    #[test]
    fn a_webhook_is_kept_only_whole() {
        let setup = |url: &str, secret: &str, pubkey: &str| WebhookSetup {
            url: url.into(),
            secret: secret.into(),
            pubkey: pubkey.into(),
        };
        let key = "ab".repeat(32);
        let k = key.as_str();
        let s = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        let kept = webhook(setup("https://hooks.example/enclavid?ref=1", s, k)).unwrap();
        assert_eq!(kept.url, "https://hooks.example/enclavid?ref=1");
        assert_eq!(kept.secret.len(), 24);
        assert_eq!(kept.pubkey, key);
        assert!(kept.id.starts_with("msg_") && kept.id.len() == 36);
        assert_ne!(
            kept.id,
            webhook(setup("https://hooks.example", s, k)).unwrap().id
        );
        // Kept as the hatch reads it.
        for (written, read) in [
            ("HTTPS://Hooks.Example/x", "https://hooks.example/x"),
            (
                "https://bücher.example/x",
                "https://xn--bcher-kva.example/x",
            ),
            ("https://hooks.example", "https://hooks.example/"),
        ] {
            assert_eq!(
                webhook(setup(written, s, k)).unwrap().url,
                read,
                "{written}"
            );
        }

        let not_hex = "zz".repeat(32);
        let too_long = format!("https://hooks.example/{}", "a".repeat(MAX_WEBHOOK_URL_LEN));
        for (url, secret, pubkey) in [
            ("hooks.example/enclavid", s, k),
            ("https://", s, k),
            ("https:///path", s, k),
            ("https:\\\\hooks.example/x", s, k),
            ("https://hooks.example/a b", s, k),
            ("https://hooks.ex\tample/x", s, k),
            ("ftp://hooks.example", s, k),
            (too_long.as_str(), s, k),
            (
                "https://hooks.example",
                "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
                k,
            ),
            ("https://hooks.example", "whsec_c2hvcnQ=", k),
            ("https://hooks.example", "whsec_!!!", k),
            ("https://hooks.example", s, "ab"),
            ("https://hooks.example", s, not_hex.as_str()),
        ] {
            assert_eq!(
                webhook(setup(url, secret, pubkey)).err(),
                Some(StatusCode::BAD_REQUEST),
                "{url} {secret} {pubkey}"
            );
        }
        assert_eq!(
            webhook(setup("http://hooks.example", s, k)).is_ok(),
            !cfg!(feature = "sev-snp")
        );
        assert_eq!(
            webhook(setup("https://127.0.0.1/hook", s, k)).is_ok(),
            !cfg!(feature = "sev-snp")
        );
    }

    /// A term asked for past the fleet's ceiling is the ceiling.
    #[test]
    fn a_term_past_its_ceiling_is_the_ceiling() {
        let asked = SessionTerms {
            components_bytes: Some(u64::MAX),
            cwasm_bytes: Some(u64::MAX),
            session_ttl_secs: Some(u64::MAX),
            pull_deadline_secs: Some(u64::MAX),
        };
        assert_eq!(
            held(asked, Some(3600), PULL),
            session_types::Terms {
                components_bytes: Some(engine_rpc::MAX_COMPONENTS_BYTES),
                cwasm_bytes: Some(engine_rpc::MAX_CWASM_BYTES),
                session_ttl_secs: Some(3600),
                pull_deadline_secs: Some(30),
            }
        );
    }

    /// A term asked for under its ceiling stands as asked; where the store keeps
    /// sessions with no end, any TTL asked for stands.
    #[test]
    fn a_term_under_its_ceiling_stands() {
        let asked = SessionTerms {
            components_bytes: Some(1),
            cwasm_bytes: Some(2),
            session_ttl_secs: Some(u64::MAX),
            pull_deadline_secs: Some(4),
        };
        assert_eq!(
            held(asked, None, PULL),
            session_types::Terms {
                components_bytes: Some(1),
                cwasm_bytes: Some(2),
                session_ttl_secs: Some(u64::MAX),
                pull_deadline_secs: Some(4),
            }
        );
    }

    /// A term not asked for stays the fleet's own: none is written into the
    /// session.
    #[test]
    fn a_term_not_asked_for_stays_the_fleets() {
        let asked = SessionTerms {
            components_bytes: None,
            cwasm_bytes: None,
            session_ttl_secs: None,
            pull_deadline_secs: None,
        };
        assert_eq!(
            held(asked, Some(3600), PULL),
            session_types::Terms::default()
        );
    }
}
