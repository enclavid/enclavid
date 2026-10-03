//! Auth handler: resolves the client `Authorization` header to a tenant
//! principal. Two modes, selected by `HATCH_AUTH` (required, fail-loud):
//!
//!   * `HATCH_AUTH=oidc` — production. Verifies client JWTs (Logto for
//!     the MVP) against the issuer's JWKS (cached), found at the
//!     `jwks_uri` of its OpenID Connect discovery document, checks
//!     audience/expiration, and extracts `organization_id` as the
//!     principal. Requires `HATCH_AUTH_OIDC_ISSUER` +
//!     `HATCH_AUTH_OIDC_AUDIENCE`.
//!   * `HATCH_AUTH=none` — **dev only**. Skips all verification and
//!     attributes every request to a fixed `HATCH_AUTH_PRINCIPAL`. Must
//!     be opted into explicitly — it is never the default, never
//!     inferred. Lets the local stack run without Logto.
//!
//! Either way the hatch's verdict is hatch-supplied and TEE-side
//! defence-in-depth only: the real access anchor is the
//! `client_session_token` hash, which the TEE checks itself and the host
//! never sees (TLS-in-TEE). So `none` weakens nothing the TEE relies on
//! cryptographically — it just hands back a fixed tenant in dev.
//!
//! Deny paths are HTTP 401 (bad credential) / 403 (valid but no org
//! binding) in oidc mode, and in either mode 429 when the principal is over
//! its rate limit for the operation (see `rate_limit`). Any org-scoped token
//! may perform any operation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use reqwest::redirect::Policy;
use serde::Deserialize;
use tokio::sync::{Notify, watch};
use tokio::time::Instant;
use tracing::{debug, warn};

use hatch_protocol::{AuthorizeRequest, AuthorizeResponse};

use crate::AppState;
use crate::error::{HatchError, decode_body, encode_body};
use crate::required_env;

/// How long after a fetch the key set is fetched again. A set is used until
/// another replaces it, however old: with the issuer out of reach, tokens it
/// signed with keys the hatch holds are still checked, and a key it has since
/// withdrawn is still taken.
const JWKS_TTL: Duration = Duration::from_secs(600);

/// The least time between two fetches of the key set. Once the held set is
/// this old, a kid it lacks — a key the issuer may have rotated in since — has
/// it fetched again, and a failed fetch is tried again after this long. So
/// tokens naming made-up keys, however many and however they end, cost the
/// issuer one fetch per this long, and a key rotated in is taken within it.
const REFETCH_AFTER: Duration = Duration::from_secs(60);

/// Bounds on each fetch from the issuer. Mirrors the pair in `kds`. `timeout`
/// covers the whole request including connect, so one fetch costs at most
/// `REQUEST_TIMEOUT`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a caller waits for a key set it needs: the first — the discovery
/// document and the set, one fetch each — or one fetched for a kid the held
/// set lacks. A guest's `/authorize` blocks on this, and the guest puts a
/// deadline of its own over the whole exchange, which this has to clear: left
/// to that deadline, a slow issuer would surface as the TEE failing rather than
/// as keys that did not come.
const KEYS_WAIT: Duration = Duration::from_secs(2 * REQUEST_TIMEOUT.as_secs());

/// Auth verification mode, selected by `HATCH_AUTH`.
#[derive(Clone)]
pub enum AuthState {
    /// Production: verify client JWTs against the issuer's JWKS.
    Oidc(OidcAuth),
    /// Dev only (`HATCH_AUTH=none`): skip verification, return a fixed
    /// principal. Explicit opt-in — never inferred.
    None { principal: String },
}

impl AuthState {
    /// Build from `HATCH_AUTH` (required — fail-loud if unset). See the
    /// module docs for the full env matrix. The insecure `none` mode can
    /// only be reached by an exact `HATCH_AUTH=none`; an unset or
    /// unknown value is a hard error, so dev auth can never be selected
    /// by accident.
    pub fn from_env() -> anyhow::Result<Self> {
        let mode = required_env("HATCH_AUTH")
            .map_err(|_| anyhow::anyhow!("env var HATCH_AUTH is required (`oidc` | `none`)"))?;
        match mode.as_str() {
            "oidc" => {
                if std::env::var("HATCH_AUTH_PRINCIPAL").is_ok() {
                    anyhow::bail!(
                        "HATCH_AUTH=oidc but HATCH_AUTH_PRINCIPAL is set — \
                         the fixed principal only applies to HATCH_AUTH=none; unset it"
                    );
                }
                let issuer = required_env("HATCH_AUTH_OIDC_ISSUER")?;
                let audience = required_env("HATCH_AUTH_OIDC_AUDIENCE")?;
                Ok(AuthState::Oidc(OidcAuth::new(issuer, audience)))
            }
            "none" => {
                for forbidden in ["HATCH_AUTH_OIDC_ISSUER", "HATCH_AUTH_OIDC_AUDIENCE"] {
                    if std::env::var(forbidden).is_ok() {
                        anyhow::bail!(
                            "HATCH_AUTH=none but {forbidden} is set — \
                             OIDC config is ignored in dev auth mode; unset it"
                        );
                    }
                }
                let principal = required_env("HATCH_AUTH_PRINCIPAL")?;
                if principal.is_empty() {
                    anyhow::bail!("HATCH_AUTH_PRINCIPAL must be non-empty");
                }
                warn!(
                    principal = %principal,
                    "HATCH_AUTH=none — credential verification DISABLED, every \
                     request attributed to this principal (dev only)"
                );
                Ok(AuthState::None { principal })
            }
            other => anyhow::bail!("unknown HATCH_AUTH={other:?}, expected `oidc` or `none`"),
        }
    }
}

#[derive(Clone)]
pub struct OidcAuth {
    issuer: String,
    audience: String,
    /// What `keep_keys` holds, and when its last try failed.
    held: watch::Receiver<Held>,
    /// Asks `keep_keys` for the set again, for a kid the held one lacks.
    wanted: Arc<Notify>,
}

#[derive(Clone, Default)]
struct Held {
    /// The issuer's keys as last fetched; `None` before a fetch succeeds.
    set: Option<Arc<KeySet>>,
    /// When the last try failed, if it did.
    failed_at: Option<Instant>,
}

/// The issuer's keys by kid, and when they were fetched.
struct KeySet {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

/// A JWK set read key by key, so a key the verifier cannot read leaves the
/// rest standing.
#[derive(Deserialize)]
struct KeysDocument {
    keys: Vec<serde_json::Value>,
}

/// The part of an OpenID Connect discovery document the hatch reads.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    /// Logto org-scoped tokens carry this when minted with
    /// `organization_id`. Required for all client operations.
    organization_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    sub: Option<String>,
}

impl OidcAuth {
    /// Starts the task that keeps the issuer's keys, for the process's life.
    pub fn new(issuer: String, audience: String) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            // The keys are what every client token is checked against: taken
            // from where the issuer's document says, and from nowhere an
            // answer would send the hatch on to.
            .redirect(Policy::none())
            .build()
            .expect("reqwest client");
        let (sender, held) = watch::channel(Held::default());
        let wanted = Arc::new(Notify::new());
        tokio::spawn(keep_keys(issuer.clone(), http, sender, wanted.clone()));
        Self {
            issuer,
            audience,
            held,
            wanted,
        }
    }

    /// The key `kid` names. A kid the held set lacks may be one the issuer has
    /// rotated in since: once the set is `REFETCH_AFTER` old, it is asked for
    /// again and the caller waits for it, as it waits for the first set. No
    /// try comes within `REFETCH_AFTER` of a failed one, so after a failure
    /// the caller is answered at once from what is held.
    async fn key(&self, kid: &str) -> Result<DecodingKey, HatchError> {
        let mut watched = self.held.clone();
        let mut held = watched.borrow_and_update().clone();
        if let Some(key) = held.set.as_ref().and_then(|set| set.keys.get(kid)) {
            return Ok(key.clone());
        }
        let lately = |t: Instant| t.elapsed() < REFETCH_AFTER;
        let fetched_lately = held.set.as_ref().is_some_and(|set| lately(set.fetched_at));
        if !fetched_lately && !held.failed_at.is_some_and(lately) {
            if held.set.is_some() {
                debug!(kid = %kid, "kid not in the key set; asking for the set again");
                self.wanted.notify_one();
            }
            // Answered from what there is then: a new set, the same one after
            // a failed fetch, or, past the wait, whatever is held.
            let _ = tokio::time::timeout(KEYS_WAIT, watched.changed()).await;
            held = watched.borrow().clone();
        }
        match held.set {
            Some(set) => set.keys.get(kid).cloned().ok_or(HatchError::Unauthorized),
            None => Err(HatchError::Internal(
                "no key set from the issuer yet".into(),
            )),
        }
    }

    fn extract_bearer(authorization_header: &str) -> Option<&str> {
        let s = authorization_header.trim();
        s.strip_prefix("Bearer ")
            .or_else(|| s.strip_prefix("bearer "))
    }

    /// Verify the request's bearer token and return its principal.
    async fn verify(&self, req: &AuthorizeRequest) -> Result<String, HatchError> {
        let token = Self::extract_bearer(&req.authorization_header).ok_or_else(|| {
            debug!("authorize: no bearer token");
            HatchError::Unauthorized
        })?;

        let header = decode_header(token).map_err(|_| HatchError::Unauthorized)?;
        let kid = header.kid.ok_or(HatchError::Unauthorized)?;

        let key = self.key(&kid).await?;

        // Algorithm taken from the token header (restricts to that single
        // alg, the safe default — don't accept a weaker alg than the JWKS
        // key was published for).
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);

        let data = decode::<Claims>(token, &key, &validation).map_err(|e| {
            debug!(err = %e, "jwt validation failed");
            HatchError::Unauthorized
        })?;

        match data.claims.organization_id {
            Some(s) if !s.is_empty() => Ok(s),
            _ => {
                debug!("authorize: token has no organization_id");
                Err(HatchError::Forbidden)
            }
        }
    }
}

/// Keeps the issuer's key set in `held`: fetches it at once, then again
/// `JWKS_TTL` after each fetch, or sooner when a caller wants a kid the set
/// lacks — but never within `REFETCH_AFTER` of the last try. A failed fetch
/// leaves the held set in place, and says when it failed. Every fetch runs
/// here: a caller only waits on `held`, so one that goes away neither cuts a
/// fetch short nor brings on another.
async fn keep_keys(
    issuer: String,
    http: reqwest::Client,
    held: watch::Sender<Held>,
    wanted: Arc<Notify>,
) {
    let mut jwks_uri = None;
    while !held.is_closed() {
        let next = match fetch(&issuer, &http, &mut jwks_uri).await {
            Ok(keys) => {
                debug!(keys = keys.len(), "fetched the issuer's key set");
                held.send_replace(Held {
                    set: Some(Arc::new(KeySet {
                        keys,
                        fetched_at: Instant::now(),
                    })),
                    failed_at: None,
                });
                JWKS_TTL
            }
            Err(e) => {
                warn!(err = %e, "the issuer's key set was not fetched; the held one stays");
                held.send_modify(|held| held.failed_at = Some(Instant::now()));
                REFETCH_AFTER
            }
        };
        let tried = Instant::now();
        tokio::time::sleep_until(tried + REFETCH_AFTER).await;
        tokio::select! {
            () = tokio::time::sleep_until(tried + next) => {}
            () = wanted.notified() => {}
        }
    }
}

/// The issuer's keys by kid, from the `jwks_uri` its discovery document
/// names — the document read once, and kept. A key the verifier cannot read,
/// one for encryption, or one without a kid is left out; the rest stand.
async fn fetch(
    issuer: &str,
    http: &reqwest::Client,
    jwks_uri: &mut Option<String>,
) -> anyhow::Result<HashMap<String, DecodingKey>> {
    let uri = match jwks_uri.clone() {
        Some(uri) => uri,
        None => jwks_uri.insert(discover(issuer, http).await?).clone(),
    };
    let document: KeysDocument = http
        .get(&uri)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(document
        .keys
        .into_iter()
        .filter_map(|key| serde_json::from_value::<Jwk>(key).ok())
        .filter(|jwk| !matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)))
        .filter_map(|jwk| {
            Some((
                jwk.common.key_id.clone()?,
                DecodingKey::from_jwk(&jwk).ok()?,
            ))
        })
        .collect())
}

/// The `jwks_uri` of the issuer's OpenID Connect discovery document. The
/// document is taken only for the issuer it was fetched from — it must name
/// exactly that issuer (OpenID Connect Discovery 1.0, section 4.3) — and the
/// keys only under the issuer's own scheme.
async fn discover(issuer: &str, http: &reqwest::Client) -> anyhow::Result<String> {
    let at = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let doc: Discovery = http
        .get(&at)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    anyhow::ensure!(
        doc.issuer == issuer,
        "discovery at {at} is for issuer {:?}",
        doc.issuer
    );
    let scheme = |uri: &str| url::Url::parse(uri).map(|uri| uri.scheme().to_owned());
    anyhow::ensure!(
        scheme(&doc.jwks_uri)? == scheme(issuer)?,
        "discovery at {at} puts the keys under another scheme: {}",
        doc.jwks_uri
    );
    Ok(doc.jwks_uri)
}

/// POST /authorize
pub async fn authorize(State(state): State<AppState>, body: Bytes) -> Result<Vec<u8>, HatchError> {
    let req: AuthorizeRequest = decode_body(&body)?;

    // Any org-scoped token may perform any operation, within the rate limit.
    let principal = match &state.auth {
        // Dev: no verification, fixed tenant. The empty/dummy bearer the
        // client sends is ignored — there is nothing to validate against.
        AuthState::None { principal } => principal.clone(),
        AuthState::Oidc(oidc) => oidc.verify(&req).await?,
    };
    state
        .rate_limits
        .check(&principal, req.operation)
        .map_err(HatchError::RateLimited)?;

    encode_body(&AuthorizeResponse {
        principal: Some(principal),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::Json;
    use axum::routing::get;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::{Value, json};

    use hatch_protocol::ClientOperation;

    use super::*;

    const SECRET: &[u8] = b"hatch-test-key-hatch-test-key-32";
    /// `SECRET` as a JWK's `k`: base64url, unpadded.
    const SECRET_K: &str = "aGF0Y2gtdGVzdC1rZXktaGF0Y2gtdGVzdC1rZXktMzI";
    const AUDIENCE: &str = "https://api.example.test";

    /// A discovery document naming the issuer at `base`, with its keys at a
    /// path no guess off the issuer would reach.
    fn own(base: &str) -> Value {
        json!({ "issuer": base, "jwks_uri": format!("{base}/elsewhere/keys") })
    }

    /// An issuer on a loopback port, whose discovery document is `doc` of its
    /// address. Its key set holds `k1`, and from its second fetch on `k2` too,
    /// as if rotated in; each fetch takes a moment, so callers at once overlap
    /// it, and from fetch `fail_from` on it answers 500. Returns its address
    /// and a count of the fetches of its keys.
    async fn issuer(doc: fn(&str) -> Value, fail_from: usize) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let doc = doc(&base);
        let fetches = Arc::new(AtomicUsize::new(0));
        let counted = fetches.clone();
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let doc = doc.clone();
                    async move { Json(doc) }
                }),
            )
            .route(
                "/elsewhere/keys",
                get(move || {
                    let before = counted.fetch_add(1, Ordering::SeqCst);
                    async move {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if before >= fail_from {
                            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                        }
                        let key = |kid| json!({ "kty": "oct", "kid": kid, "k": SECRET_K });
                        let mut keys = vec![
                            key("k1"),
                            // Beside them, a key the verifier cannot read and
                            // one for encryption, which no token checks out on.
                            json!({ "kty": "EC", "crv": "secp256k1", "kid": "odd", "x": "AA", "y": "AA" }),
                            json!({ "kty": "oct", "kid": "enc", "use": "enc", "k": SECRET_K }),
                        ];
                        if before > 0 {
                            keys.push(key("k2"));
                        }
                        Ok(Json(json!({ "keys": keys })))
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, fetches)
    }

    /// Moves the clock on by `by`, without the minutes passing: the held set
    /// ages, and the task keeping it wakes as it would then.
    async fn age(by: Duration) {
        tokio::time::pause();
        tokio::time::advance(by).await;
        tokio::time::resume();
    }

    /// Waits, a little at a time, until the issuer has had `n` fetches.
    async fn fetched(fetches: &AtomicUsize, n: usize) {
        while fetches.load(Ordering::SeqCst) < n {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A request carrying a token `issuer` would issue, signed with `SECRET`
    /// and naming the key `kid`.
    fn bearer(issuer: &str, kid: &str) -> AuthorizeRequest {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let claims =
            json!({ "iss": issuer, "aud": AUDIENCE, "exp": exp, "organization_id": "org-1" });
        let header = Header {
            kid: Some(kid.into()),
            ..Header::new(Algorithm::HS256)
        };
        let token = encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap();
        AuthorizeRequest {
            authorization_header: format!("Bearer {token}"),
            operation: ClientOperation::SessionCreate,
        }
    }

    #[tokio::test]
    async fn keys_come_from_where_the_discovery_document_says() {
        let (base, fetches) = issuer(own, usize::MAX).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        assert_eq!(oidc.verify(&bearer(&base, "k1")).await.unwrap(), "org-1");
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    /// A key the verifier cannot read is left out without the set, and a key
    /// for encryption checks no token.
    #[tokio::test]
    async fn keys_it_cannot_read_or_for_encryption_are_left_out() {
        let (base, _) = issuer(own, usize::MAX).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        assert_eq!(oidc.verify(&bearer(&base, "k1")).await.unwrap(), "org-1");
        assert!(matches!(
            oidc.verify(&bearer(&base, "enc")).await,
            Err(HatchError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn a_discovery_document_naming_another_issuer_is_refused() {
        let elsewhere = |base: &str| {
            json!({
                "issuer": "https://elsewhere.example.test",
                "jwks_uri": format!("{base}/elsewhere/keys"),
            })
        };
        let (base, fetches) = issuer(elsewhere, usize::MAX).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        assert!(matches!(
            oidc.verify(&bearer(&base, "k1")).await,
            Err(HatchError::Internal(_))
        ));
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            0,
            "no keys from where it points"
        );
    }

    #[tokio::test]
    async fn keys_under_another_scheme_than_the_issuer_are_refused() {
        let https = |base: &str| {
            let at = base.replace("http://", "https://");
            json!({ "issuer": base, "jwks_uri": format!("{at}/elsewhere/keys") })
        };
        let (base, fetches) = issuer(https, usize::MAX).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        assert!(matches!(
            oidc.verify(&bearer(&base, "k1")).await,
            Err(HatchError::Internal(_))
        ));
        assert_eq!(fetches.load(Ordering::SeqCst), 0);
    }

    /// A kid the set lacks is fetched again for only once the set is older
    /// than `REFETCH_AFTER`: made-up kids cost the issuer nothing until then,
    /// and a key rotated in is taken after.
    #[tokio::test]
    async fn an_unknown_kid_is_fetched_again_for_once_the_set_has_aged() {
        let (base, fetches) = issuer(own, usize::MAX).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        for kid in ["k1", "made-up", "made-up", "k2"] {
            let verdict = oidc.verify(&bearer(&base, kid)).await;
            assert_eq!(verdict.is_ok(), kid == "k1", "{kid}");
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        age(REFETCH_AFTER + Duration::from_secs(1)).await;
        assert_eq!(oidc.verify(&bearer(&base, "k2")).await.unwrap(), "org-1");
        assert!(matches!(
            oidc.verify(&bearer(&base, "made-up")).await,
            Err(HatchError::Unauthorized)
        ));
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn callers_at_once_share_one_fetch() {
        let (base, fetches) = issuer(own, usize::MAX).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        let mut callers = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (oidc, req) = (oidc.clone(), bearer(&base, "k1"));
            callers.spawn(async move { oidc.verify(&req).await.unwrap() });
        }
        while let Some(principal) = callers.join_next().await {
            assert_eq!(principal.unwrap(), "org-1");
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    /// Made-up kids from callers that go away mid-wait — however many, and
    /// however they end — still cost the issuer one fetch per `REFETCH_AFTER`.
    #[tokio::test]
    async fn made_up_kids_cost_one_fetch_however_their_callers_end() {
        let (base, fetches) = issuer(own, usize::MAX).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        oidc.verify(&bearer(&base, "k1")).await.unwrap();
        age(REFETCH_AFTER + Duration::from_secs(1)).await;
        for _ in 0..20 {
            let caller = tokio::spawn({
                let (oidc, req) = (oidc.clone(), bearer(&base, "made-up"));
                async move { oidc.verify(&req).await }
            });
            tokio::time::sleep(Duration::from_millis(5)).await;
            caller.abort();
        }
        fetched(&fetches, 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    /// A fetch that fails leaves the held set in use: the issuer down for a
    /// moment refuses no token the hatch could already check.
    #[tokio::test]
    async fn a_failed_fetch_keeps_the_held_set() {
        let (base, fetches) = issuer(own, 1).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        oidc.verify(&bearer(&base, "k1")).await.unwrap();
        age(JWKS_TTL + Duration::from_secs(1)).await;
        fetched(&fetches, 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(oidc.verify(&bearer(&base, "k1")).await.unwrap(), "org-1");
        // No try comes for a while after the failed one, so a kid the set
        // lacks is refused at once rather than waited on.
        let verdict = at_once(oidc.verify(&bearer(&base, "made-up"))).await;
        assert!(matches!(verdict, Err(HatchError::Unauthorized)));
    }

    /// With no set, a failed fetch is the answer at once — to a caller
    /// waiting on it, and to one that comes after.
    #[tokio::test]
    async fn with_no_set_a_failed_fetch_is_answered_at_once() {
        let (base, _) = issuer(own, 0).await;
        let oidc = OidcAuth::new(base.clone(), AUDIENCE.into());
        for _ in 0..2 {
            let verdict = at_once(oidc.verify(&bearer(&base, "k1"))).await;
            assert!(matches!(verdict, Err(HatchError::Internal(_))));
        }
    }

    /// `answer`, which must come well inside `KEYS_WAIT`.
    async fn at_once<T>(answer: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(2), answer)
            .await
            .expect("answered well inside KEYS_WAIT")
    }
}
