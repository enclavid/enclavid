//! Auth handler: resolves the client `Authorization` header to a tenant
//! principal. Two modes, selected by `BROKER_AUTH` (required, fail-loud):
//!
//!   * `BROKER_AUTH=oidc` — production. Verifies client JWTs (Logto for
//!     the MVP) against the issuer's JWKS (cached), checks
//!     audience/expiration, and extracts `organization_id` as the
//!     principal. Requires `BROKER_AUTH_OIDC_ISSUER` +
//!     `BROKER_AUTH_OIDC_AUDIENCE`.
//!   * `BROKER_AUTH=none` — **dev only**. Skips all verification and
//!     attributes every request to a fixed `BROKER_AUTH_PRINCIPAL`. Must
//!     be opted into explicitly — it is never the default, never
//!     inferred. Lets the local stack run without Logto.
//!
//! Either way the broker's verdict is broker-supplied and TEE-side
//! defence-in-depth only: the real access anchor is the
//! `client_session_token` hash, which the TEE checks itself and the host
//! never sees (TLS-in-TEE). So `none` weakens nothing the TEE relies on
//! cryptographically — it just hands back a fixed tenant in dev.
//!
//! Deny paths (oidc mode) are HTTP 401 (bad credential) / 403 (valid but
//! no org binding). For MVP, RBAC is "any org-scoped token is allowed for
//! any operation"; per-operation gating lands later.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use broker_protocol::{AuthorizeRequest, AuthorizeResponse};

use crate::AppState;
use crate::error::{BrokerError, decode_body, encode_body};
use crate::required_env;

/// JWKS cache TTL. Logto rotates rarely; on cache miss we refetch.
const JWKS_CACHE_SECS: u64 = 600;

/// Auth verification mode, selected by `BROKER_AUTH`.
#[derive(Clone)]
pub enum AuthState {
    /// Production: verify client JWTs against the issuer's JWKS.
    Oidc(OidcAuth),
    /// Dev only (`BROKER_AUTH=none`): skip verification, return a fixed
    /// principal. Explicit opt-in — never inferred.
    None { principal: String },
}

impl AuthState {
    /// Build from `BROKER_AUTH` (required — fail-loud if unset). See the
    /// module docs for the full env matrix. The insecure `none` mode can
    /// only be reached by an exact `BROKER_AUTH=none`; an unset or
    /// unknown value is a hard error, so dev auth can never be selected
    /// by accident.
    pub fn from_env() -> anyhow::Result<Self> {
        let mode = required_env("BROKER_AUTH")
            .map_err(|_| anyhow::anyhow!("env var BROKER_AUTH is required (`oidc` | `none`)"))?;
        match mode.as_str() {
            "oidc" => {
                if std::env::var("BROKER_AUTH_PRINCIPAL").is_ok() {
                    anyhow::bail!(
                        "BROKER_AUTH=oidc but BROKER_AUTH_PRINCIPAL is set — \
                         the fixed principal only applies to BROKER_AUTH=none; unset it"
                    );
                }
                let issuer = required_env("BROKER_AUTH_OIDC_ISSUER")?;
                let audience = required_env("BROKER_AUTH_OIDC_AUDIENCE")?;
                Ok(AuthState::Oidc(OidcAuth::new(issuer, audience)))
            }
            "none" => {
                for forbidden in ["BROKER_AUTH_OIDC_ISSUER", "BROKER_AUTH_OIDC_AUDIENCE"] {
                    if std::env::var(forbidden).is_ok() {
                        anyhow::bail!(
                            "BROKER_AUTH=none but {forbidden} is set — \
                             OIDC config is ignored in dev auth mode; unset it"
                        );
                    }
                }
                let principal = required_env("BROKER_AUTH_PRINCIPAL")?;
                if principal.is_empty() {
                    anyhow::bail!("BROKER_AUTH_PRINCIPAL must be non-empty");
                }
                warn!(
                    principal = %principal,
                    "BROKER_AUTH=none — credential verification DISABLED, every \
                     request attributed to this principal (dev only)"
                );
                Ok(AuthState::None { principal })
            }
            other => anyhow::bail!("unknown BROKER_AUTH={other:?}, expected `oidc` or `none`"),
        }
    }
}

#[derive(Clone)]
pub struct OidcAuth {
    issuer: String,
    audience: String,
    jwks: Arc<RwLock<JwksCache>>,
    http: reqwest::Client,
}

#[derive(Default)]
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
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
    pub fn new(issuer: String, audience: String) -> Self {
        Self {
            issuer,
            audience,
            jwks: Arc::new(RwLock::new(JwksCache::default())),
            http: reqwest::Client::builder().build().expect("reqwest client"),
        }
    }

    async fn ensure_jwks(&self) -> Result<(), BrokerError> {
        let needs_refresh = {
            let cache = self.jwks.read().await;
            match cache.fetched_at {
                Some(t) if t.elapsed() < Duration::from_secs(JWKS_CACHE_SECS) => false,
                _ => true,
            }
        };
        if !needs_refresh {
            return Ok(());
        }

        let url = format!("{}/jwks", self.issuer.trim_end_matches('/'));
        let resp: JwkSet = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| BrokerError::Internal(format!("fetch jwks: {e}")))?
            .json()
            .await
            .map_err(|e| BrokerError::Internal(format!("parse jwks: {e}")))?;

        let mut keys = HashMap::new();
        for jwk in resp.keys.iter() {
            if let Some(kid) = &jwk.common.key_id {
                if let Ok(key) = DecodingKey::from_jwk(jwk) {
                    keys.insert(kid.clone(), key);
                }
            }
        }

        let mut cache = self.jwks.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        debug!(jwks_count = cache.keys.len(), "refreshed jwks cache");
        Ok(())
    }

    fn extract_bearer(authorization_header: &str) -> Option<&str> {
        let s = authorization_header.trim();
        s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer "))
    }

    /// Verify the request's bearer token and return its principal.
    async fn verify(&self, req: &AuthorizeRequest) -> Result<String, BrokerError> {
        let token = Self::extract_bearer(&req.authorization_header).ok_or_else(|| {
            debug!("authorize: no bearer token");
            BrokerError::Unauthorized
        })?;

        let header = decode_header(token).map_err(|_| BrokerError::Unauthorized)?;
        let kid = header.kid.ok_or(BrokerError::Unauthorized)?;

        self.ensure_jwks().await?;

        let key = {
            let cache = self.jwks.read().await;
            cache.keys.get(&kid).cloned()
        };
        let key = match key {
            Some(k) => k,
            None => {
                // Maybe the issuer rotated — force one refresh.
                warn!(kid = %kid, "kid not in cache, refetching jwks");
                {
                    let mut cache = self.jwks.write().await;
                    cache.fetched_at = None;
                }
                self.ensure_jwks().await?;
                let cache = self.jwks.read().await;
                cache.keys.get(&kid).cloned().ok_or(BrokerError::Unauthorized)?
            }
        };

        // Algorithm taken from the token header (restricts to that single
        // alg, the safe default — don't accept a weaker alg than the JWKS
        // key was published for).
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);

        let data = decode::<Claims>(token, &key, &validation).map_err(|e| {
            debug!(err = %e, "jwt validation failed");
            BrokerError::Unauthorized
        })?;

        match data.claims.organization_id {
            Some(s) if !s.is_empty() => Ok(s),
            _ => {
                debug!("authorize: token has no organization_id");
                Err(BrokerError::Forbidden)
            }
        }
    }
}

/// POST /authorize
pub async fn authorize(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Vec<u8>, BrokerError> {
    let req: AuthorizeRequest = decode_body(&body)?;

    // RBAC for MVP: any org-scoped token is allowed for any operation.
    // Per-operation gating lands when scopes/roles are wired through the
    // org template in Logto.
    let _ = req.operation;

    let principal = match &state.auth {
        // Dev: no verification, fixed tenant. The empty/dummy bearer the
        // client sends is ignored — there is nothing to validate against.
        AuthState::None { principal } => principal.clone(),
        AuthState::Oidc(oidc) => oidc.verify(&req).await?,
    };

    encode_body(&AuthorizeResponse {
        principal: Some(principal),
    })
}
