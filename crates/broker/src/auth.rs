//! Auth handler: validates the client `Authorization` header (Logto
//! JWTs for the MVP) and returns the tenant principal.
//!
//! The TEE forwards the raw header value + the intended operation; this
//! handler parses, verifies the signature against the issuer's JWKS
//! (cached), checks audience/expiration, and extracts `organization_id`
//! as the principal. Deny paths are HTTP 401 (bad credential) / 403
//! (valid but no org binding).
//!
//! For MVP, RBAC is "any org-scoped token is allowed for any operation";
//! per-operation gating lands later. The generic-OIDC refactor (move
//! verification into the TEE, broker becomes a JWKS fetcher) is a later
//! phase — this handler preserves the current host-validates behavior.

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

/// JWKS cache TTL. Logto rotates rarely; on cache miss we refetch.
const JWKS_CACHE_SECS: u64 = 600;

#[derive(Clone)]
pub struct AuthState {
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

impl AuthState {
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
}

/// POST /authorize
pub async fn authorize(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Vec<u8>, BrokerError> {
    let req: AuthorizeRequest = decode_body(&body)?;
    let auth = &state.auth;

    // RBAC for MVP: any org-scoped token is allowed for any operation.
    // Per-operation gating lands when scopes/roles are wired through the
    // org template in Logto.
    let _ = req.operation;

    let token = AuthState::extract_bearer(&req.authorization_header).ok_or_else(|| {
        debug!("authorize: no bearer token");
        BrokerError::Unauthorized
    })?;

    let header = decode_header(token).map_err(|_| BrokerError::Unauthorized)?;
    let kid = header.kid.ok_or(BrokerError::Unauthorized)?;

    auth.ensure_jwks().await?;

    let key = {
        let cache = auth.jwks.read().await;
        cache.keys.get(&kid).cloned()
    };
    let key = match key {
        Some(k) => k,
        None => {
            // Maybe the issuer rotated — force one refresh.
            warn!(kid = %kid, "kid not in cache, refetching jwks");
            {
                let mut cache = auth.jwks.write().await;
                cache.fetched_at = None;
            }
            auth.ensure_jwks().await?;
            let cache = auth.jwks.read().await;
            cache.keys.get(&kid).cloned().ok_or(BrokerError::Unauthorized)?
        }
    };

    // Algorithm taken from the token header (restricts to that single
    // alg, the safe default — don't accept a weaker alg than the JWKS
    // key was published for).
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[auth.issuer.as_str()]);
    validation.set_audience(&[auth.audience.as_str()]);

    let data = decode::<Claims>(token, &key, &validation).map_err(|e| {
        debug!(err = %e, "jwt validation failed");
        BrokerError::Unauthorized
    })?;

    let principal = match data.claims.organization_id {
        Some(s) if !s.is_empty() => s,
        _ => {
            debug!("authorize: token has no organization_id");
            return Err(BrokerError::Forbidden);
        }
    };

    encode_body(&AuthorizeResponse {
        principal: Some(principal),
    })
}
