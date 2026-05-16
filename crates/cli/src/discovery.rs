use anyhow::{Context, Result};
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
    CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalProviderMetadata, DeviceAuthorizationUrl, IssuerUrl, ProviderMetadata,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_DISCOVERY_URL: &str = "https://console.enclavid.com/api/cli-config";
const CACHE_TTL_SECS: u64 = 3600;

static DISCOVERY: OnceLock<Discovery> = OnceLock::new();

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceEndpointMetadata {
    pub device_authorization_endpoint: DeviceAuthorizationUrl,
}
impl AdditionalProviderMetadata for DeviceEndpointMetadata {}

pub type EnclavidProviderMetadata = ProviderMetadata<
    DeviceEndpointMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub struct Discovery {
    pub cli_client_id: String,
    pub registry_resource: String,
    /// OIDC scopes for login (identity flow).
    pub scopes: Vec<String>,
    /// Resource permissions to request when minting access tokens scoped
    /// to the Enclavid registry. Push CLI inserts these on the
    /// refresh_token grant so a Bearer can authenticate to our Angos.
    pub registry_scopes: Vec<String>,
    pub provider_metadata: EnclavidProviderMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CliConfig {
    issuer_url: String,
    cli_client_id: String,
    /// Registry hostname surfaced by the discovery endpoint. Kept as a
    /// deserialization-only field for forward compat with the cli-config
    /// payload — push no longer derives a default registry from
    /// discovery; the user supplies a full OCI ref.
    #[serde(default)]
    #[allow(dead_code)]
    registry_url: Option<String>,
    registry_resource: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default)]
    registry_scopes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct CachedCliConfig {
    fetched_at: u64,
    config: CliConfig,
}

/// Resolve and cache the full discovery.
/// cli-config: disk cache → remote → env-only fallback. Per-field env vars override on top.
/// OIDC metadata: fetched fresh every run (cheap, avoids cache invalidation when issuer changes).
pub async fn load() -> Result<()> {
    if DISCOVERY.get().is_some() {
        return Ok(());
    }

    let base = resolve_cli_config().await?;
    let provider_metadata = fetch_oidc_metadata(&base.issuer_url).await?;

    let discovery = Discovery {
        cli_client_id: base.cli_client_id,
        registry_resource: base.registry_resource,
        scopes: base.scopes,
        registry_scopes: base.registry_scopes,
        provider_metadata,
    };

    let _ = DISCOVERY.set(discovery);
    Ok(())
}

pub fn get() -> &'static Discovery {
    DISCOVERY
        .get()
        .expect("discovery::load() must be called before discovery::get()")
}

pub type HttpClient = openidconnect::reqwest::Client;

/// Build an async http client suitable for openidconnect requests.
pub fn http_client() -> Result<HttpClient> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .context("building http client")
}

async fn resolve_cli_config() -> Result<CliConfig> {
    if let Some(cached) = read_cached() {
        return Ok(apply_env_overrides(cached));
    }

    match fetch_remote_cli_config().await {
        Ok(cfg) => {
            let _ = write_cached(&cfg);
            Ok(apply_env_overrides(cfg))
        }
        Err(fetch_err) => {
            if let Some(cfg) = full_env_override() {
                Ok(cfg)
            } else {
                Err(fetch_err.context(
                    "discovery fetch failed and no full env override set; \
                     either ensure ENCLAVID_DISCOVERY URL is reachable or set all of \
                     ENCLAVID_ISSUER + ENCLAVID_CLI_CLIENT_ID + ENCLAVID_REGISTRY_RESOURCE",
                ))
            }
        }
    }
}

fn discovery_url() -> String {
    std::env::var("ENCLAVID_DISCOVERY").unwrap_or_else(|_| DEFAULT_DISCOVERY_URL.to_string())
}

fn default_scopes() -> Vec<String> {
    ["openid", "profile", "offline_access"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

fn full_env_override() -> Option<CliConfig> {
    let issuer_url = std::env::var("ENCLAVID_ISSUER").ok()?;
    let cli_client_id = std::env::var("ENCLAVID_CLI_CLIENT_ID").ok()?;
    let registry_resource = std::env::var("ENCLAVID_REGISTRY_RESOURCE").ok()?;
    let registry_scopes = std::env::var("ENCLAVID_REGISTRY_SCOPES")
        .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
        .unwrap_or_default();
    Some(CliConfig {
        issuer_url,
        cli_client_id,
        registry_url: None,
        registry_resource,
        scopes: default_scopes(),
        registry_scopes,
    })
}

fn apply_env_overrides(mut cfg: CliConfig) -> CliConfig {
    if let Ok(v) = std::env::var("ENCLAVID_ISSUER") {
        cfg.issuer_url = v;
    }
    if let Ok(v) = std::env::var("ENCLAVID_CLI_CLIENT_ID") {
        cfg.cli_client_id = v;
    }
    if let Ok(v) = std::env::var("ENCLAVID_REGISTRY_RESOURCE") {
        cfg.registry_resource = v;
    }
    cfg
}

fn cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("enclavid").join("cli-config.json"))
}

fn read_cached() -> Option<CliConfig> {
    let path = cache_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let cached: CachedCliConfig = serde_json::from_str(&content).ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(cached.fetched_at) > CACHE_TTL_SECS {
        return None;
    }
    Some(cached.config)
}

fn write_cached(cfg: &CliConfig) -> Result<()> {
    let Some(path) = cache_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cached = CachedCliConfig {
        fetched_at: now,
        config: cfg.clone(),
    };
    std::fs::write(&path, serde_json::to_string_pretty(&cached)?)?;
    Ok(())
}

async fn fetch_remote_cli_config() -> Result<CliConfig> {
    let url = discovery_url();
    let client = reqwest::Client::builder()
        .build()
        .context("building http client")?;
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("discovery {url} failed ({status}): {body}");
    }
    let mut cfg: CliConfig =
        serde_json::from_str(&body).with_context(|| format!("parsing discovery: {body}"))?;
    if cfg.scopes.is_empty() {
        cfg.scopes = default_scopes();
    }
    Ok(cfg)
}

async fn fetch_oidc_metadata(issuer_url: &str) -> Result<EnclavidProviderMetadata> {
    let issuer = IssuerUrl::new(issuer_url.to_string())
        .with_context(|| format!("invalid issuer URL: {issuer_url}"))?;
    let http = http_client()?;
    EnclavidProviderMetadata::discover_async(issuer, &http)
        .await
        .with_context(|| format!("OIDC discovery from {issuer_url}"))
}
