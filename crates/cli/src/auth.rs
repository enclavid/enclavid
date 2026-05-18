use anyhow::{Context, Result};
use base64::Engine;
use openidconnect::core::CoreClient;
use openidconnect::{ClientId, ClientSecret, OAuth2TokenResponse, RefreshToken, Scope};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{config, discovery};

/// 60-second grace period: refresh slightly early so a token doesn't expire mid-request.
const EXPIRY_GRACE_SECS: u64 = 60;

/// Override the active workspace via environment, useful in CI where
/// an interactive picker would hang. Wins over `active_workspace_id`
/// in the cached `StoredTokens`.
pub const ENV_WORKSPACE_ID: &str = "ENCLAVID_WORKSPACE_ID";

/// Raw Bearer override for API calls — bypasses the entire Logto
/// flow (device login / refresh / M2M). Sessions / `cloud token`
/// return this verbatim when set. Intended for lightweight dev
/// stacks (no Logto running) and for pre-minted tokens supplied by
/// an external tool. Treat the string as opaque; CLI never parses.
pub const ENV_API_TOKEN: &str = "ENCLAVID_API_TOKEN";

/// Logto-specific id_token claim listing the orgs the user belongs
/// to with names. Populated when `urn:logto:scope:organization_data`
/// is requested at login.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Workspace {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct StoredTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// id_token from device flow — kept for inspection / debugging,
    /// also re-parsed on every login to refresh the workspaces list.
    #[serde(default)]
    pub id_token: Option<String>,
    pub expires_at: u64,
    /// Workspaces the user belongs to (id + name). Snapshot from
    /// the most recent `enclavid cloud login`; `enclavid cloud
    /// workspace list` reads this without a network call. Refreshed
    /// on each login.
    #[serde(default)]
    pub workspaces: Vec<Workspace>,
    /// Active workspace id (the Logto `organization_id` that gets
    /// pinned in subsequent token mints). `enclavid cloud workspace
    /// use ...` writes this; cred helper reads it; gate for
    /// `enclavid policy push` ending up in the right registry
    /// namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_workspace_id: Option<String>,
}

/// Resolve a usable access token from any available source.
///
/// Priority:
/// 1. `ENCLAVID_API_TOKEN` env — used verbatim, no Logto round-trip
///    (dev mode / pre-minted token).
/// 2. Env-var client_credentials (`ENCLAVID_CLIENT_ID`/`_SECRET`) — CI.
/// 3. Tokens stored on disk by `enclavid cloud login`. Auto-refreshed
///    when expired.
/// 4. Error: not authenticated.
pub async fn get_access_token() -> Result<String> {
    if let Ok(t) = std::env::var(ENV_API_TOKEN)
        && !t.is_empty()
    {
        return Ok(t);
    }
    if let (Some(id), Some(secret)) = (config::client_id(), config::client_secret()) {
        return client_credentials_grant(id, secret).await;
    }

    match load_from_disk().await? {
        Some(token) => Ok(token),
        None => anyhow::bail!(
            "not authenticated — run `enclavid cloud login` for interactive auth, \
             set ENCLAVID_CLIENT_ID + ENCLAVID_CLIENT_SECRET for CI, \
             or {ENV_API_TOKEN}=<jwt> for a pre-minted token",
        ),
    }
}

/// Resolve the active workspace id from any available source.
///
/// Priority:
/// 1. `ENCLAVID_WORKSPACE_ID` env var (CI escape hatch).
/// 2. `active_workspace_id` in `StoredTokens` (set by `enclavid cloud login`
///    or `enclavid cloud workspace use ...`).
/// 3. Error: workspace not selected.
///
/// Called by the cred helper to scope the refresh_token grant to the
/// right Logto organization.
pub fn active_workspace_id() -> Result<String> {
    if let Ok(v) = std::env::var(ENV_WORKSPACE_ID)
        && !v.is_empty()
    {
        return Ok(v);
    }
    let tokens = read_stored_tokens()?
        .context("not authenticated — run `enclavid cloud login` first")?;
    tokens.active_workspace_id.ok_or_else(|| {
        anyhow::anyhow!(
            "no active workspace — run `enclavid cloud login` to pick one, \
             or set {ENV_WORKSPACE_ID}",
        )
    })
}

/// Read the entire StoredTokens record from disk, if present.
pub fn read_stored_tokens() -> Result<Option<StoredTokens>> {
    let path = auth_path()?;
    let buf = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let tokens: StoredTokens = serde_json::from_str(&buf)
        .with_context(|| format!("parsing {} as StoredTokens", path.display()))?;
    Ok(Some(tokens))
}

/// Remove the locally-stored auth file. Returns whether a file was removed.
pub fn clear_tokens() -> Result<bool> {
    let path = auth_path()?;
    match std::fs::remove_file(&path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Persist tokens to a 0600 file under the user config directory.
pub fn store_tokens(tokens: &StoredTokens) -> Result<()> {
    let path = auth_path().context("resolving auth file path")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;

    let serialized = serde_json::to_vec(tokens).context("serializing tokens")?;
    file.write_all(&serialized).context("writing auth file")?;
    Ok(())
}

async fn load_from_disk() -> Result<Option<String>> {
    let Some(tokens) = read_stored_tokens()? else {
        return Ok(None);
    };

    if tokens.expires_at > now_secs() + EXPIRY_GRACE_SECS {
        return Ok(Some(tokens.access_token));
    }

    let Some(refresh_token) = tokens.refresh_token.clone() else {
        anyhow::bail!(
            "stored access token expired and no refresh_token available — \
             please run `enclavid login` again"
        );
    };

    match refresh_access_token(&refresh_token).await {
        Ok(refreshed) => {
            let mut updated = tokens;
            updated.access_token = refreshed.access_token;
            if refreshed.refresh_token.is_some() {
                updated.refresh_token = refreshed.refresh_token;
            }
            updated.expires_at = refreshed.expires_at;
            // id_token preserved from existing record
            store_tokens(&updated)?;
            Ok(Some(updated.access_token))
        }
        Err(e) => anyhow::bail!(
            "refresh token exchange failed ({e:#}) — please run `enclavid login` again"
        ),
    }
}

fn auth_path() -> Result<PathBuf> {
    let base = dirs::config_dir().context("no config dir on this platform")?;
    Ok(base.join("enclavid").join("auth.json"))
}

async fn refresh_access_token(refresh_token: &str) -> Result<StoredTokens> {
    let d = discovery::get();
    let http = discovery::http_client()?;

    let client = CoreClient::from_provider_metadata(
        d.provider_metadata.clone(),
        ClientId::new(d.cli_client_id.clone()),
        None,
    );

    let rt = RefreshToken::new(refresh_token.to_string());
    let mut request = client
        .exchange_refresh_token(&rt)
        .context("preparing refresh_token request")?
        .add_extra_param("resource", d.registry_resource.clone());
    // Scope the refreshed access_token to the active workspace
    // (Logto `organization_id` param). Without this the JWT carries
    // no `organization_id` claim and Angos's access policy denies the
    // push. Active workspace is set by `enclavid cloud login` /
    // `enclavid cloud workspace use ...`.
    if let Ok(workspace) = active_workspace_id() {
        request = request.add_extra_param("organization_id", workspace);
    }
    for scope in &d.registry_scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }

    let response = request
        .request_async(&http)
        .await
        .context("refresh_token exchange")?;

    let next_refresh = response
        .refresh_token()
        .map(|t| t.secret().clone())
        .or_else(|| Some(refresh_token.to_string()));

    Ok(StoredTokens {
        access_token: response.access_token().secret().clone(),
        refresh_token: next_refresh,
        id_token: None, // caller preserves existing id_token from the stored record
        expires_at: now_secs()
            + response
                .expires_in()
                .map(|d| d.as_secs())
                .unwrap_or(0),
        workspaces: Vec::new(), // caller preserves from stored record
        active_workspace_id: None, // caller preserves from stored record
    })
}

/// Parse the middle (payload) segment of a JWT and return it as a
/// serde_json::Value. NO signature verification — we trust this token
/// because we just obtained it from a TLS connection to our own
/// configured issuer; this is read-only claim extraction, not auth.
/// Used to harvest the workspaces list out of an id_token at login
/// time.
pub fn parse_jwt_claims(jwt: &str) -> Result<serde_json::Value> {
    let mut parts = jwt.split('.');
    let _header = parts.next();
    let payload = parts.next().context("malformed JWT: missing payload")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("JWT payload base64url decode")?;
    serde_json::from_slice(&bytes).context("JWT payload JSON parse")
}

/// Extract `organization_data` claim (Logto-specific) — list of
/// workspaces the user belongs to with id + name. Returns an empty
/// vec if the claim is absent or malformed (no panic, no error —
/// `enclavid cloud login` decides what to do with zero workspaces).
pub fn workspaces_from_id_token(id_token: &str) -> Vec<Workspace> {
    let Ok(claims) = parse_jwt_claims(id_token) else {
        return Vec::new();
    };
    let Some(arr) = claims.get("organization_data").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|item| {
            let id = item.get("id")?.as_str()?.to_string();
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(Workspace { id, name })
        })
        .collect()
}

async fn client_credentials_grant(client_id: String, client_secret: String) -> Result<String> {
    let d = discovery::get();
    let http = discovery::http_client()?;

    let client = CoreClient::from_provider_metadata(
        d.provider_metadata.clone(),
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
    );

    let mut request = client
        .exchange_client_credentials()
        .context("preparing client_credentials request")?
        .add_extra_param("resource", d.registry_resource.clone());
    for scope in &d.scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }

    let token_response = request
        .request_async(&http)
        .await
        .context("client_credentials token exchange")?;

    Ok(token_response.access_token().secret().clone())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
