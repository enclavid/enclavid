use anyhow::{Context, Result};
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

#[derive(Serialize, Deserialize)]
pub struct StoredTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// id_token from device flow — kept for inspection / debugging.
    #[serde(default)]
    pub id_token: Option<String>,
    pub expires_at: u64,
}

/// Resolve a usable access token from any available source.
///
/// Priority:
/// 1. Env-var client_credentials (`ENCLAVID_CLIENT_ID`/`_SECRET`) — explicit CI behavior.
/// 2. Tokens stored on disk by `enclavid login`. Auto-refreshed if expired.
/// 3. Error: not authenticated.
pub async fn get_access_token() -> Result<String> {
    if let (Some(id), Some(secret)) = (config::client_id(), config::client_secret()) {
        return client_credentials_grant(id, secret).await;
    }

    match load_from_disk().await? {
        Some(token) => Ok(token),
        None => anyhow::bail!(
            "not authenticated — run `enclavid login` for interactive auth, \
             or set ENCLAVID_CLIENT_ID + ENCLAVID_CLIENT_SECRET for CI",
        ),
    }
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
    })
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
