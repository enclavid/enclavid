use anyhow::{Context, Result};
use openidconnect::core::{CoreClient, CoreDeviceAuthorizationResponse};
use openidconnect::{ClientId, OAuth2TokenResponse, Scope};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::auth::{store_tokens, StoredTokens};
use crate::discovery;

pub async fn run() -> Result<()> {
    let d = discovery::get();
    let http = discovery::http_client()?;

    let device_url = d
        .provider_metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone();

    let client = CoreClient::from_provider_metadata(
        d.provider_metadata.clone(),
        ClientId::new(d.cli_client_id.clone()),
        None,
    )
    .set_device_authorization_url(device_url);

    let mut request = client.exchange_device_code();
    for scope in &d.scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    // Request registry scopes up-front so the refresh_token grant covers
    // them on subsequent exchanges (Logto requires refresh scopes to be a
    // subset of the originally-granted scopes — see memory
    // `project_logto_refresh_scope.md`).
    for scope in &d.registry_scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    request = request.add_extra_param("resource", d.registry_resource.clone());

    let details: CoreDeviceAuthorizationResponse = request
        .request_async(&http)
        .await
        .context("requesting device code")?;

    let display_url = details
        .verification_uri_complete()
        .map(|u| u.secret().clone())
        .unwrap_or_else(|| details.verification_uri().to_string());

    println!("To authenticate, visit:\n  {display_url}");
    println!("Code (in case it's not auto-filled): {}", details.user_code().secret());
    println!("\n(Opening browser automatically...)\n");
    let _ = open::that(&display_url);

    let token_response = client
        .exchange_device_access_token(&details)
        .context("preparing device access token request")?
        .add_extra_param("resource", d.registry_resource.clone())
        .request_async(&http, async_sleep, None)
        .await
        .context("polling for token")?;

    let id_token = token_response
        .extra_fields()
        .id_token()
        .map(|t| t.to_string());

    let tokens = StoredTokens {
        access_token: token_response.access_token().secret().clone(),
        refresh_token: token_response
            .refresh_token()
            .map(|t| t.secret().clone()),
        id_token,
        expires_at: now_secs()
            + token_response
                .expires_in()
                .map(|d| d.as_secs())
                .unwrap_or(0),
    };
    store_tokens(&tokens)?;

    println!("✓ Authenticated.");
    Ok(())
}

async fn async_sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
