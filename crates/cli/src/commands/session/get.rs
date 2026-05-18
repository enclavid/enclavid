//! `enclavid session get <id>` — fetch the session view (status,
//! policy, disclosure count, ...) and pretty-print as JSON. Uses the
//! cached `X-Session-Token` for the AuthZ gate; access JWT comes from
//! the standard auth chain.

use anyhow::{Context, Result};
use reqwest::Method;

use super::cache;
use super::transport;
use super::api_url;

pub async fn run(session_id: &str) -> Result<()> {
    let token = cache::read_session_token(session_id)?;
    let jwt = transport::fetch_jwt().await?;
    let client = transport::http_client()?;
    let url = format!(
        "{}/api/v1/sessions/{}",
        api_url().trim_end_matches('/'),
        session_id,
    );

    let response =
        transport::send(&client, Method::GET, &url, &jwt, Some(&token), None).await?;
    let response = transport::ensure_ok(response, "GET /api/v1/sessions/<id>").await?;
    let value: serde_json::Value = response
        .json()
        .await
        .context("parsing session view JSON")?;

    let pretty =
        serde_json::to_string_pretty(&value).context("pretty-printing session view")?;
    println!("{pretty}");
    Ok(())
}
