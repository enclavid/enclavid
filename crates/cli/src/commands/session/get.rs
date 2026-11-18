//! `enclavid session get <id>` — fetch the session view (status,
//! policy, disclosure count, ...) and pretty-print as JSON, from the API
//! `create` cached, with the cached `X-Session-Token` for the AuthZ gate.
//! Goes under the cached group's marker when `create` cached one.

use anyhow::{Context, Result};
use reqwest::Method;

use super::cache;
use super::session_api;
use super::transport;

pub async fn run(session_id: &str) -> Result<()> {
    let token = cache::read_session_token(session_id)?;
    let api = session_api(session_id)?;
    let client = transport::http_client(&api)?;
    let url = format!("{api}/api/v1/sessions/{session_id}");

    let response = transport::send(&client, Method::GET, &url, Some(&token), None, None).await?;
    let response = transport::ensure_ok(response, "GET /api/v1/sessions/<id>").await?;
    let value: serde_json::Value = response.json().await.context("parsing session view JSON")?;

    let pretty = serde_json::to_string_pretty(&value).context("pretty-printing session view")?;
    println!("{pretty}");
    Ok(())
}
