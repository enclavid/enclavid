//! `enclavid session disclosures <id>` — pull the disclosure list,
//! decrypt each entry with the cached (or `--disclosure-key`) X25519
//! secret, parse to JSON, pretty-print as an array.
//!
//! Layout: server returns `{ items: [<base64-sealed-box>, ...] }`.
//! Each item is a libsodium sealed box to `client_disclosure_pubkey`
//! (we picked the recipient at `session create` time). Order is the
//! engine's append order; index = i-th disclosure emitted.
//!
//! Decryption errors abort the command (any single failure means
//! the cached key doesn't match what the session was created with —
//! signals user error / wrong session, not partial data).

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::Method;
use serde::Deserialize;
use std::path::PathBuf;

use super::api_url;
use super::cache;
use super::transport;

#[derive(Deserialize)]
struct DisclosuresResponse {
    items: Vec<String>,
}

pub async fn run(session_id: &str, disclosure_key_override: Option<PathBuf>) -> Result<()> {
    let token = cache::read_session_token(session_id)?;
    let key_path = match disclosure_key_override {
        Some(p) => p,
        None => cache::read_disclosure_key_path(session_id)?,
    };
    let secret = load_secret(&key_path)?;

    let jwt = transport::fetch_jwt().await?;
    let client = transport::http_client()?;
    let url = format!(
        "{}/api/v1/sessions/{}/disclosures",
        api_url().trim_end_matches('/'),
        session_id,
    );

    let response = transport::send(&client, Method::GET, &url, &jwt, Some(&token), None).await?;
    let response = transport::ensure_ok(response, "GET /api/v1/sessions/<id>/disclosures").await?;
    let body: DisclosuresResponse = response
        .json()
        .await
        .context("parsing disclosures envelope")?;

    if body.items.is_empty() {
        println!("[]");
        return Ok(());
    }

    let mut decrypted: Vec<serde_json::Value> = Vec::with_capacity(body.items.len());
    for (i, b64) in body.items.iter().enumerate() {
        let ciphertext = BASE64
            .decode(b64)
            .with_context(|| format!("item {i}: base64 decode"))?;
        let plaintext = enclavid_crypto::open_sealed(&ciphertext, &secret)
            .with_context(|| format!("item {i}: sealed box open"))?;
        // Engine emits JSON payloads; surface as nested values so the
        // outer array stays valid JSON. If a policy emits non-JSON
        // bytes (raw binary disclosure), we'd fall back to base64 —
        // but no policy has been doing that, so keep the strict path
        // until that changes.
        let parsed: serde_json::Value =
            serde_json::from_slice(&plaintext).with_context(|| format!("item {i}: not JSON"))?;
        decrypted.push(parsed);
    }

    let pretty = serde_json::to_string_pretty(&decrypted)
        .context("pretty-printing decrypted disclosures")?;
    println!("{pretty}");
    Ok(())
}

fn load_secret(path: &PathBuf) -> Result<String> {
    let content = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading disclosure secret {} — did `session create` for this session run?",
            path.display(),
        )
    })?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return Ok(trimmed.to_string());
    }
    anyhow::bail!("no disclosure secret line in {}", path.display())
}
