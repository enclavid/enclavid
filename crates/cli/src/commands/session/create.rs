//! `enclavid session create` — POST /api/v1/sessions.
//!
//! Generates (or imports) a disclosure keypair, packages the create
//! body, fires the request, and stashes the response's session token
//! plus disclosure secret on disk so subsequent `session get` /
//! `session disclosures` work without re-passing anything.

use age::secrecy::ExposeSecret;
use age::x25519::Identity;
use anyhow::{Context, Result};
use reqwest::Method;
use serde::Deserialize;
use std::path::PathBuf;
use std::str::FromStr;

use super::cache;
use super::transport;
use super::{api_url, applicant_url};

#[derive(Deserialize, Debug)]
struct CreateResponse {
    session_id: String,
    client_session_token: String,
    resolved_policy: ResolvedPolicyView,
    attestation: AttestationView,
}

#[derive(Deserialize, Debug)]
struct ResolvedPolicyView {
    reference: String,
    digest: String,
}

#[derive(Deserialize, Debug)]
struct AttestationView {
    format: String,
}

pub async fn run(
    policy: String,
    policy_key_path: PathBuf,
    disclosure_key_path: Option<PathBuf>,
    client_ref: Option<String>,
) -> Result<()> {
    // client_policy_key — full AGE-SECRET-KEY-1… string, sent verbatim
    // in the request body (TEE re-parses on its side).
    let policy_key_secret = read_age_secret(&policy_key_path).with_context(|| {
        format!("reading client_policy_key from {}", policy_key_path.display())
    })?;

    // Disclosure recipient resolution. Two paths:
    //   * --disclosure-key <path> → reuse caller's keypair; we still
    //     stash the secret under sessions/<id>/disclosure.key on success
    //     so `session disclosures` works against the same cache layout.
    //   * absent → mint ephemeral X25519, secret to disk after create.
    let (disclosure_secret, disclosure_pubkey, generated) =
        match disclosure_key_path.as_deref() {
            Some(p) => {
                let secret = read_age_secret(&p.to_path_buf()).with_context(|| {
                    format!("reading disclosure key from {}", p.display())
                })?;
                let identity = Identity::from_str(&secret).map_err(|e| {
                    anyhow::anyhow!("disclosure key in {} is not a valid age identity: {e}", p.display())
                })?;
                (secret, identity.to_public().to_string(), false)
            }
            None => {
                let identity = Identity::generate();
                let secret = identity.to_string().expose_secret().to_string();
                (secret, identity.to_public().to_string(), true)
            }
        };

    let mut body = serde_json::json!({
        "policy": policy,
        "client_disclosure_pubkey": disclosure_pubkey,
        "client_policy_key": policy_key_secret,
    });
    if let Some(r) = client_ref.as_deref() {
        body["client_ref"] = serde_json::Value::String(r.to_string());
    }

    let client = transport::http_client()?;
    let jwt = transport::fetch_jwt().await?;
    let url = format!("{}/api/v1/sessions", api_url().trim_end_matches('/'));

    let response = transport::send(&client, Method::POST, &url, &jwt, None, Some(body))
        .await?;
    let response = transport::ensure_ok(response, "POST /api/v1/sessions").await?;
    let created: CreateResponse = response
        .json()
        .await
        .context("parsing POST /sessions response")?;

    // Cache the per-session secrets. Storing the disclosure key
    // even in the "user supplied --disclosure-key" path so that
    // `session disclosures <id>` works uniformly without needing
    // the caller to re-pass --disclosure-key — they can if they
    // want via the same flag, but the cache covers the dev path.
    let token_path = cache::store_session_token(&created.session_id, &created.client_session_token)?;
    let key_path = cache::store_disclosure_key(&created.session_id, &disclosure_secret)?;

    println!("✓ Session created");
    println!("  session_id:       {}", created.session_id);
    println!("  policy:           {} ({})", created.resolved_policy.reference, created.resolved_policy.digest);
    println!("  attestation:      {}", created.attestation.format);
    if let Some(r) = client_ref.as_deref() {
        println!("  client_ref:       {r}");
    }
    println!("  applicant URL:    {}/session/{}/",
        applicant_url().trim_end_matches('/'),
        created.session_id,
    );
    println!();
    println!("  Cached:");
    println!("    X-Session-Token  →  {}", token_path.display());
    println!("    Disclosure key   →  {} {}",
        key_path.display(),
        if generated { "(auto-generated)" } else { "(copied from --disclosure-key)" });
    println!();
    println!("Next:");
    println!("  open '{}/session/{}/'", applicant_url().trim_end_matches('/'), created.session_id);
    println!("  enclavid session get {}", created.session_id);
    println!("  enclavid session disclosures {}", created.session_id);

    Ok(())
}

/// Pick out the AGE-SECRET-KEY-1… line from a keygen-style file:
/// comments (lines starting with `#`) and blank lines are skipped,
/// the first non-blank line is returned. Mirrors `policy/push.rs::
/// read_identity` but doesn't construct an `Identity` — sessions pass
/// the secret string straight through to the TEE.
fn read_age_secret(path: &PathBuf) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("opening {}", path.display()))?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return Ok(trimmed.to_string());
    }
    anyhow::bail!("no age secret-key line found in {}", path.display())
}
