//! `enclavid session create` — POST /api/v1/sessions.
//!
//! Builds the create body — either from `--policy <ref>` (trivial case)
//! or from `--from-file <spec.json>` (the full POST payload: plugin pins,
//! per-artifact keys, registry_auth) — resolves the disclosure recipient,
//! fires the request, and stashes the response's session token plus
//! disclosure secret on disk so subsequent `session get` /
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

/// Where the disclosure recipient came from — drives whether the CLI can
/// cache a secret for later `session disclosures`.
enum DisclosureSource {
    /// The CLI knows the secret (generated, or read from `--disclosure-key`)
    /// → cache it so reads decrypt with no extra flags.
    Known { secret: String, label: &'static str },
    /// `--from-file` supplied its own `client_disclosure_pubkey`; the secret
    /// lives with the caller, so `session disclosures` needs `--disclosure-key`.
    Caller,
}

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
    policy: Option<String>,
    from_file: Option<PathBuf>,
    disclosure_key_path: Option<PathBuf>,
    client_ref: Option<String>,
) -> Result<()> {
    // 1. Base request body. `--from-file` carries the full POST payload;
    //    `--policy` is the trivial single-field case. clap already enforces
    //    they're mutually exclusive — this guards the "neither" case.
    let mut body: serde_json::Value = match (from_file.as_deref(), policy.as_deref()) {
        (Some(path), _) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading session spec from {}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&raw)
                .with_context(|| format!("parsing JSON session spec {}", path.display()))?;
            if !value.is_object() {
                anyhow::bail!(
                    "session spec {} must be a JSON object (the POST /sessions body)",
                    path.display()
                );
            }
            value
        }
        (None, Some(p)) => serde_json::json!({ "policy": p }),
        (None, None) => anyhow::bail!("pass either --policy <ref> or --from-file <spec.json>"),
    };
    if let Some(r) = client_ref.as_deref() {
        body["client_ref"] = serde_json::Value::String(r.to_string());
    }

    // 2. Disclosure recipient. Precedence: --disclosure-key (explicit) >
    //    a `client_disclosure_pubkey` already in the body (--from-file) >
    //    auto-generate. We cache the secret whenever the CLI knows it so
    //    `session disclosures` decrypts without re-passing anything.
    let obj = body
        .as_object_mut()
        .expect("body is a JSON object (checked / constructed above)");
    let disclosure = if let Some(p) = disclosure_key_path.as_deref() {
        let secret = read_age_secret(&p.to_path_buf())
            .with_context(|| format!("reading disclosure key from {}", p.display()))?;
        let identity = Identity::from_str(&secret).map_err(|e| {
            anyhow::anyhow!("disclosure key in {} is not a valid age identity: {e}", p.display())
        })?;
        obj.insert(
            "client_disclosure_pubkey".into(),
            identity.to_public().to_string().into(),
        );
        DisclosureSource::Known { secret, label: "copied from --disclosure-key" }
    } else if obj
        .get("client_disclosure_pubkey")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        // The spec file brought its own recipient; the CLI doesn't hold
        // the matching secret.
        DisclosureSource::Caller
    } else {
        let identity = Identity::generate();
        let secret = identity.to_string().expose_secret().to_string();
        obj.insert(
            "client_disclosure_pubkey".into(),
            identity.to_public().to_string().into(),
        );
        DisclosureSource::Known { secret, label: "auto-generated" }
    };

    // 3. POST.
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

    // 4. Cache the session token always; cache the disclosure secret only
    //    when the CLI generated/read it (caller-supplied recipients keep
    //    their own secret).
    let token_path = cache::store_session_token(&created.session_id, &created.client_session_token)?;
    let key_cache = match &disclosure {
        DisclosureSource::Known { secret, label } => {
            let path = cache::store_disclosure_key(&created.session_id, secret)?;
            Some((path, *label))
        }
        DisclosureSource::Caller => None,
    };

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
    match key_cache {
        Some((path, label)) => {
            println!("    Disclosure key   →  {} ({label})", path.display());
        }
        None => {
            println!("    Disclosure key   →  caller-supplied (not cached)");
            println!("                        pass --disclosure-key to `session disclosures`");
        }
    }
    println!();
    println!("Next:");
    println!("  open '{}/session/{}/'", applicant_url().trim_end_matches('/'), created.session_id);
    println!("  enclavid session get {}", created.session_id);
    println!("  enclavid session disclosures {}", created.session_id);

    Ok(())
}

/// Pick out the AGE-SECRET-KEY-1… line from a key file: comments
/// (lines starting with `#`) and blank lines are skipped, the first
/// non-blank line is returned.
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
