//! `enclavid session create` — POST /api/v1/sessions.
//!
//! Builds the create body — either from `--policy <ref>` (trivial case)
//! or from `--from-file <spec.json>` (the full POST payload: plugin pins,
//! per-artifact keys, registry_auth) — resolves the disclosure recipient,
//! fires the request, and stashes the response's session token plus
//! disclosure secret on disk so subsequent `session get` /
//! `session disclosures` work without re-passing anything.
//!
//! With a build named (`--measurement` / `$ENCLAVID_API_MEASUREMENT`),
//! the request asks a gateway for a group running that build. The group
//! it answers with is cached beside the token and printed, and the
//! applicant link goes under its marker.

use anyhow::{Context, Result};
use reqwest::Method;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use std::path::PathBuf;

use super::cache;
use super::transport;
use super::{API_URL_VAR, APPLICANT_URL_VAR};
use super::{api_measurement, api_url, applicant_url, bare_origin, is_group, under_group};

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
    measurement: Option<String>,
) -> Result<()> {
    // 0. The api build to require, checked before anything else is done.
    //    Naming one means a gateway will place the session on a group whose
    //    marker goes after both bases, so they are held to bare origins now,
    //    before a session exists that later requests could not reach.
    let measurement = api_measurement(measurement)?;
    if measurement.is_some() {
        bare_origin(API_URL_VAR, &api_url())?;
        bare_origin(APPLICANT_URL_VAR, &applicant_url())?;
    }

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
        let secret = read_disclosure_secret(&p.to_path_buf())
            .with_context(|| format!("reading disclosure key from {}", p.display()))?;
        let public = enclavid_crypto::public_from_secret(&secret).map_err(|e| {
            anyhow::anyhow!(
                "disclosure key in {} is not a valid X25519 secret: {e}",
                p.display()
            )
        })?;
        obj.insert("client_disclosure_pubkey".into(), public.into());
        DisclosureSource::Known {
            secret,
            label: "copied from --disclosure-key",
        }
    } else if obj
        .get("client_disclosure_pubkey")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        // The spec file brought its own recipient; the CLI doesn't hold
        // the matching secret.
        DisclosureSource::Caller
    } else {
        let (secret, public) = enclavid_crypto::generate_recipient();
        obj.insert("client_disclosure_pubkey".into(), public.into());
        DisclosureSource::Known {
            secret,
            label: "auto-generated",
        }
    };

    // 3. POST.
    let client = transport::http_client()?;
    let jwt = transport::fetch_jwt().await?;
    let url = format!("{}/api/v1/sessions", api_url().trim_end_matches('/'));

    let response = transport::send(
        &client,
        Method::POST,
        &url,
        &jwt,
        None,
        measurement.as_deref(),
        Some(body),
    )
    .await?;
    let response = transport::ensure_ok(response, "POST /api/v1/sessions").await?;
    // The group is read off the headers before the body consumes the
    // response, but acted on only once the body has given the session id:
    // the session exists by then, and a refusal has to say so.
    let placed = match measurement.as_deref() {
        Some(measurement) => placed_group(response.headers(), measurement),
        None => Ok(None),
    };
    let created: CreateResponse = response
        .json()
        .await
        .context("parsing POST /sessions response")?;
    let group = placed.with_context(|| {
        format!(
            "session {} was created, but the group it was placed on cannot be used",
            created.session_id
        )
    })?;
    if measurement.is_some() && group.is_none() {
        eprintln!(
            "note: no {} came back, so the session is on no group and the build was not required (api answered directly)",
            transport::GROUP_HEADER
        );
    }

    // 4. Cache the group first, when a gateway placed the session on one:
    //    requests without it go unmarked and are refused, so a token is
    //    never left behind without its group. Then the session token,
    //    always, and the disclosure secret only when the CLI generated/read
    //    it (caller-supplied recipients keep their own secret).
    let group_path = group
        .as_deref()
        .map(|group| cache::store_group(&created.session_id, group))
        .transpose()?;
    let token_path =
        cache::store_session_token(&created.session_id, &created.client_session_token)?;
    let key_cache = match &disclosure {
        DisclosureSource::Known { secret, label } => {
            let path = cache::store_disclosure_key(&created.session_id, secret)?;
            Some((path, *label))
        }
        DisclosureSource::Caller => None,
    };
    let applicant_link = format!(
        "{}/#/session/{}",
        under_group(APPLICANT_URL_VAR, &applicant_url(), group.as_deref())?,
        created.session_id,
    );

    println!("✓ Session created");
    println!("  session_id:       {}", created.session_id);
    println!(
        "  policy:           {} ({})",
        created.resolved_policy.reference, created.resolved_policy.digest
    );
    println!("  attestation:      {}", created.attestation.format);
    if let Some(r) = client_ref.as_deref() {
        println!("  client_ref:       {r}");
    }
    if let Some(group) = group.as_deref() {
        println!("  group:            {group}");
    }
    println!("  applicant URL:    {applicant_link}");
    println!();
    println!("  Cached:");
    println!("    X-Session-Token  →  {}", token_path.display());
    if let Some(path) = group_path {
        println!("    Group            →  {}", path.display());
    }
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
    println!("  open '{applicant_link}'");
    println!("  enclavid session get {}", created.session_id);
    println!("  enclavid session disclosures {}", created.session_id);

    Ok(())
}

/// Pick out the disclosure secret (an X25519 secret as hex) from a key
/// file: comments (lines starting with `#`) and blank lines are
/// skipped, the first non-blank line is returned.
fn read_disclosure_secret(path: &PathBuf) -> Result<String> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("opening {}", path.display()))?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return Ok(trimmed.to_string());
    }
    anyhow::bail!("no disclosure secret line found in {}", path.display())
}

/// The group a gateway placed the session on, from `x-enclavid-group`:
/// `<label>.<build>`. `None` when the header is absent, which is api
/// answering directly.
///
/// Checked before anything is built from it. It becomes a path segment
/// of every later request and of the applicant link, so it is held to
/// what a gateway group may be — see [`is_group`], the same check
/// [`cache::read_group`] applies whenever it is read back. And its
/// build must be the one this request required: a link naming any
/// other would send the applicant to a build the caller never chose.
fn placed_group(headers: &HeaderMap, measurement: &str) -> Result<Option<String>> {
    let Some(value) = headers.get(transport::GROUP_HEADER) else {
        return Ok(None);
    };
    let group = value
        .to_str()
        .with_context(|| format!("{} is not text", transport::GROUP_HEADER))?;
    match group.split_once('.') {
        Some((_, build)) if is_group(group) && build == measurement => Ok(Some(group.to_string())),
        _ => anyhow::bail!(
            "{} is `{group}`, expected `<label>.{measurement}`",
            transport::GROUP_HEADER
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_group(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(transport::GROUP_HEADER, value.parse().unwrap());
        headers
    }

    #[test]
    fn no_header_is_no_group() {
        assert_eq!(
            placed_group(&HeaderMap::new(), &"0f".repeat(48)).unwrap(),
            None
        );
    }

    #[test]
    fn a_group_on_the_required_build_is_kept() {
        let build = "0f".repeat(48);
        let group = format!("blue-2.{build}");
        assert_eq!(
            placed_group(&with_group(&group), &build).unwrap(),
            Some(group),
        );
    }

    #[test]
    fn a_group_on_another_build_is_refused() {
        let build = "0f".repeat(48);
        let other = format!("blue.{}", "1f".repeat(48));
        assert!(placed_group(&with_group(&other), &build).is_err());
    }

    #[test]
    fn a_label_a_gateway_could_not_hold_is_refused() {
        let build = "0f".repeat(48);
        let too_long = "a".repeat(33);
        for label in ["", "a/b", "a.b", "Blue", "a?b", too_long.as_str()] {
            let group = format!("{label}.{build}");
            assert!(
                placed_group(&with_group(&group), &build).is_err(),
                "{label:?}"
            );
        }
    }
}
