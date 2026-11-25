//! `enclavid session create` — POST /api/v1/sessions.
//!
//! Builds the create body — either from `--policy <ref>` (with `--props`)
//! or from `--from-file <spec.json>` (the full POST payload: plugin pins,
//! per-artifact keys, registry_auth) — resolves the disclosure recipient,
//! fires the request, and stashes what later requests need on disk — the
//! API, the session token, the group, the disclosure secret — so
//! subsequent `session get` / `session disclosures` name the session alone.
//!
//! The group a gateway placed the session on, when the API answers with
//! one, is cached beside the token and printed, and the applicant link
//! goes under its marker. With a build named (`--measurement` /
//! `$ENCLAVID_API_MEASUREMENT`), the request asks the gateway for a group
//! running that build.

use anyhow::{Context, Result};
use reqwest::Method;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;

use super::cache;
use super::transport;
use super::{API_URL, APPLICANT_URL};
use super::{api_measurement, bare_origin, is_group, under_group};

/// What `session create` was asked.
pub struct Asked {
    /// The policy's pinned reference, or `-` for one on stdin.
    pub policy: Option<String>,
    pub from_file: Option<PathBuf>,
    /// The props: a JSON object, or `@<path>` of a file holding one.
    pub props: Option<String>,
    pub disclosure_key: Option<PathBuf>,
    pub consumer_ref: Option<String>,
    pub measurement: Option<String>,
    /// The API's origin.
    pub api: String,
    /// The origin of the site applicants take a session at.
    pub applicants: String,
}

/// Where the disclosure recipient came from — drives whether the CLI can
/// cache a secret for later `session disclosures`.
enum DisclosureSource {
    /// The CLI knows the secret (generated, or read from `--disclosure-key`)
    /// → cache it so reads decrypt with no extra flags.
    Known { secret: String, label: &'static str },
    /// `--from-file` supplied its own `disclosure_pubkey`; the secret
    /// lives with the caller, so `session disclosures` needs `--disclosure-key`.
    Caller,
}

#[derive(Deserialize, Debug)]
struct CreateResponse {
    session_id: String,
    session_token: String,
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

pub async fn run(asked: Asked) -> Result<()> {
    // 0. Where the request goes, and the build it requires, checked before
    //    anything is done: both bases take a group's marker after them, so
    //    they are held to bare origins now, before a session exists that
    //    later requests could not reach.
    let measurement = api_measurement(asked.measurement)?;
    let api = bare_origin(API_URL, &asked.api)?;
    let applicants = bare_origin(APPLICANT_URL, &asked.applicants)?;
    let client = transport::http_client(&api)?;

    // 1. Base request body. `--from-file` carries the full POST payload;
    //    `--policy` is the trivial case, with its props. clap already
    //    enforces they're mutually exclusive — this guards the "neither"
    //    case.
    let mut body: serde_json::Value = match (asked.from_file.as_deref(), asked.policy) {
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
        (None, Some(policy)) => serde_json::json!({ "policy": policy_from(policy).await? }),
        (None, None) => anyhow::bail!("pass either --policy <ref> or --from-file <spec.json>"),
    };
    if let Some(props) = asked.props.as_deref() {
        body["props"] = props_from(props)?;
    }
    if let Some(r) = asked.consumer_ref.as_deref() {
        body["consumer_ref"] = serde_json::Value::String(r.to_string());
    }

    // 2. Disclosure recipient. Precedence: --disclosure-key (explicit) >
    //    a `disclosure_pubkey` already in the body (--from-file) >
    //    auto-generate. We cache the secret whenever the CLI knows it so
    //    `session disclosures` decrypts without re-passing anything.
    let obj = body
        .as_object_mut()
        .expect("body is a JSON object (checked / constructed above)");
    let disclosure = if let Some(p) = asked.disclosure_key.as_deref() {
        let secret = read_disclosure_secret(&p.to_path_buf())
            .with_context(|| format!("reading disclosure key from {}", p.display()))?;
        let public = enclavid_crypto::public_from_secret(&secret).map_err(|e| {
            anyhow::anyhow!(
                "disclosure key in {} is not a valid X25519 secret: {e}",
                p.display()
            )
        })?;
        obj.insert("disclosure_pubkey".into(), public.into());
        DisclosureSource::Known {
            secret,
            label: "copied from --disclosure-key",
        }
    } else if obj
        .get("disclosure_pubkey")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        // The spec file brought its own recipient; the CLI doesn't hold
        // the matching secret.
        DisclosureSource::Caller
    } else {
        let (secret, public) = enclavid_crypto::generate_recipient();
        obj.insert("disclosure_pubkey".into(), public.into());
        DisclosureSource::Known {
            secret,
            label: "auto-generated",
        }
    };

    // 3. POST.
    let url = format!("{api}/api/v1/sessions");

    let response = transport::send(
        &client,
        Method::POST,
        &url,
        None,
        measurement.as_deref(),
        Some(body),
    )
    .await?;
    let response = transport::ensure_ok(response, "POST /api/v1/sessions").await?;
    // The group is read off the headers before the body consumes the
    // response, but acted on only once the body has given the session id:
    // the session exists by then, and a refusal has to say so.
    let placed = placed_group(response.headers(), measurement.as_deref());
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

    // 4. Cache the API and the group first, when a gateway placed the
    //    session on one: requests without them go elsewhere or unmarked
    //    and are refused, so a token is never left behind without them.
    //    Then the session token, always, and the disclosure secret only
    //    when the CLI generated/read it (caller-supplied recipients keep
    //    their own secret).
    let api_path = cache::store_api(&created.session_id, &api)?;
    let group_path = group
        .as_deref()
        .map(|group| cache::store_group(&created.session_id, group))
        .transpose()?;
    let token_path = cache::store_session_token(&created.session_id, &created.session_token)?;
    let key_cache = match &disclosure {
        DisclosureSource::Known { secret, label } => {
            let path = cache::store_disclosure_key(&created.session_id, secret)?;
            Some((path, *label))
        }
        DisclosureSource::Caller => None,
    };
    let applicant_link = format!(
        "{}/{}",
        under_group(&applicants, group.as_deref()),
        created.session_id,
    );

    println!("✓ Session created");
    println!("  session_id:       {}", created.session_id);
    println!(
        "  policy:           {} ({})",
        created.resolved_policy.reference, created.resolved_policy.digest
    );
    println!("  attestation:      {}", created.attestation.format);
    if let Some(r) = asked.consumer_ref.as_deref() {
        println!("  consumer_ref:     {r}");
    }
    if let Some(group) = group.as_deref() {
        println!("  group:            {group}");
    }
    println!("  applicant URL:    {applicant_link}");
    println!();
    println!("  Cached:");
    println!("    API              →  {}", api_path.display());
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

/// The policy `value` names: itself, or for `-` the one line on stdin, as
/// `enclavid oci push --quiet` writes it.
async fn policy_from(value: String) -> Result<String> {
    if value != "-" {
        return Ok(value);
    }
    let mut read = String::new();
    tokio::io::stdin()
        .read_to_string(&mut read)
        .await
        .context("reading the policy from stdin")?;
    let policy = read.trim();
    if policy.is_empty() || policy.contains(char::is_whitespace) {
        anyhow::bail!(
            "stdin holds no policy's reference: one line, as `enclavid oci push --quiet` writes it"
        );
    }
    Ok(policy.to_string())
}

/// The props `value` gives: a JSON object, or `@<path>` of a file
/// holding one.
fn props_from(value: &str) -> Result<serde_json::Value> {
    let (text, source) = match value.strip_prefix('@') {
        Some(path) => (
            std::fs::read_to_string(path)
                .with_context(|| format!("reading the props in {path}"))?,
            path,
        ),
        None => (value.to_string(), "--props"),
    };
    let props: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("{source} is not JSON"))?;
    if !props.is_object() {
        anyhow::bail!("{source} is not a JSON object: props are one, keyed by their names");
    }
    Ok(props)
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
/// `<label>.<build>`. `None` when the header is absent, which is an API
/// answering directly.
///
/// Checked before anything is built from it. It becomes a path segment
/// of every later request and of the applicant link, so it is held to
/// what a gateway group may be — see [`is_group`], the same check
/// [`cache::read_group`] applies whenever it is read back. And when the
/// request required a build, its build must be that one: a link naming
/// any other would send the applicant to a build the caller never chose.
fn placed_group(headers: &HeaderMap, measurement: Option<&str>) -> Result<Option<String>> {
    let Some(value) = headers.get(transport::GROUP_HEADER) else {
        return Ok(None);
    };
    let group = value
        .to_str()
        .with_context(|| format!("{} is not text", transport::GROUP_HEADER))?;
    match group.split_once('.') {
        Some((_, build))
            if is_group(group) && measurement.is_none_or(|measurement| build == measurement) =>
        {
            Ok(Some(group.to_string()))
        }
        _ => anyhow::bail!(
            "{} is `{group}`, expected `<label>.{}`",
            transport::GROUP_HEADER,
            measurement.unwrap_or("<build>")
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
            placed_group(&HeaderMap::new(), Some(&"0f".repeat(48))).unwrap(),
            None
        );
        assert_eq!(placed_group(&HeaderMap::new(), None).unwrap(), None);
    }

    #[test]
    fn a_group_on_the_required_build_is_kept() {
        let build = "0f".repeat(48);
        let group = format!("blue-2.{build}");
        assert_eq!(
            placed_group(&with_group(&group), Some(&build)).unwrap(),
            Some(group),
        );
    }

    #[test]
    fn a_group_is_kept_when_no_build_was_required() {
        let group = format!("blue-2.{}", "1f".repeat(48));
        assert_eq!(
            placed_group(&with_group(&group), None).unwrap(),
            Some(group)
        );
    }

    #[test]
    fn a_group_on_another_build_is_refused() {
        let build = "0f".repeat(48);
        let other = format!("blue.{}", "1f".repeat(48));
        assert!(placed_group(&with_group(&other), Some(&build)).is_err());
    }

    #[test]
    fn a_label_a_gateway_could_not_hold_is_refused() {
        let build = "0f".repeat(48);
        let too_long = "a".repeat(33);
        for label in ["", "a/b", "a.b", "Blue", "a?b", too_long.as_str()] {
            let group = format!("{label}.{build}");
            assert!(
                placed_group(&with_group(&group), Some(&build)).is_err(),
                "{label:?}"
            );
            assert!(
                placed_group(&with_group(&group), None).is_err(),
                "{label:?}"
            );
        }
    }

    #[test]
    fn props_are_an_object_inline_or_in_a_file() {
        assert_eq!(
            props_from(r#"{"min-age": 18}"#).unwrap(),
            serde_json::json!({"min-age": 18})
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), r#"{"selfie": false}"#).unwrap();
        assert_eq!(
            props_from(&format!("@{}", file.path().display())).unwrap(),
            serde_json::json!({"selfie": false})
        );
        assert!(props_from("[18]").is_err());
        assert!(props_from("min-age=18").is_err());
        assert!(props_from("@/nowhere/props.json").is_err());
    }
}
