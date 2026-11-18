//! Resolve credentials for a target OCI registry. Same precedence
//! chain `docker push` / `oras push` follow plus a couple of
//! enclavid-specific extras (explicit `--auth` flag, single env var)
//! for non-interactive CI:
//!
//! 1. `--auth "<scheme> <token>"`      — explicit, wins over everything.
//! 2. `$ENCLAVID_REGISTRY_AUTH`        — `<registry> <scheme> <token>`, for
//!    CI: used for the registry it names alone.
//! 3. `~/.docker/config.json`:
//!    - `auths.<registry>.auth`        — base64("user:pass") form.
//!    - `credHelpers.<registry>`       — per-registry helper subprocess.
//!    - `credsStore`                   — global helper subprocess (osxkeychain etc.).
//! 4. None: anonymous, as docker pushes to a registry it holds no
//!    credentials for — the playground asks for none. A registry that
//!    wants some refuses, which [`needs_credentials`] tells apart.
//!
//! Returns `oci_client::secrets::RegistryAuth` ready to hand to a
//! `Client::push` call. No enclavid-specific carve-out for our own
//! registry.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use oci_client::errors::{OciDistributionError, OciErrorCode};
use oci_client::secrets::RegistryAuth;
use serde::Deserialize;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::docker_config;

const ENV_AUTH: &str = "ENCLAVID_REGISTRY_AUTH";

/// Resolve credentials for `registry` (a bare host, e.g. `ghcr.io`
/// or `localhost:5050`). `override_auth` is the value of the
/// `--auth` flag, if any.
pub async fn resolve(registry: &str, override_auth: Option<&str>) -> Result<RegistryAuth> {
    if let Some(a) = override_auth {
        return parse_authorization_header(a).context("parsing --auth value");
    }
    if let Ok(v) = std::env::var(ENV_AUTH)
        && let Some(creds) =
            env_auth_for(registry, &v).with_context(|| format!("parsing ${ENV_AUTH}"))?
    {
        return Ok(creds);
    }
    if let Some(creds) = from_docker_config(registry)? {
        return Ok(creds);
    }
    Ok(RegistryAuth::Anonymous)
}

/// The credentials `$ENCLAVID_REGISTRY_AUTH`, `value`, holds for
/// `registry`: `<registry> <scheme> <token>` gives them to the registry it
/// names, and to no other.
fn env_auth_for(registry: &str, value: &str) -> Result<Option<RegistryAuth>> {
    let value = value.trim();
    let named = value
        .split_once(char::is_whitespace)
        .filter(|(host, _)| !matches!(*host, "Bearer" | "Basic"));
    let Some((host, credentials)) = named else {
        bail!(
            "expected `<registry> Bearer <token>` or `<registry> Basic <base64>`: the registry it is for comes first"
        );
    };
    if host != registry {
        return Ok(None);
    }
    parse_authorization_header(credentials).map(Some)
}

/// Whether `e` is a registry refusing a request for its credentials:
/// none were given, or not enough.
pub fn needs_credentials(e: &OciDistributionError) -> bool {
    match e {
        OciDistributionError::UnauthorizedError { .. }
        | OciDistributionError::AuthenticationFailure(_) => true,
        OciDistributionError::ServerError { code, .. } => matches!(code, 401 | 403),
        OciDistributionError::RegistryError { envelope, .. } => envelope
            .errors
            .iter()
            .any(|e| matches!(e.code, OciErrorCode::Unauthorized | OciErrorCode::Denied)),
        _ => false,
    }
}

/// Accept full `Authorization` header values: `Bearer <token>` or
/// `Basic <base64>`. We collapse Basic into `(user, pass)` so
/// oci-client's Basic auth path is used (lets the registry
/// negotiate token exchange transparently if it wants).
fn parse_authorization_header(value: &str) -> Result<RegistryAuth> {
    let trimmed = value.trim();
    if let Some(token) = trimmed.strip_prefix("Bearer ") {
        return Ok(RegistryAuth::Bearer(token.trim().to_string()));
    }
    if let Some(b64) = trimmed.strip_prefix("Basic ") {
        let bytes = BASE64
            .decode(b64.trim())
            .context("Basic auth value is not valid base64")?;
        let s = String::from_utf8(bytes).context("Basic auth credentials are not utf8")?;
        let (user, pass) = s
            .split_once(':')
            .context("Basic auth must encode `username:password`")?;
        return Ok(RegistryAuth::Basic(user.to_string(), pass.to_string()));
    }
    bail!(
        "unrecognised authorization scheme — expected `Bearer <token>` or `Basic <base64>`, got: \
         {trimmed:.32}..."
    );
}

fn from_docker_config(registry: &str) -> Result<Option<RegistryAuth>> {
    let cfg = docker_config::load()?;

    // 3a. Static auths entry — most common form after a plain
    //     `docker login` on a Linux box (no system keychain).
    if let Some(entry) = cfg.auths.get(registry)
        && !entry.auth.is_empty()
    {
        return Ok(Some(decode_basic(&entry.auth).with_context(|| {
            format!("docker config auths.{registry}.auth")
        })?));
    }

    // 3b. Per-registry helper. Wins over the global store when both
    //     are configured (mirrors docker's own precedence).
    if let Some(helper) = cfg.cred_helpers.get(registry) {
        return Ok(Some(invoke_helper(helper, registry).with_context(
            || format!("invoking docker-credential-{helper}"),
        )?));
    }

    // 3c. Global store (e.g. macOS `osxkeychain`). Asked for every
    //     registry that doesn't have a per-registry entry.
    if let Some(store) = &cfg.creds_store {
        match invoke_helper(store, registry) {
            Ok(c) => return Ok(Some(c)),
            // Many helpers return `credentials not found` as an
            // error when asked for a registry they don't know — bubble
            // up as None so the caller can show the "no creds" hint.
            Err(_) => return Ok(None),
        }
    }

    Ok(None)
}

fn decode_basic(b64: &str) -> Result<RegistryAuth> {
    let raw = BASE64.decode(b64).context("base64 decode")?;
    let s = String::from_utf8(raw).context("utf8 decode")?;
    let (user, pass) = s.split_once(':').context("expected `username:password`")?;
    Ok(RegistryAuth::Basic(user.to_string(), pass.to_string()))
}

#[derive(Deserialize)]
struct HelperResponse {
    #[serde(rename = "Username", default)]
    username: String,
    #[serde(rename = "Secret", default)]
    secret: String,
}

/// Subprocess out to `docker-credential-<name>` per the docker
/// credential-helper protocol:
///   stdin  : registry hostname (raw bytes, no newline required)
///   stdout : `{"Username": "...", "Secret": "..."}` (JSON)
///   exit 0 : success; non-zero with stderr message on failure.
///
/// Username may be empty (token-auth convention). Secret then
/// becomes the Bearer token; we surface as `Basic("", secret)` to
/// stay inside oci-client's BasicAuth path — most registries accept
/// either form and BasicAuth negotiates token exchange transparently.
fn invoke_helper(name: &str, registry: &str) -> Result<RegistryAuth> {
    let binary = format!("docker-credential-{name}");
    let mut child = Command::new(&binary)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn `{binary} get` — is it on PATH?"))?;
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(registry.as_bytes())
        .context("writing registry name to helper stdin")?;
    let out = child
        .wait_with_output()
        .with_context(|| format!("waiting on `{binary}`"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("`{binary} get` failed: {stderr}");
    }
    let r: HelperResponse = serde_json::from_slice(&out.stdout)
        .with_context(|| format!("parsing `{binary} get` output as JSON"))?;
    if r.username.is_empty() {
        // Token auth: registry treats Basic('', secret) the same as
        // Bearer(secret) in oci-client's negotiation. Keep it simple.
        Ok(RegistryAuth::Bearer(r.secret))
    } else {
        Ok(RegistryAuth::Basic(r.username, r.secret))
    }
}

pub fn no_credentials_message(registry: &str) -> String {
    format!(
        "the registry `{registry}` wants credentials.\n\n\
         Try one of:\n  \
         * docker login {registry}             (writes to ~/.docker/config.json)\n  \
         * enclavid oci push ... --auth \"Bearer <token>\"\n  \
         * export {ENV_AUTH}=\"{registry} Bearer <token>\""
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_environments_credentials_go_to_the_registry_they_name_alone() {
        let value = "ghcr.io Bearer t0k3n";
        assert!(matches!(
            env_auth_for("ghcr.io", value).unwrap(),
            Some(RegistryAuth::Bearer(token)) if token == "t0k3n"
        ));
        assert!(
            env_auth_for("playground.enclavid.com", value)
                .unwrap()
                .is_none()
        );
        assert!(
            env_auth_for("ghcr.io.evil.example", value)
                .unwrap()
                .is_none()
        );
        // `user:pass`.
        assert!(matches!(
            env_auth_for("localhost:5000", " localhost:5000 Basic dXNlcjpwYXNz ").unwrap(),
            Some(RegistryAuth::Basic(user, pass)) if user == "user" && pass == "pass"
        ));
        for unbound in ["Bearer t0k3n", "Basic dXNlcjpwYXNz", "ghcr.io"] {
            assert!(env_auth_for("ghcr.io", unbound).is_err(), "{unbound}");
        }
    }
}
