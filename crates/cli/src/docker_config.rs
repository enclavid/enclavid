//! Read `~/.docker/config.json` — the credential file docker, oras,
//! podman and skopeo share — for the fields credential resolution
//! uses:
//!
//!   * `auths.<registry>.auth` — base64("username:password") for
//!     static creds (the form `docker login` writes when no helper is
//!     configured).
//!   * `credHelpers.<registry>` — name suffix of a helper binary
//!     (`docker-credential-<name>`) used per-registry.
//!   * `credsStore` — global helper name used for every registry that
//!     doesn't have its own `credHelpers` entry. macOS docker login
//!     writes this with value `"osxkeychain"`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
pub struct DockerConfig {
    #[serde(default)]
    pub auths: BTreeMap<String, AuthEntry>,

    #[serde(default, rename = "credHelpers")]
    pub cred_helpers: BTreeMap<String, String>,

    #[serde(default, rename = "credsStore")]
    pub creds_store: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthEntry {
    /// Base64("username:password"). Empty when creds live in a helper
    /// or store (the field is just a marker that an entry exists).
    #[serde(default)]
    pub auth: String,
}

pub fn path() -> Result<PathBuf> {
    // Same precedence as docker: $DOCKER_CONFIG/config.json, else
    // ~/.docker/config.json. We don't honor podman's per-user store
    // — that lives in $XDG_RUNTIME_DIR/containers/auth.json. If a
    // user is podman-only and lacks ~/.docker, they can `--auth`
    // explicitly or set ENCLAVID_REGISTRY_AUTH.
    if let Ok(dir) = std::env::var("DOCKER_CONFIG") {
        return Ok(PathBuf::from(dir).join("config.json"));
    }
    let home = dirs::home_dir().context("no home dir on this platform")?;
    Ok(home.join(".docker").join("config.json"))
}

/// Read `~/.docker/config.json`. Missing file → empty config (so
/// downstream code can treat "no docker login ever" as "no auths
/// found" uniformly).
pub fn load() -> Result<DockerConfig> {
    let p = path()?;
    match std::fs::read_to_string(&p) {
        Ok(s) if s.trim().is_empty() => Ok(DockerConfig::default()),
        Ok(s) => serde_json::from_str(&s)
            .with_context(|| format!("parsing {} as docker config", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DockerConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}
