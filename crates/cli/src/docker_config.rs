//! Read/write `~/.docker/config.json` — the de-facto standard
//! credential file shared across docker, oras, podman, skopeo,
//! containerd, and now enclavid CLI.
//!
//! We only touch fields relevant to credential resolution:
//!
//!   * `auths.<registry>.auth` — base64("username:password") for
//!     static creds (the form `docker login` writes when no helper is
//!     configured).
//!   * `credHelpers.<registry>` — name suffix of a helper binary
//!     (`docker-credential-<name>`) used per-registry. This is the
//!     hook `enclavid login` registers under our registry so other
//!     tools get fresh tokens automatically.
//!   * `credsStore` — global helper name used for ALL registries
//!     that don't have an explicit `credHelpers` entry. macOS docker
//!     login writes this with value `"osxkeychain"`.
//!
//! Everything else in the file (e.g. `psFormat`, `imagesFormat`,
//! BuildKit settings) is preserved verbatim via a `flat: HashMap`
//! catch-all so writes don't clobber unrelated config.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Decoded view of the bits we care about. Unknown keys are kept in
/// `flat` and re-emitted on save so we never lose unrelated config a
/// user has accumulated (BuildKit settings, aliases, ...).
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct DockerConfig {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub auths: BTreeMap<String, AuthEntry>,

    #[serde(
        default,
        rename = "credHelpers",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub cred_helpers: BTreeMap<String, String>,

    #[serde(
        default,
        rename = "credsStore",
        skip_serializing_if = "Option::is_none"
    )]
    pub creds_store: Option<String>,

    /// Everything else — preserved verbatim across read+write so we
    /// don't drop unrelated keys.
    #[serde(flatten)]
    pub flat: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct AuthEntry {
    /// Base64("username:password"). Empty when creds live in a helper
    /// or store (the field is just a marker that an entry exists).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth: String,

    /// Anything else docker writes per-entry (identitytoken, email,
    /// ...). Forward through unchanged.
    #[serde(flatten)]
    pub extras: BTreeMap<String, serde_json::Value>,
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

/// Write `~/.docker/config.json`, creating parents as needed. Mode
/// 0600 — same as docker writes itself (file may contain base64
/// credentials).
pub fn save(cfg: &DockerConfig) -> Result<()> {
    let p = path()?;
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(cfg).context("serializing docker config")?;
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(&p)
        .with_context(|| format!("opening {} for write", p.display()))?;
    f.write_all(&body)
        .with_context(|| format!("writing {}", p.display()))?;
    Ok(())
}

/// Idempotently register `<registry> → <helper_name>` in `credHelpers`.
/// `helper_name` is the suffix docker uses to compute the binary name:
/// `docker-credential-<helper_name>` must be on PATH at push time.
pub fn set_cred_helper(registry: &str, helper_name: &str) -> Result<()> {
    let mut cfg = load()?;
    cfg.cred_helpers
        .insert(registry.to_string(), helper_name.to_string());
    save(&cfg)
}

/// Inverse of `set_cred_helper`. No-op if the entry isn't there.
/// Returns whether a removal actually happened — for "logged out
/// from N registries" reporting in `enclavid logout`.
pub fn remove_cred_helper(registry: &str) -> Result<bool> {
    let mut cfg = load()?;
    let removed = cfg.cred_helpers.remove(registry).is_some();
    if removed {
        save(&cfg)?;
    }
    Ok(removed)
}
