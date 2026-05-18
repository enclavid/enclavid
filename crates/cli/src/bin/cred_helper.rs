//! `docker-credential-enclavid` — credential helper bridging docker
//! / oras / our own `enclavid policy push` to the Logto-issued
//! Enclavid access token.
//!
//! Protocol (docker-credential-helpers spec):
//!
//!   - argv[1]: action — `get`, `store`, `erase`, `list`.
//!   - stdin: for `get`/`erase`, the registry hostname (no trailing
//!     newline required).
//!   - stdout: for `get`/`list`, a JSON document. `store` reads JSON
//!     from stdin; we don't honor it (creds lifecycle is owned by
//!     `enclavid login`).
//!   - exit code: 0 on success, non-zero with stderr message on
//!     failure.
//!
//! The interesting path is `get`: read the Enclavid registry host
//! from stdin, return a fresh JWT as the Secret field. Internally
//! that goes through the same `auth::get_access_token()` the rest of
//! the CLI uses — `enclavid login` has cached a refresh_token under
//! the user's config dir, and we refresh it on demand when the
//! access_token expires. Stale → stale → 401 in the calling tool,
//! they'll re-run `enclavid login` (we surface a hint then).
//!
//! `store` and `erase` are no-ops in our model: docker calls these
//! after `docker login` to delegate credentials storage to the
//! helper, but our credentials originate from `enclavid login` not
//! from docker. `list` reports the registry we know about, so
//! `docker logout` UIs can offer to clear it.

use std::io::{self, Read, Write};
use std::process::ExitCode;

// Share modules with the main `enclavid` binary via `#[path]`. Each
// binary is its own compile unit, so the dead-code lint here counts
// uses of these modules within cred_helper only (it doesn't know
// `clear_tokens` is used by the `enclavid` binary). Suppress at
// import.
#[path = "../auth.rs"]
#[allow(dead_code)]
mod auth;
#[path = "../config.rs"]
#[allow(dead_code)]
mod config;
#[path = "../discovery.rs"]
#[allow(dead_code)]
mod discovery;

#[tokio::main]
async fn main() -> ExitCode {
    let action = std::env::args().nth(1).unwrap_or_default();
    match dispatch(&action).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("docker-credential-enclavid: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(action: &str) -> anyhow::Result<()> {
    match action {
        "get" => action_get().await,
        "store" => {
            // docker pipes JSON to stdin; consume + discard so its
            // write side doesn't block on EPIPE.
            let _ = io::copy(&mut io::stdin(), &mut io::sink());
            Ok(())
        }
        "erase" => {
            // docker logout — discard stdin (registry hostname),
            // we don't own per-host state to clear.
            let _ = io::copy(&mut io::stdin(), &mut io::sink());
            Ok(())
        }
        "list" => action_list().await,
        other => anyhow::bail!(
            "unknown action `{other}` — expected one of: get, store, erase, list"
        ),
    }
}

/// Mint a fresh JWT for the requested registry. We need discovery
/// to know what scopes/resource to request on refresh. Returns
/// JSON `{"ServerURL":"<reg>","Username":"","Secret":"<jwt>"}` on
/// stdout per the helper spec.
async fn action_get() -> anyhow::Result<()> {
    let mut registry = String::new();
    io::stdin().read_to_string(&mut registry)?;
    let registry = registry.trim();

    discovery::load().await?;
    let token = auth::get_access_token().await?;

    let response = serde_json::json!({
        "ServerURL": registry,
        "Username": "",
        "Secret": token,
    });
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &response)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Return the list of registries this helper has credentials for.
/// Docker uses this for `docker logout` UIs and admin tooling. We
/// publish our discovered Enclavid registry hostname, mapped to the
/// empty username (token-auth convention).
async fn action_list() -> anyhow::Result<()> {
    discovery::load().await?;
    let mut map = serde_json::Map::new();
    if let Some(host) = discovery::get().registry_host() {
        map.insert(host, serde_json::Value::String(String::new()));
    }
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &serde_json::Value::Object(map))?;
    out.write_all(b"\n")?;
    Ok(())
}
