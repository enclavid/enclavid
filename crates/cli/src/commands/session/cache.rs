//! Local on-disk cache for per-session secrets. Lives at
//! `~/.config/enclavid/sessions/<id>/`:
//!
//!   * `token`           — base64-decoded `client_session_token` from
//!                         POST /sessions response (sent as
//!                         `X-Session-Token` on every read).
//!   * `disclosure.key`  — age secret-key when `session create` had to
//!                         auto-generate the disclosure recipient.
//!                         Absent when the user supplied `--disclosure-key`
//!                         and the secret lives in their own keystore.
//!
//! Mode `0700` directory + `0600` files — same posture as `auth.json`.
//! No mtime/atime maintenance, no concurrent-access locking — sessions
//! are written once at create and read N times after; concurrent
//! `session create` for the same id wouldn't happen in practice.

use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub fn session_dir(session_id: &str) -> Result<PathBuf> {
    let base = dirs::config_dir().context("no config dir on this platform")?;
    Ok(base.join("enclavid").join("sessions").join(session_id))
}

fn write_secret_file(path: &PathBuf, body: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        // Tighten the parent dir mode if we just created it. Pre-
        // existing dirs are left alone (avoid mode rewrite races).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    f.write_all(body)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub fn store_session_token(session_id: &str, token_b64: &str) -> Result<PathBuf> {
    let dir = session_dir(session_id)?;
    let path = dir.join("token");
    write_secret_file(&path, token_b64.as_bytes())?;
    Ok(path)
}

pub fn read_session_token(session_id: &str) -> Result<String> {
    let path = session_dir(session_id)?.join("token");
    let body = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} — was the session created with this CLI? (file holds the X-Session-Token)",
            path.display(),
        )
    })?;
    Ok(body.trim().to_string())
}

pub fn store_disclosure_key(session_id: &str, secret_key_str: &str) -> Result<PathBuf> {
    let dir = session_dir(session_id)?;
    let path = dir.join("disclosure.key");
    write_secret_file(&path, secret_key_str.as_bytes())?;
    Ok(path)
}

pub fn read_disclosure_key_path(session_id: &str) -> Result<PathBuf> {
    Ok(session_dir(session_id)?.join("disclosure.key"))
}
