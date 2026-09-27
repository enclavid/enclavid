//! Local on-disk cache for per-session secrets. Lives at
//! `<config>/enclavid/sessions/<id>/`, `<config>` being the platform
//! config directory `dirs::config_dir()` returns — `$XDG_CONFIG_HOME`
//! or `~/.config` on Linux, `~/Library/Application Support` on macOS,
//! `%APPDATA%` on Windows:
//!
//! * `token` — base64-decoded `client_session_token` from the
//!   POST /sessions response (sent as `X-Session-Token` on every read).
//! * `disclosure.key` — the disclosure secret, when `session create`
//!   generated it or copied it from `--disclosure-key`. Absent when
//!   `--from-file` brought its own recipient and the secret lives with
//!   the caller.
//! * `group` — the group a gateway placed the session on,
//!   `<label>.<build>`, from the POST /sessions response's
//!   `x-enclavid-group`. Later requests put it in their path so the
//!   gateway sends them to the same group. Absent when the session was
//!   created against api directly.
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

use super::is_group;

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

pub fn store_group(session_id: &str, group: &str) -> Result<PathBuf> {
    let dir = session_dir(session_id)?;
    let path = dir.join("group");
    write_secret_file(&path, group.as_bytes())?;
    Ok(path)
}

/// The cached group, or `None` when there is no `group` file — the
/// session was created against api directly, and its requests go
/// there unmarked.
pub fn read_group(session_id: &str) -> Result<Option<String>> {
    let path = session_dir(session_id)?.join("group");
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let group = group_in(&body)
        .with_context(|| format!("{} does not hold a group `<label>.<build>`", path.display()))?;
    Ok(Some(group.to_string()))
}

/// The group a `group` file names, surrounding whitespace dropped.
/// Held to the same check `create` held the gateway's header to before
/// writing it: the file is only as trustworthy as whoever last edited
/// it, and what it holds goes into the path of every later request.
fn group_in(body: &str) -> Option<&str> {
    let group = body.trim();
    is_group(group).then_some(group)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cached_group_is_checked_when_read() {
        let group = format!("blue.{}", "0f".repeat(48));
        assert_eq!(group_in(&format!("{group}\n")), Some(group.as_str()));
        for bad in [
            String::new(),
            " \n".to_string(),
            format!("{group}/x"),
            format!("../{group}"),
        ] {
            assert_eq!(group_in(&bad), None, "{bad:?}");
        }
    }
}
