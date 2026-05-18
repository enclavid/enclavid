//! `enclavid cloud workspace` — show / list / use the active
//! workspace. The list is cached locally from the most recent
//! `enclavid cloud login`; switching is purely local (a write to
//! the same `auth.json` the cred helper reads), no network call.

use anyhow::{Context, Result};

use crate::auth::{read_stored_tokens, store_tokens};
use crate::commands::cloud::login::{display_name, match_workspace};
use crate::discovery;

/// Default bare `enclavid cloud workspace` action: print the active
/// workspace plus the registry push-prefix derived from it.
pub async fn show() -> Result<()> {
    let tokens = require_login()?;
    let active_id = tokens
        .active_workspace_id
        .as_ref()
        .context("no active workspace — run `enclavid cloud workspace use <id-or-name>`")?;
    let active = tokens
        .workspaces
        .iter()
        .find(|w| &w.id == active_id)
        .context("active workspace id not present in cached workspaces list — re-run `enclavid cloud login`")?;

    println!("Active workspace: {} ({})", display_name(active), active.id);
    if let Some(host) = discovery::try_get().and_then(|d| d.registry_host()) {
        println!(
            "Push prefix:      {host}/enclavid/{}/policies/<name>:<tag>",
            active.id,
        );
    }
    Ok(())
}

/// List all workspaces the user is a member of, marking the active
/// one. Cached locally — no network call.
pub async fn list() -> Result<()> {
    let tokens = require_login()?;
    let active_id = tokens.active_workspace_id.as_deref();
    let mut max_name = 0usize;
    for w in &tokens.workspaces {
        let n = display_name(w).chars().count();
        if n > max_name {
            max_name = n;
        }
    }
    for w in &tokens.workspaces {
        let marker = if Some(w.id.as_str()) == active_id {
            "*"
        } else {
            " "
        };
        println!(
            "{marker} {name:<width$}  {id}",
            name = display_name(w),
            width = max_name,
            id = w.id,
        );
    }
    Ok(())
}

/// Switch the active workspace by id (exact match) or name substring
/// (case-insensitive). On success, subsequent cred-helper invocations
/// mint tokens scoped to this workspace — so the next `docker push` /
/// `enclavid policy push` lands in the new namespace immediately.
pub async fn use_workspace(needle: &str) -> Result<()> {
    let mut tokens = require_login()?;
    let chosen = match_workspace(&tokens.workspaces, needle)?;
    let chosen_id = chosen.id.clone();
    let chosen_name = display_name(chosen).to_string();

    tokens.active_workspace_id = Some(chosen_id.clone());
    // Invalidate the cached access_token: it was minted with the
    // previous workspace's organization_id claim, so any cred-helper
    // request before its natural expiry would otherwise hand a stale
    // (wrong-workspace) JWT to docker / oras / push. Setting
    // expires_at = 0 forces `auth::get_access_token` to take the
    // refresh path on the next call, where `refresh_access_token`
    // reads the now-updated `active_workspace_id` and re-mints scoped
    // to the new workspace.
    tokens.expires_at = 0;
    store_tokens(&tokens)?;

    println!("✓ Switched to {chosen_name} ({chosen_id}).");
    if let Some(host) = discovery::try_get().and_then(|d| d.registry_host()) {
        println!(
            "  Push prefix: {host}/enclavid/{chosen_id}/policies/<name>:<tag>",
        );
    }
    Ok(())
}

fn require_login() -> Result<crate::auth::StoredTokens> {
    read_stored_tokens()?
        .context("not authenticated — run `enclavid cloud login` first")
}
