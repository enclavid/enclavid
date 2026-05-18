use anyhow::{Context, Result};
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;
use openidconnect::core::{CoreClient, CoreDeviceAuthorizationResponse};
use openidconnect::{ClientId, OAuth2TokenResponse, Scope};
use std::io::IsTerminal;
use std::time::Duration;

use crate::auth::{Workspace, StoredTokens, store_tokens, workspaces_from_id_token};
use crate::{discovery, docker_config};

/// `credHelpers` value docker writes to `~/.docker/config.json`. The
/// helper binary is `docker-credential-<this>` — must be on PATH for
/// docker / oras / `enclavid policy push` to invoke it.
const CRED_HELPER_NAME: &str = "enclavid";

pub async fn run(workspace_pref: Option<String>) -> Result<()> {
    let d = discovery::get();
    let http = discovery::http_client()?;

    let device_url = d
        .provider_metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone();

    let client = CoreClient::from_provider_metadata(
        d.provider_metadata.clone(),
        ClientId::new(d.cli_client_id.clone()),
        None,
    )
    .set_device_authorization_url(device_url);

    let mut request = client.exchange_device_code();
    for scope in &d.scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    // Request registry scopes up-front so the refresh_token grant covers
    // them on subsequent exchanges (Logto requires refresh scopes to be a
    // subset of the originally-granted scopes — see memory
    // `project_logto_refresh_scope.md`).
    for scope in &d.registry_scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    request = request.add_extra_param("resource", d.registry_resource.clone());

    let details: CoreDeviceAuthorizationResponse = request
        .request_async(&http)
        .await
        .context("requesting device code")?;

    let display_url = details
        .verification_uri_complete()
        .map(|u| u.secret().clone())
        .unwrap_or_else(|| details.verification_uri().to_string());

    println!("To authenticate, visit:\n  {display_url}");
    println!("Code (in case it's not auto-filled): {}", details.user_code().secret());
    println!("\n(Opening browser automatically...)\n");
    let _ = open::that(&display_url);

    let token_response = client
        .exchange_device_access_token(&details)
        .context("preparing device access token request")?
        .add_extra_param("resource", d.registry_resource.clone())
        .request_async(&http, async_sleep, None)
        .await
        .context("polling for token")?;

    let id_token = token_response
        .extra_fields()
        .id_token()
        .map(|t| t.to_string());

    // Harvest workspace list from id_token claims (Logto-specific
    // `organization_data`). Empty list = user is not a member of any
    // organization — bail with a console hint.
    let workspaces = id_token
        .as_ref()
        .map(|t| workspaces_from_id_token(t))
        .unwrap_or_default();

    if workspaces.is_empty() {
        anyhow::bail!(
            "authenticated, but you are not a member of any Enclavid workspace.\n\
             Join one in the console (or have an admin invite you), then retry login."
        );
    }

    // Resolve the active workspace per `--workspace` flag → picker →
    // single-workspace fast path. Picker is only shown when stdin is
    // a TTY *and* the user has 2+ workspaces. Non-TTY + multi-workspace
    // without --workspace → bail with guidance.
    let active = resolve_active_workspace(&workspaces, workspace_pref.as_deref())?;

    // Two-stage persist:
    //
    //   1. Save refresh_token + active_workspace_id with expires_at=0.
    //      The device-flow access_token from `exchange_device_access_token`
    //      lacks the `organization_id` claim (Logto's device-code grant
    //      doesn't take an `organization_id` parameter, and we don't know
    //      the workspace until the picker above resolves it). Angos's
    //      access policy keys off that claim, so this token can't push
    //      against `enclavid/<workspace_id>/policies/...`.
    //
    //   2. Immediately invoke `get_access_token()` which reads the
    //      now-persisted `active_workspace_id`, runs a refresh_token grant
    //      with `organization_id=<id>`, and writes the resulting
    //      org-scoped JWT back to disk. From that point on cred helper
    //      hands docker / oras / push a token Angos accepts.
    //
    // Failing here aborts login — preferable to silently leaving an
    // unusable session where every push fails 401 with no obvious cause.
    let initial = StoredTokens {
        access_token: String::new(),
        refresh_token: token_response
            .refresh_token()
            .map(|t| t.secret().clone()),
        id_token,
        expires_at: 0,
        workspaces: workspaces.clone(),
        active_workspace_id: Some(active.id.clone()),
    };
    store_tokens(&initial)?;

    crate::auth::get_access_token()
        .await
        .context("minting workspace-scoped access token (refresh after device flow)")?;

    // Register `docker-credential-enclavid` for the Enclavid registry.
    // Docker / oras / our own push will subprocess it on every push
    // to fetch a fresh JWT — no manual relogin once tokens expire.
    let helper_status = match discovery::get().registry_host() {
        Some(host) => match docker_config::set_cred_helper(&host, CRED_HELPER_NAME) {
            Ok(()) => Some(host),
            Err(e) => {
                eprintln!(
                    "warning: could not register credential helper in ~/.docker/config.json ({e}). \
                     Use --auth or ENCLAVID_REGISTRY_AUTH when pushing.",
                );
                None
            }
        },
        None => {
            eprintln!(
                "warning: no registry hostname in discovery; credHelper not registered. \
                 Use --auth or ENCLAVID_REGISTRY_AUTH when pushing.",
            );
            None
        }
    };

    println!("✓ Authenticated.");
    println!(
        "  Active workspace: {} ({})",
        display_name(active),
        active.id,
    );
    if let Some(host) = helper_status {
        println!(
            "  Push prefix:      {host}/enclavid/{}/policies/<name>:<tag>",
            active.id,
        );
        println!(
            "  Registered docker-credential-enclavid for {host} — docker / oras / \
             `enclavid policy push` refresh tokens automatically.",
        );
    }
    Ok(())
}

/// Pick the active workspace from the list. Priority:
///   1. `--workspace <id-or-substring>` flag (or `ENCLAVID_WORKSPACE_ID`
///      env var) — must match exactly one entry.
///   2. Single workspace → silent auto-confirm.
///   3. TTY + multiple workspaces → interactive picker.
///   4. Non-TTY + multiple workspaces → bail with guidance.
fn resolve_active_workspace<'a>(
    workspaces: &'a [Workspace],
    pref: Option<&str>,
) -> Result<&'a Workspace> {
    let env_pref = std::env::var(crate::auth::ENV_WORKSPACE_ID).ok();
    let pref = pref.or(env_pref.as_deref());

    if let Some(needle) = pref {
        return match_workspace(workspaces, needle);
    }
    if workspaces.len() == 1 {
        return Ok(&workspaces[0]);
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "multiple workspaces available and stdin isn't a TTY.\n\
             Re-run with `--workspace <id-or-substring>`, \
             or set {}=<id> in the environment.\n\
             Available: {}",
            crate::auth::ENV_WORKSPACE_ID,
            workspaces
                .iter()
                .map(|w| format!("{} ({})", display_name(w), w.id))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    pick_interactive(workspaces)
}

fn pick_interactive(workspaces: &[Workspace]) -> Result<&Workspace> {
    let items: Vec<String> = workspaces
        .iter()
        .map(|w| format!("{}  ({})", display_name(w), w.id))
        .collect();
    let chosen = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select workspace")
        .items(&items)
        .default(0)
        .interact()
        .context("interactive selection failed")?;
    Ok(&workspaces[chosen])
}

/// Resolve `id_or_name` to exactly one workspace. Exact id match
/// wins; otherwise case-insensitive substring match against name. On
/// 0 matches: bail with full list. On >1 matches: bail with the
/// ambiguous subset.
pub fn match_workspace<'a>(
    workspaces: &'a [Workspace],
    needle: &str,
) -> Result<&'a Workspace> {
    if let Some(w) = workspaces.iter().find(|w| w.id == needle) {
        return Ok(w);
    }
    let lower = needle.to_lowercase();
    let candidates: Vec<&Workspace> = workspaces
        .iter()
        .filter(|w| w.name.to_lowercase().contains(&lower))
        .collect();
    match candidates.as_slice() {
        [w] => Ok(*w),
        [] => anyhow::bail!(
            "no workspace matched `{needle}`.\nAvailable: {}",
            workspaces
                .iter()
                .map(|w| format!("{} ({})", display_name(w), w.id))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        many => anyhow::bail!(
            "ambiguous: `{needle}` matched {} workspaces.\nNarrow down: {}",
            many.len(),
            many.iter()
                .map(|w| format!("{} ({})", display_name(w), w.id))
                .collect::<Vec<_>>()
                .join(", "),
        ),
    }
}

pub fn display_name(w: &Workspace) -> &str {
    if w.name.is_empty() {
        &w.id
    } else {
        &w.name
    }
}

async fn async_sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}
