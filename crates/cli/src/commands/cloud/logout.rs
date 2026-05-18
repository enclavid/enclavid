use anyhow::Result;

use crate::{auth, discovery, docker_config};

pub async fn run() -> Result<()> {
    let cleared_tokens = auth::clear_tokens()?;

    // Symmetric with `login`: tear down the credHelper entry from
    // ~/.docker/config.json. Errors logged but not fatal — the
    // primary outcome is "local creds gone".
    let cleared_helper = match discovery::get().registry_host() {
        Some(host) => match docker_config::remove_cred_helper(&host) {
            Ok(true) => Some(host),
            Ok(false) => None,
            Err(e) => {
                eprintln!(
                    "warning: could not remove credential helper entry for {host}: {e}",
                );
                None
            }
        },
        None => None,
    };

    match (cleared_tokens, cleared_helper) {
        (true, Some(host)) => println!(
            "✓ Logged out — local credentials removed, credHelper unregistered for {host}.",
        ),
        (true, None) => println!("✓ Logged out — local credentials removed."),
        (false, Some(host)) => {
            println!("✓ credHelper unregistered for {host} (no local credentials to clear).")
        }
        (false, None) => println!("Already logged out (no local credentials found)."),
    }
    Ok(())
}
