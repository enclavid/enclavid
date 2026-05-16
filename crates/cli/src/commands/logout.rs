use anyhow::Result;

use crate::auth;

pub async fn run() -> Result<()> {
    if auth::clear_tokens()? {
        println!("✓ Logged out — local credentials removed.");
    } else {
        println!("Already logged out (no local credentials found).");
    }
    Ok(())
}
