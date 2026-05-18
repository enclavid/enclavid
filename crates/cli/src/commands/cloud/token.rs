use anyhow::Result;

use crate::auth;

pub async fn run() -> Result<()> {
    let token = auth::get_access_token().await?;
    println!("{}", token);
    Ok(())
}
