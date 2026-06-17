//! `enclavid plugin validate [dir]` — lint a plugin project's embedded
//! declarations (i18n / icons) against the same rules the TEE engine
//! enforces at load. No `disclosure-fields` — the policy is the single
//! bandwidth gate for disclosure-field refs (Option C). Pre-flight
//! before `oci push`. Shares the linter with `policy validate`.

use anyhow::Result;
use std::path::PathBuf;

pub async fn run(dir: PathBuf) -> Result<()> {
    crate::declarations::validate_dir(&dir, false, "Plugin")
}
