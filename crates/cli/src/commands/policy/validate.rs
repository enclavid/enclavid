//! `enclavid policy validate [dir]` — lint a policy project's embedded
//! declarations (disclosure-fields / i18n / icons) against the same
//! rules the TEE engine enforces at load. Pre-flight before `oci push`
//! to catch a malformed declaration at author time instead of an opaque
//! 500 at first `/connect`. Shares the linter with `plugin validate`.

use anyhow::Result;
use std::path::PathBuf;

pub async fn run(dir: PathBuf) -> Result<()> {
    crate::declarations::validate_dir(&dir, true, "Policy")
}
