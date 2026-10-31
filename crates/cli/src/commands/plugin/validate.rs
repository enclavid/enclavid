//! `enclavid plugin validate [dir]` — lint a plugin project's texts against
//! the keys its WIT declares, by the same rules the TEE engine enforces at
//! load, and its models' files against what its slot declares of them. No
//! disclosure fields — a plugin's helpers name fields of the policy's list.
//! Pre-flight before `oci push`. Shares the linter with `policy validate`.

use anyhow::Result;
use std::path::PathBuf;

use crate::declarations::{self, Role};

pub async fn run(dir: PathBuf, i18n: PathBuf, models: PathBuf) -> Result<()> {
    declarations::validate(&dir, &i18n, &models, Role::Plugin)
}
