//! `enclavid policy validate [dir]` — lint a policy project's catalogs (its
//! texts and its disclosure fields) against the keys its WIT declares, by the
//! same rules the TEE engine enforces at load, and its models' files against
//! what its slot declares of them. Pre-flight before `oci push` to catch a
//! malformed catalog, or a model a round would refuse, at author time instead
//! of in a session. Shares the linter with `plugin validate`.

use anyhow::Result;
use std::path::PathBuf;

use crate::declarations::{self, Role};

pub async fn run(dir: PathBuf, i18n: PathBuf, models: PathBuf) -> Result<()> {
    declarations::validate(&dir, &i18n, &models, Role::Policy)
}
