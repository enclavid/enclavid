//! `enclavid plugin embed` — writes the plugin's texts (`i18n/`, one JSON
//! file per language) into its wasm component, checked against the keys its
//! slot declares: `enclavid-ext:<name>`, named for the plugin's package.
//!
//! Same mechanics as `enclavid policy embed`, minus disclosure fields: a
//! plugin's helpers take the fields the policy mints, so plugins don't declare
//! their own. Texts stay per-slot because they are applicant-facing only — the
//! consumer never sees them.

use anyhow::Result;
use std::path::PathBuf;

use crate::declarations::{self, Role};

pub fn run(wasm: PathBuf, wit: PathBuf, i18n: PathBuf, output: Option<PathBuf>) -> Result<()> {
    // Role gate: this component must NOT be a policy (it must not export
    // `enclavid:policy/policy`). A policy handed to `plugin embed` is rejected
    // with a pointer to `policy embed`.
    declarations::embed(
        &wasm,
        wit,
        i18n,
        output,
        Role::Plugin,
        crate::wit_role::assert_plugin,
    )
}
