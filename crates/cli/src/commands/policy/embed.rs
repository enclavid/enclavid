//! `enclavid policy embed` — writes the policy's catalogs into its wasm
//! component: its texts (`i18n/`, one JSON file per language) and its
//! disclosure fields (the cases of its `enclavid-ext:policy/disclosure-fields`
//! key), each checked against the keys its slot, `enclavid-ext:policy`,
//! declares.
//!
//! Pure metadata embedding — no encryption, no signing. The output is a wasm
//! component, ready for `enclavid oci push`.

use anyhow::Result;
use std::path::PathBuf;

use crate::declarations::{self, Role};

pub fn run(wasm: PathBuf, wit: PathBuf, i18n: PathBuf, output: Option<PathBuf>) -> Result<()> {
    // Role gate: this component must export the `enclavid:policy/policy`
    // world. A plugin handed to `policy embed` is rejected (with a pointer to
    // `plugin embed`) — the artifacts are otherwise identical on the wire, so
    // this WIT check is what keeps the groups honest.
    declarations::embed(
        &wasm,
        wit,
        i18n,
        output,
        Role::Policy,
        crate::wit_role::assert_policy,
    )
}
