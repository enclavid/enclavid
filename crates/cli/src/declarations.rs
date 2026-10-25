//! What `enclavid {policy,plugin} {embed,validate}` share: a project's
//! catalogs — its texts, under `i18n/` or in one `i18n.json`, and for a
//! policy its disclosure fields — checked against the keys its WIT declares by
//! `enclavid_embedded::embed`, the same rules the TEE holds them to at load,
//! and what is wrong printed where it is.
//!
//! Policies and plugins differ by their slot: a policy's is
//! `enclavid-ext:policy`, which holds its texts and its disclosure fields, the
//! cases of its `disclosure-fields` key; a plugin's is named for its package and
//! holds its texts alone. A plugin's helpers take the fields the policy mints.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

use enclavid_embedded::embed::{self, Checked, Project};

/// Which artifact a project is: a policy's slot is `enclavid-ext:policy`,
/// which holds its disclosure fields; a plugin's is named for its package.
#[derive(Clone, Copy)]
pub enum Role {
    Policy,
    Plugin,
}

impl Role {
    fn label(self) -> &'static str {
        match self {
            Role::Policy => "Policy",
            Role::Plugin => "Plugin",
        }
    }
}

/// Check the project whose WIT is `wit` and whose texts are `i18n`, printing
/// what is wrong and what is worth saying.
fn check(wit: PathBuf, i18n: PathBuf, role: Role) -> Result<Checked> {
    let checked = embed::check(&Project {
        wit,
        i18n,
        role: match role {
            Role::Policy => embed::Role::Policy,
            Role::Plugin => embed::Role::Plugin,
        },
    })?;
    for warning in &checked.report.warnings {
        println!("warning: {warning}");
    }
    for error in &checked.report.errors {
        println!("error: {error}");
    }
    Ok(checked)
}

/// Lint the project in `dir`: its `wit/` and its texts at `i18n` in it.
pub fn validate(dir: &Path, i18n: &Path, role: Role) -> Result<()> {
    let checked = check(dir.join("wit"), dir.join(i18n), role)?;
    println!("{} {} at {}:", role.label(), checked.package, dir.display());
    println!("  slot: enclavid-ext:{}", checked.slot);
    println!(
        "  texts: {} key(s), in {}",
        checked.keys.as_ref().map_or(0, Vec::len),
        match checked.languages.as_slice() {
            [] => "no language".to_string(),
            languages => languages.join(", "),
        },
    );
    if matches!(role, Role::Policy) {
        println!(
            "  disclosure fields: {}",
            checked.disclosure_fields.as_ref().map_or(0, Vec::len)
        );
    }
    if !checked.report.ok() {
        bail!(
            "{} error(s) found — fix before pushing.",
            checked.report.errors.len()
        );
    }
    match checked.report.warnings.len() {
        0 => println!("✓ Declarations valid."),
        n => println!("✓ Declarations valid ({n} warning(s))."),
    }
    Ok(())
}

/// Embed the catalogs of the project whose WIT is `wit` and whose texts are
/// `i18n` into the component `wasm`, the texts with the slot they are served
/// through, and write it to `output` (`<input-stem>.embedded.wasm` beside the
/// input by default). `check_role` refuses a component of the other role.
pub fn embed(
    wasm: &Path,
    wit: PathBuf,
    i18n: PathBuf,
    output: Option<PathBuf>,
    role: Role,
    check_role: fn(&[u8]) -> Result<()>,
) -> Result<()> {
    let wasm_bytes = std::fs::read(wasm).with_context(|| format!("reading {}", wasm.display()))?;
    check_role(&wasm_bytes)?;

    let checked = check(wit, i18n, role)?;
    if !checked.report.ok() {
        bail!(
            "the catalogs did not check ({} error(s))",
            checked.report.errors.len()
        );
    }
    let embedded = embed::embed(&wasm_bytes, &checked)?;

    let output_path = output.unwrap_or_else(|| derive_output_path(wasm));
    if output_path.exists() {
        bail!(
            "{} already exists — refusing to overwrite",
            output_path.display()
        );
    }
    std::fs::write(&output_path, &embedded)
        .with_context(|| format!("writing {}", output_path.display()))?;
    println!(
        "Embedded: {} ({} B → {} B, slot enclavid-ext:{}, {} text key(s), {} language(s)) → {}",
        wasm.display(),
        wasm_bytes.len(),
        embedded.len(),
        checked.slot,
        checked.keys.as_ref().map_or(0, Vec::len),
        checked.languages.len(),
        output_path.display(),
    );
    Ok(())
}

fn derive_output_path(wasm: &Path) -> PathBuf {
    let stem = wasm
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "component".to_string());
    let extension = wasm.extension().map(|e| e.to_string_lossy().to_string());
    let mut name = format!("{stem}.embedded");
    if let Some(ext) = extension {
        name.push('.');
        name.push_str(&ext);
    }
    wasm.with_file_name(name)
}
