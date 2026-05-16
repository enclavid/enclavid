//! `enclavid validate [path]` — lint the polici manifest against the
//! same rules the TEE engine enforces at load time.
//!
//! Run before `push` to catch issues at author time with a clean
//! error message instead of an opaque 500 at first /connect.

use anyhow::Result;
use std::path::PathBuf;

use crate::policy_manifest;

pub async fn run(path: PathBuf) -> Result<()> {
    let manifest = policy_manifest::read(&path)?;
    let report = policy_manifest::validate(&manifest);

    let localized_count = manifest.localized.len();
    let locale_set: std::collections::BTreeSet<&str> = manifest
        .localized
        .values()
        .flat_map(|m| m.keys().map(String::as_str))
        .collect();

    println!("Manifest at {}:", path.display());
    println!("  version: {}", manifest.version);
    println!(
        "  {} disclosure field(s), {} localized ref(s), {} locale(s) across all refs",
        manifest.disclosure_fields.len(),
        localized_count,
        locale_set.len(),
    );
    if !locale_set.is_empty() {
        let tags: Vec<&str> = locale_set.iter().copied().collect();
        println!("  Locales: {}", tags.join(", "));
    }
    println!();

    for w in &report.warnings {
        println!("  warning: {w}");
    }
    for e in &report.errors {
        println!("  error: {e}");
    }

    if report.ok() {
        if report.warnings.is_empty() {
            println!("✓ Manifest valid.");
        } else {
            println!(
                "✓ Manifest valid ({} warning(s)).",
                report.warnings.len()
            );
        }
        Ok(())
    } else {
        anyhow::bail!(
            "{} error(s) found — fix before pushing.",
            report.errors.len()
        );
    }
}
