//! Shared declaration-file linter for `enclavid policy validate` and
//! `enclavid plugin validate`. Reads the embedded-section JSONs in a
//! project dir and runs `enclavid_embedded::validate` — the same rules
//! the TEE engine enforces at load — then prints a summary.
//!
//! Policies and plugins differ by exactly one input: `disclosure-fields`
//! is policy-only (the policy is the single bandwidth gate to the
//! consumer, Option C). Plugins pass `with_disclosure_fields = false`,
//! which skips reading it and omits it from the summary.

use anyhow::Result;
use std::path::Path;

use enclavid_embedded::{
    FILE_DISCLOSURE_FIELDS, FILE_I18N, FILE_ICONS, read_disclosure_fields, read_i18n, read_icons,
    validate,
};

/// Lint the embedded declarations under `dir`. `label` is the artifact
/// kind shown in the summary header ("Policy" / "Plugin").
pub fn validate_dir(dir: &Path, with_disclosure_fields: bool, label: &str) -> Result<()> {
    let i18n_path = dir.join(FILE_I18N);
    let icons_path = dir.join(FILE_ICONS);
    let disclosure_path = dir.join(FILE_DISCLOSURE_FIELDS);

    // disclosure-fields only applies to policies.
    let disclosure = if with_disclosure_fields {
        read_disclosure_fields(&disclosure_path)?
    } else {
        None
    };
    let i18n = read_i18n(&i18n_path)?;
    let icons = read_icons(&icons_path)?;
    let report = validate(disclosure.as_ref(), i18n.as_ref(), icons.as_ref());

    let i18n_count = i18n.as_ref().map(|i| i.entries.len()).unwrap_or(0);
    let icons_count = icons.as_ref().map(|i| i.names.len()).unwrap_or(0);
    let locale_set: std::collections::BTreeSet<&str> = i18n
        .as_ref()
        .map(|i| {
            i.entries
                .values()
                .flat_map(|m| m.keys().map(String::as_str))
                .collect()
        })
        .unwrap_or_default();

    println!("{label} embedded declarations at {}:", dir.display());
    if with_disclosure_fields {
        let disclosure_count = disclosure.as_ref().map(|d| d.fields.len()).unwrap_or(0);
        println!(
            "  disclosure-fields: {} ({} entries)",
            match &disclosure {
                Some(_) => disclosure_path.display().to_string(),
                None => format!("{} (absent)", disclosure_path.display()),
            },
            disclosure_count,
        );
    }
    println!(
        "  i18n:              {} ({} entries, {} locale(s))",
        match &i18n {
            Some(_) => i18n_path.display().to_string(),
            None => format!("{} (absent)", i18n_path.display()),
        },
        i18n_count,
        locale_set.len(),
    );
    println!(
        "  icons:             {} ({} entries)",
        match &icons {
            Some(_) => icons_path.display().to_string(),
            None => format!("{} (absent)", icons_path.display()),
        },
        icons_count,
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
            println!("✓ Declarations valid.");
        } else {
            println!(
                "✓ Declarations valid ({} warning(s)).",
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
