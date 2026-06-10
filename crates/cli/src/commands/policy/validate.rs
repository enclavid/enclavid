//! `enclavid validate [dir]` — lint a policy project's embedded
//! declarations against the same rules the TEE engine enforces at
//! load time.
//!
//! Run before `push` to catch issues at author time with a clean
//! error message instead of an opaque 500 at first /connect.

use anyhow::Result;
use std::path::PathBuf;

use enclavid_embedded::{FILE_DISCLOSURE_FIELDS, FILE_I18N, read_disclosure_fields, read_i18n, validate};

pub async fn run(dir: PathBuf) -> Result<()> {
    let disclosure_path = dir.join(FILE_DISCLOSURE_FIELDS);
    let i18n_path = dir.join(FILE_I18N);

    let disclosure = read_disclosure_fields(&disclosure_path)?;
    let i18n = read_i18n(&i18n_path)?;
    let report = validate(disclosure.as_ref(), i18n.as_ref());

    let disclosure_count = disclosure.as_ref().map(|d| d.fields.len()).unwrap_or(0);
    let i18n_count = i18n.as_ref().map(|i| i.entries.len()).unwrap_or(0);
    let locale_set: std::collections::BTreeSet<&str> = i18n
        .as_ref()
        .map(|i| {
            i.entries
                .values()
                .flat_map(|m| m.keys().map(String::as_str))
                .collect()
        })
        .unwrap_or_default();

    println!("Policy embedded declarations at {}:", dir.display());
    println!(
        "  disclosure-fields: {} ({} entries)",
        match &disclosure {
            Some(_) => disclosure_path.display().to_string(),
            None => format!("{} (absent)", disclosure_path.display()),
        },
        disclosure_count,
    );
    println!(
        "  i18n:              {} ({} entries, {} locale(s))",
        match &i18n {
            Some(_) => i18n_path.display().to_string(),
            None => format!("{} (absent)", i18n_path.display()),
        },
        i18n_count,
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
