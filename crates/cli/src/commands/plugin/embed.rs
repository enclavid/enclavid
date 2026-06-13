//! `enclavid plugin embed` — appends the plugin's
//! `enclavid:embedded.{i18n,icons}.v1` declarations to a wasm
//! component as custom sections.
//!
//! Same mechanics as `enclavid policy embed`, minus `disclosure-fields`:
//! under Option C the policy is the single source of truth for what's
//! disclosable to the consumer, so plugins don't declare their own
//! DF keys (see `[[project-df-policy-gated]]`). i18n and icons stay
//! per-component because they're applicant-facing only — consumer
//! never sees these refs.

use anyhow::{Context, Result};
use std::path::PathBuf;

use enclavid_embedded::{read_bytes, read_i18n, read_icons, validate};

use crate::embed::embed_sections;

pub fn run(
    wasm: PathBuf,
    i18n_path: PathBuf,
    icons_path: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let wasm_bytes = std::fs::read(&wasm)
        .with_context(|| format!("reading {}", wasm.display()))?;

    let parsed_i18n = read_i18n(&i18n_path)
        .with_context(|| format!("reading {}", i18n_path.display()))?;
    let parsed_icons = read_icons(&icons_path)
        .with_context(|| format!("reading {}", icons_path.display()))?;
    // No DF section for plugins — pass None to skip validation of
    // that kind.
    let report = validate(None, parsed_i18n.as_ref(), parsed_icons.as_ref());
    for w in &report.warnings {
        println!("warning: {w}");
    }
    if !report.ok() {
        for e in &report.errors {
            println!("error: {e}");
        }
        anyhow::bail!(
            "embedded-sections validation failed ({} error(s))",
            report.errors.len(),
        );
    }

    let i18n_bytes = if parsed_i18n.is_some() {
        Some(read_bytes(&i18n_path)?)
    } else {
        None
    };
    let icons_bytes = if parsed_icons.is_some() {
        Some(read_bytes(&icons_path)?)
    } else {
        None
    };

    let embedded = embed_sections(
        &wasm_bytes,
        // No disclosure-fields section for plugins.
        None,
        i18n_bytes.as_deref(),
        icons_bytes.as_deref(),
    );

    let output_path = output.unwrap_or_else(|| derive_output_path(&wasm));
    if output_path.exists() {
        anyhow::bail!(
            "{} already exists — refusing to overwrite",
            output_path.display()
        );
    }
    std::fs::write(&output_path, &embedded)
        .with_context(|| format!("writing {}", output_path.display()))?;

    let i18n_len = i18n_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
    let icons_len = icons_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
    println!(
        "Embedded: {} (wasm {} B + i18n {} B + icons {} B → {} B) → {}",
        wasm.display(),
        wasm_bytes.len(),
        i18n_len,
        icons_len,
        embedded.len(),
        output_path.display(),
    );

    Ok(())
}

fn derive_output_path(wasm: &PathBuf) -> PathBuf {
    let stem = wasm
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "plugin".to_string());
    let extension = wasm.extension().map(|e| e.to_string_lossy().to_string());
    let mut name = format!("{stem}.embedded");
    if let Some(ext) = extension {
        name.push('.');
        name.push_str(&ext);
    }
    wasm.with_file_name(name)
}
