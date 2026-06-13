//! `enclavid policy embed` — appends the policy's
//! `enclavid:embedded.*.v1` declarations (disclosure-fields, i18n,
//! icons) to a wasm component as custom sections.
//!
//! Pure metadata embedding — no encryption, no signing. The output is
//! a wasm component, suitable as input to `enclavid policy encrypt`
//! (age-encrypts the whole component under `client_policy_key`) or
//! pushed as-is for an unencrypted/dev artifact.
//!
//! All three section files are independently optional. A policy
//! without `prompt-disclosure` calls can omit `disclosure-fields.json`;
//! one without UI text refs can omit `i18n.json`; one that never sets
//! `CaptureStep.icon` can omit `icons.json`. An absent file is silently
//! treated as "no declarations of this kind" — the TEE-side loader
//! sees the missing section as an empty registry slot for that kind.

use anyhow::{Context, Result};
use std::path::PathBuf;

use enclavid_embedded::{read_bytes, read_disclosure_fields, read_i18n, read_icons, validate};

use crate::embed::embed_sections;

pub fn run(
    wasm: PathBuf,
    disclosure_fields_path: PathBuf,
    i18n_path: PathBuf,
    icons_path: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let wasm_bytes = std::fs::read(&wasm)
        .with_context(|| format!("reading {}", wasm.display()))?;

    // Parse + validate whatever sections the author supplied. All
    // three are independently optional — `read_*` return None for
    // an absent file, validation runs over whatever's present.
    let parsed_disclosure = read_disclosure_fields(&disclosure_fields_path)
        .with_context(|| format!("reading {}", disclosure_fields_path.display()))?;
    let parsed_i18n = read_i18n(&i18n_path)
        .with_context(|| format!("reading {}", i18n_path.display()))?;
    let parsed_icons = read_icons(&icons_path)
        .with_context(|| format!("reading {}", icons_path.display()))?;
    let report = validate(
        parsed_disclosure.as_ref(),
        parsed_i18n.as_ref(),
        parsed_icons.as_ref(),
    );
    for w in &report.warnings {
        println!("warning: {w}");
    }
    if !report.ok() {
        for e in &report.errors {
            println!("error: {e}");
        }
        anyhow::bail!(
            "embedded-sections validation failed ({} error(s)) — \
             run `enclavid policy validate <dir>` for the full report",
            report.errors.len(),
        );
    }

    // Read the raw on-disk bytes (verbatim, never re-serialized) of
    // whichever section files exist, so wasm custom-section bytes
    // are byte-identical to the on-disk source — content-addressing
    // of the embedded artifact is reproducible from the source.
    let disclosure_bytes = if parsed_disclosure.is_some() {
        Some(read_bytes(&disclosure_fields_path)?)
    } else {
        None
    };
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
        disclosure_bytes.as_deref(),
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

    let disclosure_len = disclosure_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
    let i18n_len = i18n_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
    let icons_len = icons_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
    println!(
        "Embedded: {} (wasm {} B + disclosure-fields {} B + i18n {} B + icons {} B \
         → {} B) → {}",
        wasm.display(),
        wasm_bytes.len(),
        disclosure_len,
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
        .unwrap_or_else(|| "policy".to_string());
    let extension = wasm.extension().map(|e| e.to_string_lossy().to_string());
    let mut name = format!("{stem}.embedded");
    if let Some(ext) = extension {
        name.push('.');
        name.push_str(&ext);
    }
    wasm.with_file_name(name)
}
