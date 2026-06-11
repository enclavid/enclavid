//! `enclavid policy seal` — bundles a wasm policy component with its
//! optional embedded text-ref declarations, then age-encrypts the
//! result. "Seal" because the step both binds (wasm + declarations
//! cryptographically welded) and locks (age-encrypted to the
//! client's key) — once sealed, the artifact is ready for shipping.
//!
//! Bundling: each declarations file is appended to the wasm as its
//! own component-level custom section:
//!
//!   * `enclavid:embedded.disclosure-fields.v1` — flat list of
//!     identifiers.
//!   * `enclavid:embedded.i18n.v1` — translation catalog.
//!
//! Both sections are independently optional. A policy without
//! `prompt-disclosure` calls can ship without `disclosure-fields.json`;
//! a policy without UI text refs can ship without `i18n.json`. Custom
//! sections are spec-defined as arbitrary metadata that wasm runtimes
//! ignore for execution — wasmtime will compile the component as if
//! the sections weren't there. The TEE extracts whichever sections
//! are present at /connect time via `enclavid_engine::load_embedded`.
//!
//! Rationale: a single self-contained `.age` file is the unit of
//! distribution. After seal, push doesn't need declarations flags,
//! OCI artifacts have a single layer, and there's no way for the
//! wasm and the declarations to drift out of sync — they're
//! cryptographically welded together by the age envelope.

use age::Encryptor;
use age::x25519::Identity;
use anyhow::{Context, Result};
use std::borrow::Cow;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use wasm_encoder::ComponentSection;

use enclavid_embedded::{
    SECTION_DISCLOSURE_FIELDS, SECTION_I18N, SECTION_ICONS, read_bytes,
    read_disclosure_fields, read_i18n, read_icons, validate,
};

pub fn run(
    wasm: PathBuf,
    key: PathBuf,
    disclosure_fields_path: PathBuf,
    i18n_path: PathBuf,
    icons_path: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let identity = read_identity(&key)
        .with_context(|| format!("reading key from {}", key.display()))?;
    let recipient = identity.to_public();

    let wasm_bytes = std::fs::read(&wasm)
        .with_context(|| format!("reading {}", wasm.display()))?;

    // Parse + validate whatever sections the author supplied. All
    // three are independently optional — `read_*` return None for an
    // absent file, validation runs over whatever's present.
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
    // whichever section files exist, so wasm custom-section bytes are
    // byte-identical to the on-disk source — content-addressing of
    // the sealed artifact is reproducible from the source.
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

    let bundled = bundle_with_sections(
        &wasm_bytes,
        disclosure_bytes.as_deref(),
        i18n_bytes.as_deref(),
        icons_bytes.as_deref(),
    );
    let plaintext_digest = sha256_hex(&bundled);

    let output_path = output.unwrap_or_else(|| derive_output_path(&wasm));
    if output_path.exists() {
        anyhow::bail!(
            "{} already exists — refusing to overwrite",
            output_path.display()
        );
    }

    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .context("building age encryptor")?;

    let mut out_file = File::create(&output_path)
        .with_context(|| format!("creating {}", output_path.display()))?;
    let mut writer = encryptor
        .wrap_output(&mut out_file)
        .context("initializing age writer")?;
    writer.write_all(&bundled).context("writing ciphertext")?;
    writer.finish().context("finalizing age envelope")?;
    drop(out_file);

    let ciphertext = std::fs::read(&output_path).context("re-reading ciphertext for digest")?;
    let ciphertext_digest = sha256_hex(&ciphertext);

    let disclosure_len = disclosure_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
    let i18n_len = i18n_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
    let icons_len = icons_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
    println!(
        "Encrypted: {} (wasm {} B + disclosure-fields {} B + i18n {} B + icons {} B \
         → bundled {} B) → {}",
        wasm.display(),
        wasm_bytes.len(),
        disclosure_len,
        i18n_len,
        icons_len,
        bundled.len(),
        output_path.display(),
    );
    println!("D_plain (sha256 of bundled plaintext):  {}", plaintext_digest);
    println!("D_enc   (sha256 of ciphertext):         {}", ciphertext_digest);
    println!();
    println!("Save D_plain — needed for session attestation verification later.");

    Ok(())
}

/// Append the embedded declarations as component-level custom
/// sections to the wasm component bytes. `wasm-encoder::CustomSection`
/// writes the canonical encoding (`0x00` section id + LEB128-prefixed
/// name and payload); we just stitch its output onto the tail of the
/// existing bytes.
///
/// Custom sections per the WASM core spec can appear anywhere
/// (before, between, or after standard sections). Appending at the
/// end keeps us from re-parsing the existing wasm and matches the
/// convention LLVM/rustc/cargo-component already follow for `name` /
/// `producers` sections.
///
/// Sections are appended only when their source files were present;
/// absent files simply produce no section, and the TEE-side loader
/// treats the missing section as "no declarations of this kind".
fn bundle_with_sections(
    wasm_bytes: &[u8],
    disclosure: Option<&[u8]>,
    i18n: Option<&[u8]>,
    icons: Option<&[u8]>,
) -> Vec<u8> {
    let extra_capacity = disclosure.map(|b| b.len()).unwrap_or(0)
        + i18n.map(|b| b.len()).unwrap_or(0)
        + icons.map(|b| b.len()).unwrap_or(0)
        + 96;
    let mut bundled = Vec::with_capacity(wasm_bytes.len() + extra_capacity);
    bundled.extend_from_slice(wasm_bytes);
    if let Some(bytes) = disclosure {
        wasm_encoder::CustomSection {
            name: Cow::Borrowed(SECTION_DISCLOSURE_FIELDS),
            data: Cow::Borrowed(bytes),
        }
        .append_to_component(&mut bundled);
    }
    if let Some(bytes) = i18n {
        wasm_encoder::CustomSection {
            name: Cow::Borrowed(SECTION_I18N),
            data: Cow::Borrowed(bytes),
        }
        .append_to_component(&mut bundled);
    }
    if let Some(bytes) = icons {
        wasm_encoder::CustomSection {
            name: Cow::Borrowed(SECTION_ICONS),
            data: Cow::Borrowed(bytes),
        }
        .append_to_component(&mut bundled);
    }
    bundled
}

fn read_identity(path: &PathBuf) -> Result<Identity> {
    let mut content = String::new();
    File::open(path)?.read_to_string(&mut content)?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return Identity::from_str(trimmed)
            .map_err(|e| anyhow::anyhow!("invalid age identity: {e}"));
    }
    anyhow::bail!("no AGE-SECRET-KEY line found in key file")
}

fn derive_output_path(wasm: &PathBuf) -> PathBuf {
    let mut s = wasm.as_os_str().to_owned();
    s.push(".age");
    PathBuf::from(s)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
