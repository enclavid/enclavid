//! `enclavid policy seal` — bundles a wasm policy component with
//! its manifest, then age-encrypts the result. "Seal" because the
//! step both binds (wasm + manifest cryptographically welded) and
//! locks (age-encrypted to the client's key) — once sealed, the
//! artifact is ready for shipping.
//!
//! Bundling: the manifest JSON is appended to the wasm as a
//! component-level custom section (`enclavid:policy-manifest.v1`).
//! Custom sections are spec-defined as arbitrary metadata that wasm
//! runtimes ignore for execution — wasmtime will compile the
//! component as if the section weren't there. The TEE extracts the
//! manifest from this section at /connect time
//! (see `crates/api/src/policy_pull.rs`).
//!
//! Rationale: a single self-contained `.age` file is the unit of
//! distribution. After seal, push doesn't need a `--manifest` flag,
//! OCI artifacts have a single layer, and there's no way for the
//! wasm and the manifest to drift out of sync — they're
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

use crate::policy_manifest;

/// Component-level custom section name. Namespaced with `enclavid:`
/// for hygiene against unrelated tooling, dot-separated `.v1` so
/// future schema bumps can ship parallel `.v2` sections during
/// transitions if needed.
const MANIFEST_SECTION_NAME: &str = "enclavid:policy-manifest.v1";

pub fn run(wasm: PathBuf, key: PathBuf, manifest: PathBuf, output: Option<PathBuf>) -> Result<()> {
    let identity = read_identity(&key)
        .with_context(|| format!("reading key from {}", key.display()))?;
    let recipient = identity.to_public();

    let wasm_bytes = std::fs::read(&wasm)
        .with_context(|| format!("reading {}", wasm.display()))?;

    // Validate manifest up-front so the author sees the same errors
    // here that the TEE would trap on at /connect. Push will see the
    // already-bundled .age and have nothing to validate.
    let parsed = policy_manifest::read(&manifest)?;
    let report = policy_manifest::validate(&parsed);
    for w in &report.warnings {
        println!("warning: {w}");
    }
    if !report.ok() {
        for e in &report.errors {
            println!("error: {e}");
        }
        anyhow::bail!(
            "manifest validation failed ({} error(s)) — run `enclavid policy validate {}` for full report",
            report.errors.len(),
            manifest.display(),
        );
    }
    let manifest_bytes = policy_manifest::read_bytes(&manifest)?;

    let bundled = bundle_with_manifest(&wasm_bytes, &manifest_bytes);
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

    println!(
        "Encrypted: {} (wasm {} B + manifest {} B → bundled {} B) → {}",
        wasm.display(),
        wasm_bytes.len(),
        manifest_bytes.len(),
        bundled.len(),
        output_path.display(),
    );
    println!("D_plain (sha256 of bundled plaintext):  {}", plaintext_digest);
    println!("D_enc   (sha256 of ciphertext):         {}", ciphertext_digest);
    println!();
    println!("Save D_plain — needed for session attestation verification later.");

    Ok(())
}

/// Append the manifest as a component-level custom section to the
/// wasm component bytes. `wasm-encoder::CustomSection` writes the
/// canonical encoding (`0x00` section id + LEB128-prefixed name and
/// payload); we just stitch its output onto the tail of the existing
/// bytes.
///
/// Custom sections per the WASM core spec can appear anywhere
/// (before, between, or after standard sections). Appending at the
/// end keeps us from re-parsing the existing wasm and matches the
/// convention LLVM/rustc/cargo-component already follow for `name` /
/// `producers` sections.
fn bundle_with_manifest(wasm_bytes: &[u8], manifest_json: &[u8]) -> Vec<u8> {
    let section = wasm_encoder::CustomSection {
        name: Cow::Borrowed(MANIFEST_SECTION_NAME),
        data: Cow::Borrowed(manifest_json),
    };
    let mut bundled = Vec::with_capacity(wasm_bytes.len() + manifest_json.len() + 32);
    bundled.extend_from_slice(wasm_bytes);
    section.append_to_component(&mut bundled);
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
