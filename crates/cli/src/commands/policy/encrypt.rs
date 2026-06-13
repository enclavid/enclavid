//! `enclavid policy encrypt` — age-encrypts a wasm policy component
//! under the `client_policy_key`. Input is a wasm file (typically the
//! output of `enclavid policy embed`); output is `<input>.age`.
//!
//! This is the encryption step previously bundled into
//! `enclavid policy seal`. Split into its own command so the embed
//! step can run independently and so `enclavid plugin embed` can
//! reuse the embed helper without paying for encryption (plugins are
//! tier-1 OSS by default, only the future Phase 6 KBS-released
//! plugins encrypt — and that encrypts only the code section, not the
//! whole component, so it's a different command).
//!
//! Whole-component age encryption is the **policy** encryption model
//! (single age recipient = client_policy_key; runtime decrypts the
//! whole envelope before instantiation). See
//! `[[project-policy-artifact-encryption]]` and
//! `[[project-section-level-encryption-plan]]` for the split between
//! policy-side vs plugin-side encryption.

use age::Encryptor;
use age::x25519::Identity;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

pub fn run(wasm: PathBuf, key: PathBuf, output: Option<PathBuf>) -> Result<()> {
    let identity = read_identity(&key)
        .with_context(|| format!("reading key from {}", key.display()))?;
    let recipient = identity.to_public();

    let wasm_bytes = std::fs::read(&wasm)
        .with_context(|| format!("reading {}", wasm.display()))?;
    let plaintext_digest = sha256_hex(&wasm_bytes);

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
    writer.write_all(&wasm_bytes).context("writing ciphertext")?;
    writer.finish().context("finalizing age envelope")?;
    drop(out_file);

    let ciphertext = std::fs::read(&output_path).context("re-reading ciphertext for digest")?;
    let ciphertext_digest = sha256_hex(&ciphertext);

    println!(
        "Encrypted: {} ({} B → {} B) → {}",
        wasm.display(),
        wasm_bytes.len(),
        ciphertext.len(),
        output_path.display(),
    );
    println!("D_plain (sha256 of input wasm):  {}", plaintext_digest);
    println!("D_enc   (sha256 of ciphertext):  {}", ciphertext_digest);
    println!();
    println!("Save D_plain — needed for session attestation verification later.");

    Ok(())
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
