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

    let plaintext = std::fs::read(&wasm)
        .with_context(|| format!("reading {}", wasm.display()))?;

    let plaintext_digest = sha256_hex(&plaintext);

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
    writer.write_all(&plaintext).context("writing ciphertext")?;
    writer.finish().context("finalizing age envelope")?;
    drop(out_file);

    let ciphertext = std::fs::read(&output_path).context("re-reading ciphertext for digest")?;
    let ciphertext_digest = sha256_hex(&ciphertext);

    println!("Encrypted: {} → {}", wasm.display(), output_path.display());
    println!("D_plain (sha256 of plaintext):  {}", plaintext_digest);
    println!("D_enc   (sha256 of ciphertext): {}", ciphertext_digest);
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
