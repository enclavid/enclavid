use age::secrecy::ExposeSecret;
use age::x25519::Identity;
use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub fn run(output: PathBuf) -> Result<()> {
    if output.exists() {
        anyhow::bail!(
            "{} already exists — refusing to overwrite",
            output.display()
        );
    }

    let identity = Identity::generate();
    let recipient = identity.to_public();

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(&output)
        .with_context(|| format!("creating {}", output.display()))?;

    writeln!(file, "# Enclavid encryption key (client_policy_key)")?;
    writeln!(file, "# public recipient: {}", recipient)?;
    writeln!(
        file,
        "# Keep this file secret. If lost, encrypted policies become unrecoverable."
    )?;
    writeln!(file, "{}", identity.to_string().expose_secret())?;

    println!("Generated client_policy_key at {}", output.display());
    println!("Public recipient:   {}", recipient);
    eprintln!();
    eprintln!("Next:");
    eprintln!("  - Store this file in your secrets manager (HSM / Vault / equivalent).");
    eprintln!(
        "  - Encrypt policies with: enclavid encrypt policy.wasm --key {}",
        output.display()
    );

    Ok(())
}
