//! `cargo xtask` — repo dev tasks.
//!
//! `build-plugins <dir>`: every plugin as it is published — componentized,
//! its texts embedded — into `<dir>`, one `<name>.wasm` each, through the same
//! pipeline the engine tests build them with ([`xtask::fixtures`]). Pushing is
//! the CLI's, each face plugin with its model files beside it:
//!   cargo xtask build-plugins target/plugins
//!   enclavid oci push target/plugins/face-age.wasm <ref> --models <dir>

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use xtask::fixtures;

#[derive(Parser)]
#[command(about = "Enclavid repo dev tasks")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build every plugin as it is published into a directory, one
    /// `<name>.wasm` each.
    BuildPlugins {
        /// Where the plugins are written.
        dir: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::BuildPlugins { dir } => build_plugins(&dir),
    }
}

/// The plugins as published: well-known; face-detect, face-age and
/// face-liveness, whose models — BlazeFace, MiVOLO and MiniFASNet — the host
/// runs from the files pushed beside them.
fn build_plugins(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for (name, wasm) in [
        ("well-known", fixtures::well_known()),
        ("face-detect", fixtures::face_detect()),
        ("face-age", fixtures::face_age()),
        ("face-liveness", fixtures::face_liveness()),
    ] {
        let file = dir.join(format!("{name}.wasm"));
        std::fs::write(&file, wasm).with_context(|| format!("writing {}", file.display()))?;
        println!("{} ({} bytes)", file.display(), wasm.len());
    }
    Ok(())
}
