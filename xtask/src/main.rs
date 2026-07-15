//! `cargo xtask` — repo dev tasks.
//!
//! `push-plugins`: build → componentize → embed → push every plugin to the
//! OCI registry, then print a ready-to-paste `plugins[]` array for a
//! session spec. Reuses the same build pipeline the engine test exercises
//! (see [`xtask`] lib), so published artifacts match the tested ones.
//!
//! Auth uses a FRESH registry token for the ACTIVE workspace
//! (`enclavid cloud token`), so the push namespace always matches the
//! token. Switch first if needed: `enclavid cloud workspace use <id>`.
//!
//! Run with the dev env sourced (same as the other steps):
//!   set -a && source .env && set +a && cargo xtask push-plugins
//!   cargo xtask push-plugins --plugins well-known,extra
//! Requires `enclavid` on PATH.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use xtask::{build_componentized, embed_sections};

#[derive(Parser)]
#[command(about = "Enclavid repo dev tasks")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build, componentize, embed and push plugins to an OCI registry.
    PushPlugins {
        /// Comma-separated subset (default: all). Names: well-known,
        /// preprocess, face-detect, face-age, extra.
        #[arg(long, value_delimiter = ',')]
        plugins: Option<Vec<String>>,
        /// Registry host (dev default).
        #[arg(long, default_value = "localhost:5050")]
        registry: String,
    },
}

/// One plugin's layout, relative to the workspace root.
struct Plugin {
    /// OCI repo name + `enclavid:<name>@0.1.0` package id stem.
    name: &'static str,
    /// Crate dir to `cargo build` in (its `.cargo` pins the wasm target).
    crate_dir: &'static str,
    /// Where the built `.wasm` module lands.
    module: &'static str,
    /// Dir holding `i18n.json` / `icons.json` (if any).
    src: &'static str,
}

/// The plugin set. `extra` is a TEST fixture (needed only by the
/// test-policy); the rest are the real `plugins/` crates.
const PLUGINS: &[Plugin] = &[
    Plugin {
        name: "well-known",
        crate_dir: "plugins/well-known",
        module: "plugins/well-known/target/wasm32-unknown-unknown/release/well_known.wasm",
        src: "plugins/well-known",
    },
    Plugin {
        name: "preprocess",
        crate_dir: "plugins/preprocess",
        module: "plugins/target/wasm32-unknown-unknown/release/preprocess.wasm",
        src: "plugins/preprocess",
    },
    Plugin {
        name: "face-detect",
        crate_dir: "plugins/face-detect",
        module: "plugins/target/wasm32-unknown-unknown/release/face_detect.wasm",
        src: "plugins/face-detect",
    },
    Plugin {
        name: "face-age",
        crate_dir: "plugins/face-age",
        module: "plugins/target/wasm32-unknown-unknown/release/face_age.wasm",
        src: "plugins/face-age",
    },
    Plugin {
        name: "extra",
        crate_dir: "crates/engine/tests/fixtures/test-extra",
        module: "crates/engine/tests/fixtures/test-extra/target/wasm32-unknown-unknown/release/test_extra.wasm",
        src: "crates/engine/tests/fixtures/test-extra",
    },
];

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::PushPlugins { plugins, registry } => push_plugins(plugins, &registry),
    }
}

fn push_plugins(selected: Option<Vec<String>>, registry: &str) -> Result<()> {
    // Anchor every relative path to the workspace root so the tool works
    // from any CWD (crate builds use absolute `current_dir`).
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask has no parent dir")?
        .to_path_buf();

    let chosen: Vec<&Plugin> = match &selected {
        None => PLUGINS.iter().collect(),
        Some(names) => {
            for n in names {
                if !PLUGINS.iter().any(|p| p.name == n) {
                    bail!("unknown plugin '{n}' (known: {})", plugin_names());
                }
            }
            PLUGINS.iter().filter(|p| names.iter().any(|n| n == p.name)).collect()
        }
    };

    // Active workspace + a fresh registry token for it (so the token's org
    // matches the push namespace).
    let ws = active_workspace()?;
    let auth = format!("Bearer {}", cloud_token()?);
    let dist = root.join("target/xtask-dist");
    std::fs::create_dir_all(&dist).context("creating dist dir")?;
    println!("registry={registry}  workspace={ws}  dist={}\n", dist.display());

    let mut pins: Vec<serde_json::Value> = Vec::new();
    for p in chosen {
        println!("── {} ───────────────────────────────", p.name);
        let crate_dir = abs(&root, p.crate_dir);
        let module = abs(&root, p.module);
        let src = abs(&root, p.src);

        let wasm = embed_sections(build_componentized(&crate_dir, &module)?, &src);
        let file = dist.join(format!("{}.embedded.wasm", p.name));
        std::fs::write(&file, &wasm).with_context(|| format!("writing {}", file.display()))?;

        // Push under enclavid/<ws>/policies/<name> (no tag → timestamp +
        // :latest); capture the pinned @sha256 ref for the spec.
        let reference = format!("{registry}/enclavid/{ws}/policies/{}", p.name);
        let stdout = run_capture(
            "enclavid",
            &["oci", "push", file.to_str().unwrap(), &reference, "--auth", &auth],
        )
        .with_context(|| format!("pushing {}", p.name))?;
        print!("{stdout}");
        let pinned = stdout
            .split_whitespace()
            .find(|t| t.contains("@sha256:"))
            .with_context(|| format!("no pinned ref in `oci push` output for {}", p.name))?;
        println!("  ✓ enclavid:{}@0.1.0  ->  {pinned}\n", p.name);
        pins.push(serde_json::json!({
            "package": format!("enclavid:{}@0.1.0", p.name),
            "impl_ref": pinned,
        }));
    }

    println!("=== paste into spec.json  \"plugins\": ===");
    println!("{}", serde_json::to_string_pretty(&serde_json::Value::Array(pins))?);
    Ok(())
}

fn plugin_names() -> String {
    PLUGINS.iter().map(|p| p.name).collect::<Vec<_>>().join(", ")
}

fn abs(root: &Path, rel: &str) -> String {
    root.join(rel).to_string_lossy().into_owned()
}

/// Active workspace id: the `(...)` in `Active workspace: <name> (<id>)`.
fn active_workspace() -> Result<String> {
    let out = run_capture("enclavid", &["cloud", "workspace"])?;
    out.rsplit_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(id, _)| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .context("could not parse workspace id from `enclavid cloud workspace` (run `enclavid cloud login`)")
}

/// Fresh registry bearer for the active workspace.
fn cloud_token() -> Result<String> {
    Ok(run_capture("enclavid", &["cloud", "token"])?.trim().to_string())
}

/// Run a command, capture stdout, and fail loudly (with stderr) on a
/// non-zero exit.
fn run_capture(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("spawning `{program} {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`{program} {}` failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
