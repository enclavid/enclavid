//! Shared plugin/policy build helpers: build a wasm crate, componentize
//! its core module, and embed its catalogs.
//!
//! This is the ONE home for the build→componentize→embed pipeline. Both
//! the `xtask push-plugins` binary and the engine's `happy_path` test call
//! these, so a published artifact is byte-identical to the one the test
//! exercises in-process (same `wit_component::ComponentEncoder`, same
//! embedding as `enclavid {policy,plugin} embed`) — no drift between "what
//! we test" and "what we ship".
//!
//! [`fixtures`] builds on that: the catalog of policy + plugin artifacts the
//! engine tests compose, shared now that the executor and its child are
//! separate packages that both need them.

//! [`child_binary`] is the same idea applied to a Rust binary rather than a wasm
//! one: build a disposable child in ITS OWN cargo invocation, so a test spawns
//! the artifact the image ships and not a near-miss of it.

mod child;
pub mod fixtures;

pub use child::child_binary;

use std::process::Command;

use anyhow::{Context, Result, bail};

/// `cargo build --release` a wasm crate (its `.cargo/config.toml` pins the
/// `wasm32-unknown-unknown` target), then componentize the emitted module.
/// `module_path` is where that crate's `.wasm` lands (its own target dir,
/// or the shared workspace target for a member crate).
pub fn build_componentized(crate_dir: &str, module_path: &str) -> Result<Vec<u8>> {
    built(
        Command::new("cargo").args(["build", "--release"]),
        crate_dir,
    )?;
    let module =
        std::fs::read(module_path).with_context(|| format!("reading wasm module {module_path}"))?;
    componentize(&module)
}

/// [`build_componentized`], with `features` turned on and the build kept in
/// `target_dir`, where `module_path` lands — so a build with features never
/// stands in for the crate's default one, nor that one for it.
pub fn build_componentized_with(
    crate_dir: &str,
    features: &[&str],
    target_dir: &str,
    module_path: &str,
) -> Result<Vec<u8>> {
    built(
        Command::new("cargo")
            .args(["build", "--release", "--features", &features.join(",")])
            .args(["--target-dir", target_dir]),
        crate_dir,
    )?;
    let module =
        std::fs::read(module_path).with_context(|| format!("reading wasm module {module_path}"))?;
    componentize(&module)
}

/// Run the cargo `build` in `crate_dir`, refused unless it succeeds.
fn built(build: &mut Command, crate_dir: &str) -> Result<()> {
    let status = build
        .current_dir(crate_dir)
        .status()
        .with_context(|| format!("invoking cargo in {crate_dir}"))?;
    if !status.success() {
        bail!("cargo build failed in {crate_dir}");
    }
    Ok(())
}

/// Componentize a wit-bindgen core module into a component (no WASI
/// adapter — plugins/policies are `wasm32-unknown-unknown`). Mirrors the
/// engine test's `ComponentEncoder::default().module(..).validate(true).encode()`.
pub fn componentize(module: &[u8]) -> Result<Vec<u8>> {
    wit_component::ComponentEncoder::default()
        .module(module)
        .context("module is missing its wit-bindgen component-type custom section (build with wit-bindgen)")?
        .validate(true)
        .encode()
        .context("componentizing the core module")
}

/// Which artifact a project is: a policy embeds its disclosure fields
/// beside its texts, a plugin its texts alone.
pub use enclavid_embedded::embed::Role;

/// Embed the catalogs of the project in `dir` into `wasm` — its texts
/// under `i18n/`, checked against the keys its `wit/` declares, and for a
/// policy its disclosure fields — exactly as `enclavid {policy,plugin}
/// embed` does. Refused when they do not check.
pub fn embed_sections(wasm: Vec<u8>, dir: &str, role: Role) -> Result<Vec<u8>> {
    use enclavid_embedded::embed::{self, Project};
    let dir = std::path::Path::new(dir);
    let checked = embed::check(&Project {
        wit: dir.join("wit"),
        i18n: dir.join(enclavid_embedded::DIR_I18N),
        role,
    })?;
    if !checked.report.ok() {
        let errors: Vec<String> = checked
            .report
            .errors
            .iter()
            .map(ToString::to_string)
            .collect();
        bail!(
            "the catalogs in {} did not check:\n{}",
            dir.display(),
            errors.join("\n")
        );
    }
    embed::embed(&wasm, &checked)
}
