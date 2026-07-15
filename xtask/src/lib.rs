//! Shared plugin/policy build helpers: build a wasm crate, componentize
//! its core module, and weld the `enclavid:embedded.*` custom sections.
//!
//! This is the ONE home for the build→componentize→embed pipeline. Both
//! the `xtask push-plugins` binary and the engine's `happy_path` test call
//! these, so a published artifact is byte-identical to the one the test
//! exercises in-process (same `wit_component::ComponentEncoder`, same
//! section bytes) — no drift between "what we test" and "what we ship".

use std::process::Command;

use anyhow::{Context, Result, bail};

/// `cargo build --release` a wasm crate (its `.cargo/config.toml` pins the
/// `wasm32-unknown-unknown` target), then componentize the emitted module.
/// `module_path` is where that crate's `.wasm` lands (its own target dir,
/// or the shared workspace target for a member crate).
pub fn build_componentized(crate_dir: &str, module_path: &str) -> Result<Vec<u8>> {
    let status = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(crate_dir)
        .status()
        .with_context(|| format!("invoking cargo in {crate_dir}"))?;
    if !status.success() {
        bail!("cargo build failed in {crate_dir}");
    }
    let module = std::fs::read(module_path)
        .with_context(|| format!("reading wasm module {module_path}"))?;
    componentize(&module)
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

/// Append the author JSON in `dir` as `enclavid:embedded.*` custom
/// sections — byte-for-byte, exactly what `enclavid {policy,plugin} embed`
/// does. A missing file appends no section (a plugin ships no
/// `disclosure-fields.json`; a section-less plugin ships none at all).
pub fn embed_sections(mut wasm: Vec<u8>, dir: &str) -> Vec<u8> {
    use enclavid_embedded::{SECTION_DISCLOSURE_FIELDS, SECTION_I18N, SECTION_ICONS};
    use wasm_encoder::{ComponentSection, CustomSection};
    let read = |name: &str| std::fs::read(format!("{dir}/{name}")).ok();
    for (name, data) in [
        (SECTION_DISCLOSURE_FIELDS, read("disclosure-fields.json")),
        (SECTION_I18N, read("i18n.json")),
        (SECTION_ICONS, read("icons.json")),
    ] {
        if let Some(bytes) = data {
            CustomSection {
                name: name.into(),
                data: bytes.into(),
            }
            .append_to_component(&mut wasm);
        }
    }
    wasm
}
