//! Build a disposable-child binary the way the IMAGE builds it, and say where it
//! landed.
//!
//! ## Why a test cannot just use `CARGO_BIN_EXE_*`
//!
//! What separates a child from its supervisor is not the package boundary — it
//! is the cargo INVOCATION. `image/app` runs `cargo build -p <child>`, which does
//! not resolve dev-dependencies at all, so nothing turns on
//! `engine-supervisor/parent` and the child gets no `tokio/process`.
//!
//! A test in that same package is the opposite case. `cargo test -p <child>`
//! builds the binary and the test in ONE invocation, dev-dependencies included —
//! and the test's dev-dependencies contain the parent half, because playing
//! supervisor is exactly what a child-process test does. Features are additive
//! and unify across an invocation, so `CARGO_BIN_EXE_<child>` points at a binary
//! with a facility the shipped one does not have.
//!
//! Cargo has a mechanism for precisely this — an artifact dependency
//! (`artifact = "bin"`), which builds the binary as its own unit with its own
//! feature resolution and hands back `CARGO_BIN_FILE_*`. It is still unstable:
//! on cargo 1.96 it answers `` `artifact = …` requires `-Z bindeps` ``. Until it
//! lands, doing the separate invocation by hand is the whole of the difference.
//!
//! ## What this costs
//!
//! One extra target directory — measured at 2.5 GB and ~40 s from cold on a
//! 32-core machine, then cached until a dependency moves. Shelling out to cargo
//! from a test is already how this crate builds the wasm fixtures, so the
//! pattern is not new here.
//!
//! ## What it buys
//!
//! The integration tests spawn the artifact that ships, rather than one that
//! differs from it by however many features a dev-dependency happened to add.
//! Today that difference is one feature and harmless; the point is that nothing
//! reports it if it grows. It is also what lets the egress seccomp filter deny
//! `socketpair` — the shipped child opens none, and before this the filter had
//! to stay wide enough for a test binary that did.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Where the separately-built children live: a target directory of their own,
/// so the units cargo builds here — a different feature resolution of the same
/// crates — never share one with the units the test itself was built from.
///
/// Under `target/` so the existing `.gitignore` covers it and `cargo clean`
/// reaches it.
const TARGET_DIR: &str = "target/child-under-test";

/// Build `package` in its own cargo invocation and return the path to the
/// binary of the same name. Panics if the build fails: a test that cannot
/// produce the artifact it is about to spawn has nothing left to assert. Cargo's
/// diagnostics are not in the panic — stdio is inherited, so they are already on
/// the test's output, above the panic that follows them.
///
/// One package per call, never several. Two children in one invocation would
/// unify with each other — the compiler child's Cranelift-enabled `wasmtime`
/// would become the executor child's too — which is the same mistake at a
/// different scale.
pub fn child_binary(package: &str) -> PathBuf {
    build(package).unwrap_or_else(|e| panic!("building {package} for the test: {e:#}"))
}

fn build(package: &str) -> Result<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits one level below the workspace root")
        .to_path_buf();
    let target_dir = root.join(TARGET_DIR);

    // Match the profile the CALLER was built with, so a `cargo test --release`
    // run spawns a release child. `debug_assertions` is this crate's own compile
    // flag, and this crate is built in the same profile as the test using it.
    let release = !cfg!(debug_assertions);
    let profile = if release { "release" } else { "debug" };

    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.arg("build")
        .args(["-p", package])
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(&root);
    if release {
        cmd.arg("--release");
    }
    // Inherited stdio: cargo's progress and any error go to the test's output,
    // where whoever is reading a failure is already looking.
    let status = cmd
        .status()
        .with_context(|| format!("invoking cargo build -p {package}"))?;
    if !status.success() {
        bail!("cargo build -p {package} failed (see the output above)");
    }

    let bin = target_dir.join(profile).join(package);
    if !bin.is_file() {
        bail!("cargo reported success but {} is not there", bin.display());
    }
    Ok(bin)
}
