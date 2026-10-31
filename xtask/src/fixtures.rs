//! The test-fixture CATALOG: the policy + plugin artifacts the engine tests
//! compose, built through the same pipeline as the rest of this crate.
//!
//! It lives here for one reason: two packages now need the same artifacts. The
//! executor's `happy_path` drives them in-process, and `engine-executor-child`'s
//! integration test primes a real multi-MiB cwasm into the spawned child. Before
//! the child had its own package they were one file; the alternative to this
//! module is the same six builders copied into both, drifting apart the first
//! time a plugin gains a section.
//!
//! Each artifact is built once per process and cached — `cargo build` for the
//! wasm crate, componentize, then embed its catalogs. Building on first use
//! rather than in a `build.rs` keeps an ordinary engine build free of wasm
//! tooling.
//!
//! Paths are relative to THIS crate's manifest, so a caller's location does not
//! matter — which is the point of moving them.

use std::sync::OnceLock;

use crate::Role;

/// WIT package id the policy imports its capture / disclosure-field helpers
/// from; used as the plugin descriptor label at compose time.
pub const WELL_KNOWN_PACKAGE: &str = "enclavid:well-known@0.1.0";
/// Package id of the minimal second plugin the policy imports (its `tag::get()`
/// supplies the consent requester).
pub const EXTRA_PACKAGE: &str = "enclavid:extra@0.1.0";
/// Package id of the face-age plugin the policy calls on the selfie round.
/// Ships no embedded catalog, so it imports no slot.
pub const FACE_AGE_PACKAGE: &str = "enclavid:face-age@0.1.0";
/// Package id of the preprocess plugin — decodes the selfie `clip` into the
/// plugin-owned `decoded-frame` the policy threads to face-age.
pub const PREPROCESS_PACKAGE: &str = "enclavid:preprocess@0.1.0";
/// Package id of the face-detect plugin — locates the `face` in the
/// decoded-frame, which the policy threads to face-age.
pub const FACE_DETECT_PACKAGE: &str = "enclavid:face-detect@0.1.0";

/// The fixtures live under the executor's `tests/`, where they were written and
/// where the flow they encode is asserted.
fn fixture_dir(name: &str) -> String {
    format!(
        "{}/../crates/engine-executor/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR"),
    )
}

fn plugin_dir(name: &str) -> String {
    format!("{}/../plugins/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Plugins that are members of the `plugins/` workspace emit into its SHARED
/// target dir, not their own crate dir.
fn shared_plugin_module(name: &str) -> String {
    format!(
        "{}/../plugins/target/wasm32-unknown-unknown/release/{name}.wasm",
        env!("CARGO_MANIFEST_DIR"),
    )
}

fn build(dir: String, module: String, role: Role) -> Vec<u8> {
    crate::embed_sections(
        crate::build_componentized(&dir, &module).expect("build_componentized"),
        &dir,
        role,
    )
    .expect("the catalogs embed")
}

/// The `test-policy` fixture: componentized and embedded with its texts and
/// disclosure fields — exactly the shape the engine sees in production.
pub fn test_policy() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = fixture_dir("test-policy");
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/test_policy.wasm");
            build(dir, module, Role::Policy)
        })
        .as_slice()
}

/// The `enclavid:well-known` plugin, componentized, with its texts embedded.
pub fn well_known() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = plugin_dir("well-known");
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/well_known.wasm");
            build(dir, module, Role::Plugin)
        })
        .as_slice()
}

/// The minimal `enclavid:extra` plugin, componentized, with its texts
/// embedded.
pub fn extra() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = fixture_dir("test-extra");
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/test_extra.wasm");
            build(dir, module, Role::Plugin)
        })
        .as_slice()
}

/// The `enclavid:face-age` plugin. It has no texts, so embedding adds
/// nothing — the artifact carries only its `check` export and the
/// `enclavid:vision/types` import (the `decoded-frame` it reads crops from).
pub fn face_age() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            build(
                plugin_dir("face-age"),
                shared_plugin_module("face_age"),
                Role::Plugin,
            )
        })
        .as_slice()
}

/// The `enclavid:face-age` plugin built as the artifact whose model the host
/// runs (`--features mivolo`): its `with-models` world imports its slot,
/// `enclavid-ext:face-age/models`, whose `age` is MiVOLO. The model is not in
/// it: a composition names its graph and data file as the layers `age.onnx`
/// and `age.onnx.data`. Built in a target directory of its own, so it and the
/// default build never stand in for each other.
pub fn face_age_mivolo() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = plugin_dir("face-age");
            let target = format!("{}/../plugins/target/mivolo", env!("CARGO_MANIFEST_DIR"));
            let module = format!("{target}/wasm32-unknown-unknown/release/face_age.wasm");
            crate::embed_sections(
                crate::build_componentized_with(&dir, &["mivolo"], &target, &module)
                    .expect("build_componentized_with"),
                &dir,
                Role::Plugin,
            )
            .expect("the catalogs embed")
        })
        .as_slice()
}

/// The `enclavid:preprocess` plugin — OWNS the `decoded-frame` resource
/// (exports `enclavid:vision/types`) and imports the host `clip`; no texts.
pub fn preprocess() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            build(
                plugin_dir("preprocess"),
                shared_plugin_module("preprocess"),
                Role::Plugin,
            )
        })
        .as_slice()
}

/// The `enclavid:face-detect` plugin — imports `enclavid:vision/types` (reads
/// the preprocess-owned `decoded-frame`) and exports `detect`; no texts.
/// The default build is the weightless placeholder (whole frame as the face).
pub fn face_detect() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            build(
                plugin_dir("face-detect"),
                shared_plugin_module("face_detect"),
                Role::Plugin,
            )
        })
        .as_slice()
}

/// The `test-models` policy: the test entry's graph through its own slot's
/// models. It has no texts and no disclosure fields, so it is componentized
/// and not embedded.
pub fn test_models() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            let dir = fixture_dir("test-models");
            let module = format!("{dir}/target/wasm32-unknown-unknown/release/test_models.wasm");
            crate::build_componentized(&dir, &module).expect("build_componentized")
        })
        .as_slice()
}

/// Every plugin the policy imports, as `(package id, component wasm)`. All must
/// be present in a composition, since the policy calls into each — well-known
/// for specs/DF, extra for the requester tag, and the vision trio on the selfie
/// round.
///
/// Pairs rather than `PluginInstance`, so this build tool keeps no dependency on
/// the engine's wire types; each caller maps them in a line.
pub fn all_plugins() -> Vec<(&'static str, &'static [u8])> {
    vec![
        (WELL_KNOWN_PACKAGE, well_known()),
        (EXTRA_PACKAGE, extra()),
        (PREPROCESS_PACKAGE, preprocess()),
        (FACE_DETECT_PACKAGE, face_detect()),
        (FACE_AGE_PACKAGE, face_age()),
    ]
}
