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
pub const FACE_AGE_PACKAGE: &str = "enclavid:face-age@0.1.0";
/// Package id of the face-detect plugin — locates the `face` in the host's
/// image of the selfie, which the policy threads to face-age.
pub const FACE_DETECT_PACKAGE: &str = "enclavid:face-detect@0.1.0";
/// Package id of the face-liveness plugin, which the policy asks on a probe
/// whether the faces of a photo or of a video's frames are live.
pub const FACE_LIVENESS_PACKAGE: &str = "enclavid:face-liveness@0.1.0";

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

/// The plugins, all members of the `plugins/` workspace, emit into its SHARED
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
            build(
                plugin_dir("well-known"),
                shared_plugin_module("well_known"),
                Role::Plugin,
            )
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

/// The `enclavid:face-age` plugin: its slot, `enclavid-ext:face-age/models`,
/// hands out MiVOLO as `age`, whose graph and data file a composition names as
/// the layers `age.onnx` and `age.onnx.data`. It has no texts, so embedding
/// adds nothing.
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

/// The `enclavid:face-detect` plugin: its slot,
/// `enclavid-ext:face-detect/models`, hands out BlazeFace as `detector`, whose
/// graph a composition names as the layer `detector.onnx`. No texts.
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

/// The `enclavid:face-liveness` plugin: its slot,
/// `enclavid-ext:face-liveness/models`, hands out MiniFASNet as
/// `minifasnet-v2` and `minifasnet-v1se`, whose graphs a composition names as
/// the layers `minifasnet-v2.onnx` and `minifasnet-v1se.onnx`. No texts.
pub fn face_liveness() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| {
            build(
                plugin_dir("face-liveness"),
                shared_plugin_module("face_liveness"),
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

/// A member of `test-faces`, one of the face plugins as the tests run them:
/// its contract implemented with no model. It has no texts, so it is
/// componentized and not embedded.
fn test_face(member: &str, module: &str) -> Vec<u8> {
    let workspace = fixture_dir("test-faces");
    let module = format!("{workspace}/target/wasm32-unknown-unknown/release/{module}.wasm");
    crate::build_componentized(&format!("{workspace}/{member}"), &module)
        .expect("build_componentized")
}

/// face-detect with no model: the whole frame is the face.
pub fn test_face_detect() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| test_face("face-detect", "test_face_detect"))
        .as_slice()
}

/// face-age with no model: an age from the face's brightness, 30 for gray.
pub fn test_face_age() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| test_face("face-age", "test_face_age"))
        .as_slice()
}

/// face-liveness with no model: a score from the face's brightness, about a
/// half for gray.
pub fn test_face_liveness() -> &'static [u8] {
    static COMPONENT: OnceLock<Vec<u8>> = OnceLock::new();
    COMPONENT
        .get_or_init(|| test_face("face-liveness", "test_face_liveness"))
        .as_slice()
}

/// Every plugin the policy imports, as `(package id, component wasm)`. All must
/// be present in a composition, since the policy calls into each — well-known
/// for specs/DF, extra for the requester tag, and the face plugins on the
/// selfie round, as `test-faces` implements them.
///
/// Pairs rather than `PluginInstance`, so this build tool keeps no dependency on
/// the engine's wire types; each caller maps them in a line.
pub fn all_plugins() -> Vec<(&'static str, &'static [u8])> {
    vec![
        (WELL_KNOWN_PACKAGE, well_known()),
        (EXTRA_PACKAGE, extra()),
        (FACE_DETECT_PACKAGE, test_face_detect()),
        (FACE_AGE_PACKAGE, test_face_age()),
        (FACE_LIVENESS_PACKAGE, test_face_liveness()),
    ]
}
