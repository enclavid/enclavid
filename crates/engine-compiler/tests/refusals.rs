//! Which compositions the compile refuses, and the fault it names for each —
//! the value api keeps as the session's init error. Components are built from
//! WIT alone.

use engine_compiler::Compiler;
use engine_types::compile::{Artifact, CompileFault, InterfaceName};
use engine_types::composition::PluginInstance;
use wit_component::{ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata};
use wit_parser::{ManglingAndAbi, Resolve};

/// A component of the one world `wit` declares, its functions doing nothing.
fn component(wit: &str) -> Vec<u8> {
    let mut resolve = Resolve::default();
    let package = resolve
        .push_str("component.wit", wit)
        .expect("the WIT parses");
    let world = resolve
        .select_world(&[package], None)
        .expect("the one world");
    let mut module = dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8)
        .expect("the metadata");
    ComponentEncoder::default()
        .module(&module)
        .expect("the module")
        .validate(true)
        .encode()
        .expect("the component")
}

/// A policy importing `import`, with `packages` declaring it.
fn importing(import: &str, packages: &str) -> Vec<u8> {
    component(&format!(
        "package test:policy;
         world policy {{ import {import}; }}
         {packages}"
    ))
}

/// A plugin exporting `export`, with `packages` declaring it.
fn exporting(export: &str, packages: &str) -> Vec<u8> {
    component(&format!(
        "package test:plugin;
         world plugin {{ export {export}; }}
         {packages}"
    ))
}

const API: &str = "package test:api@0.1.0 { interface api { ping: func(); } }";

/// The fault the compile refuses `policy` with `plugins` for, `None` if it
/// compiles. An error that names no fault is not a refusal, and fails the test.
fn refusal(policy: Vec<u8>, plugins: Vec<Vec<u8>>) -> Option<CompileFault> {
    let plugins = plugins
        .into_iter()
        .enumerate()
        .map(|(i, wasm)| PluginInstance {
            package: format!("test:plugin{i}"),
            wasm,
        })
        .collect();
    match Compiler::new()
        .expect("a compiler")
        .compile_to_parts(policy, plugins)
    {
        Ok(_) => None,
        Err(e) => Some(
            e.downcast_ref::<CompileFault>()
                .unwrap_or_else(|| panic!("a failure that names no fault: {e:?}"))
                .clone(),
        ),
    }
}

fn name(s: &str) -> InterfaceName {
    InterfaceName::new(s).expect("a legal name")
}

/// An import with functions that no plugin pinned and not the host serves: no
/// round could run, so the compile refuses it, naming it.
#[test]
fn an_import_nothing_serves_is_refused() {
    let policy = importing("test:api/api@0.1.0", API);
    assert_eq!(
        refusal(policy, vec![]),
        Some(CompileFault::Unsatisfied(name("test:api/api@0.1.0")))
    );
}

/// The same import, served by a pinned plugin, fuses and compiles.
#[test]
fn an_import_a_plugin_serves_compiles() {
    let policy = importing("test:api/api@0.1.0", API);
    let plugin = exporting("test:api/api@0.1.0", API);
    assert_eq!(refusal(policy, vec![plugin]), None);
}

/// An interface of types alone needs nothing served, as the executor's linker
/// sees it.
#[test]
fn an_import_of_types_alone_compiles() {
    let policy = importing(
        "test:shapes/shapes@0.1.0",
        "package test:shapes@0.1.0 { interface shapes { record point { x: u32 } } }",
    );
    assert_eq!(refusal(policy, vec![]), None);
}

const PROPS: &str = "interface policy-props { record props { flag: bool } get: func() -> props; }";

/// The host's interfaces are served at their own version and at any
/// semver-compatible one, as the linker looks a name up — and not past that.
#[test]
fn the_host_serves_its_interfaces_by_the_linkers_rule() {
    let at = |version: &str| {
        importing(
            &format!("enclavid:host-ext/policy-props@{version}"),
            &format!("package enclavid:host-ext@{version} {{ {PROPS} }}"),
        )
    };
    assert_eq!(refusal(at("0.1.0"), vec![]), None);
    assert_eq!(refusal(at("0.1.7"), vec![]), None);
    assert_eq!(
        refusal(at("0.2.0"), vec![]),
        Some(CompileFault::Unsatisfied(name(
            "enclavid:host-ext/policy-props@0.2.0"
        )))
    );
}

/// A host package's interface the host does not serve — one a policy built
/// against an older WIT still imports — is refused like any other.
#[test]
fn a_host_interface_the_host_does_not_serve_is_refused() {
    let policy = importing(
        "enclavid:host/session-context@0.1.0",
        "package enclavid:host@0.1.0 { interface session-context { now: func() -> u64; } }",
    );
    assert_eq!(
        refusal(policy, vec![]),
        Some(CompileFault::Unsatisfied(name(
            "enclavid:host/session-context@0.1.0"
        )))
    );
}

/// What a plugin serves an import with must be of the type it is imported as.
#[test]
fn a_plugin_of_another_type_is_refused() {
    let policy = importing("test:api/api@0.1.0", API);
    let plugin = exporting(
        "test:api/api@0.1.0",
        "package test:api@0.1.0 { interface api { ping: func(times: u32); } }",
    );
    assert_eq!(
        refusal(policy, vec![plugin]),
        Some(CompileFault::Mismatched(name("test:api/api@0.1.0")))
    );
}

/// Bytes that are not a component, named by the package they are pinned as.
#[test]
fn bytes_that_are_not_a_component_are_refused() {
    let policy = importing("test:api/api@0.1.0", API);
    let plugin = exporting("test:api/api@0.1.0", API);
    assert_eq!(
        refusal(policy.clone(), vec![plugin, b"not wasm".to_vec()]),
        Some(CompileFault::NotAComponent(Artifact::Plugin(
            "test:plugin1".into()
        )))
    );
    assert_eq!(
        refusal(b"not wasm".to_vec(), vec![]),
        Some(CompileFault::NotAComponent(Artifact::Policy))
    );
}

/// A plugin may not export what only the host serves.
#[test]
fn a_plugin_exporting_a_host_interface_is_refused() {
    let policy = importing("test:api/api@0.1.0", API);
    let plugin = exporting(
        "enclavid:host-ext/policy-props@0.1.0",
        &format!("package enclavid:host-ext@0.1.0 {{ {PROPS} }}"),
    );
    assert_eq!(
        refusal(policy, vec![plugin]),
        Some(CompileFault::ReservedExport(Artifact::Plugin(
            "test:plugin0".into()
        )))
    );
}
