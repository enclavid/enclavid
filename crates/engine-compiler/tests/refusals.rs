//! Which compositions the compile refuses, and the fault it names for each —
//! the value api keeps as the session's init error. Components are built from
//! WIT alone.

use engine_compiler::{BundleParts, Compiler};
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

/// `policy` with `plugins` compiled, or the fault the compile refuses it for. An
/// error that names no fault is not a refusal, and fails the test.
fn compile(policy: Vec<u8>, plugins: Vec<Vec<u8>>) -> Result<BundleParts, CompileFault> {
    let plugins = plugins
        .into_iter()
        .enumerate()
        .map(|(i, wasm)| PluginInstance {
            package: format!("test:plugin{i}"),
            wasm,
        })
        .collect();
    Compiler::new()
        .expect("a compiler")
        .compile_to_parts(policy, plugins)
        .map_err(|e| {
            e.downcast_ref::<CompileFault>()
                .unwrap_or_else(|| panic!("a failure that names no fault: {e:?}"))
                .clone()
        })
}

/// The fault the compile refuses `policy` with `plugins` for, `None` if it
/// compiles.
fn refusal(policy: Vec<u8>, plugins: Vec<Vec<u8>>) -> Option<CompileFault> {
    compile(policy, plugins).err()
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

/// A policy importing `interface` at two versions on one semver track, each an
/// instance of one function taking and returning nothing. No WIT tooling writes
/// this — wit-component merges the two into one import, refusing types that do
/// not merge — so the component is made by hand, as an attacker would.
fn importing_twice(interface: &str, first: &str, second: &str) -> Vec<u8> {
    use wasm_encoder::{
        Component, ComponentImportSection, ComponentTypeRef, ComponentTypeSection,
        ComponentValType, InstanceType,
    };
    let mut instance = InstanceType::new();
    instance
        .ty()
        .function()
        .params(std::iter::empty::<(&str, ComponentValType)>())
        .result(None);
    instance.export("get", ComponentTypeRef::Func(0));
    let mut types = ComponentTypeSection::new();
    types.instance(&instance);
    let mut imports = ComponentImportSection::new();
    for version in [first, second] {
        imports.import(
            &format!("{interface}@{version}"),
            ComponentTypeRef::Instance(0),
        );
    }
    let mut component = Component::new();
    component.section(&types).section(&imports);
    component.finish()
}

/// The host serves one of its interfaces from one definition, which the linker
/// gives every import on its semver track. A second import on the track is
/// refused, whatever its type, so the import the compile checks is the only one
/// a round serves: no props whose `get` returns nothing, no second list of
/// disclosure fields. The fault names the second import, not the first.
#[test]
fn a_second_import_of_a_host_interface_on_its_track_is_refused() {
    for interface in [
        "enclavid:host-ext/policy-props",
        "enclavid:host-ext/disclosure-fields",
    ] {
        assert_eq!(
            refusal(importing_twice(interface, "0.1.0", "0.1.1"), vec![]),
            Some(CompileFault::Mismatched(name(&format!(
                "{interface}@0.1.1"
            )))),
            "{interface}"
        );
    }
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

/// A policy whose props interface holds `body`.
fn with_props(body: &str) -> Vec<u8> {
    importing(
        "enclavid:host-ext/policy-props@0.1.0",
        &format!("package enclavid:host-ext@0.1.0 {{ interface policy-props {{ {body} }} }}"),
    )
}

/// A `get` returning a value of any shape — a record of what props hold, with
/// aliases, enums, records nested in lists and types used from another
/// interface, or a value that is no record at all — is what the host serves,
/// and compiles. Whether the props fit it is read when a session is prepared.
#[test]
fn props_of_any_value_the_host_serves_compile() {
    let policy = with_props(
        "enum mode { strict, lenient }
         type age = u8;
         record person { name: string }
         record props {
             min-age: age,
             mode: option<mode>,
             people: list<person>,
             pair: option<tuple<u8, u8>>,
         }
         get: func() -> props;",
    );
    assert_eq!(refusal(policy, vec![]), None);

    let used = importing(
        "enclavid:host-ext/policy-props@0.1.0",
        "package enclavid:host-ext@0.1.0 {
             interface shapes { record point { x: u32, y: u32 } }
             interface policy-props {
                 use shapes.{point};
                 record props { at: point, path: list<point> }
                 get: func() -> props;
             }
         }",
    );
    assert_eq!(refusal(used, vec![]), None);

    for body in ["get: func() -> u32;", "get: func() -> list<string>;"] {
        assert_eq!(refusal(with_props(body), vec![]), None, "{body}");
    }
}

/// The host serves `get` taking nothing and returning a value, and nothing else
/// in the interface; a policy importing it as anything else is refused.
#[test]
fn props_imported_as_what_the_host_does_not_serve_are_refused() {
    let host_types = "package enclavid:host@0.1.0 { interface types { resource icon-ref; } }";
    let returns_a_handle = importing(
        "enclavid:host-ext/policy-props@0.1.0",
        &format!(
            "{host_types}
             package enclavid:host-ext@0.1.0 {{
                 interface policy-props {{
                     use enclavid:host/types@0.1.0.{{icon-ref}};
                     get: func() -> icon-ref;
                 }}
             }}"
        ),
    );
    let bodies = [
        "record props { a: u8 } get: func(x: u8) -> props;",
        "get: func();",
        "record props { a: u8 } get: func() -> props; other: func();",
        "resource token; record props { a: u8 } get: func() -> props;",
    ];
    for (policy, what) in bodies
        .map(|body| (with_props(body), body))
        .into_iter()
        .chain([(returns_a_handle, "get: func() -> icon-ref;")])
    {
        assert_eq!(
            refusal(policy, vec![]),
            Some(CompileFault::Mismatched(name(
                "enclavid:host-ext/policy-props@0.1.0"
            ))),
            "{what}"
        );
    }
}

/// A policy importing the icons at `version`, their interface holding `body`.
fn with_icons(version: &str, body: &str) -> Vec<u8> {
    importing(
        &format!("enclavid:host-icons/icons@{version}"),
        &format!(
            "package enclavid:host@0.1.0 {{
                 interface types {{ resource icon-ref; resource localized-ref; }}
             }}
             package enclavid:host-icons@{version} {{
                 interface icons {{
                     use enclavid:host/types@0.1.0.{{icon-ref, localized-ref}};
                     {body}
                 }}
             }}"
        ),
    )
}

/// Any of the icons the host has are served, at its version and at a
/// compatible one either side of it: a later version adds icons, and those the
/// host has are the same functions.
#[test]
fn icons_the_host_has_compile_on_its_track() {
    let all = "passport: func() -> icon-ref;
               id-card: func() -> icon-ref;
               drivers-license: func() -> icon-ref;
               selfie: func() -> icon-ref;";
    for (version, body) in [
        ("0.1.0", all),
        ("0.1.0", "selfie: func() -> icon-ref;"),
        ("0.1.9", "passport: func() -> icon-ref;"),
    ] {
        assert_eq!(
            refusal(with_icons(version, body), vec![]),
            None,
            "{version}: {body}"
        );
    }
}

/// An icon the host has not got — as a later version may add — or one in a
/// shape the host does not serve, a handle of another resource among them, is
/// refused; a version on another track is not the host's at all.
#[test]
fn icons_the_host_does_not_serve_are_refused() {
    let bodies = [
        "proof-of-address: func() -> icon-ref;",
        "passport: func(size: u32) -> icon-ref;",
        "passport: func();",
        "passport: func() -> localized-ref;",
        "resource token; passport: func() -> token;",
        "passport: func() -> icon-ref; other: func();",
    ];
    for body in bodies {
        assert_eq!(
            refusal(with_icons("0.1.0", body), vec![]),
            Some(CompileFault::Mismatched(name(
                "enclavid:host-icons/icons@0.1.0"
            ))),
            "{body}"
        );
    }
    assert_eq!(
        refusal(with_icons("0.2.0", "passport: func() -> icon-ref;"), vec![]),
        Some(CompileFault::Unsatisfied(name(
            "enclavid:host-icons/icons@0.2.0"
        )))
    );
}
