//! The texts and disclosure fields a composition declares, as the compile holds
//! them. A component's texts come through its slot, `enclavid-ext:<slot>/i18n`,
//! through any fusion — the compile's own, or a consumer's plain `wac plug` —
//! served from the one catalog that names the slot, and a policy's disclosure
//! fields through the cases its catalog lists. Components are built from WIT
//! alone and embedded as `enclavid {policy,plugin} embed` embeds them.

use std::fs;
use std::path::Path;

use enclavid_embedded::embed::{self, Project, Role};
use engine_compiler::{BundleParts, Compiler};
use engine_types::compile::{Artifact, CompileFault, InterfaceName};
use engine_types::composition::PluginInstance;
use wac_graph::types::Package;
use wac_graph::{CompositionGraph, EncodeOptions};
use wit_component::{ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata};
use wit_parser::{ManglingAndAbi, Resolve};

const HOST: &str = "package enclavid:host@0.1.0;
    interface types { resource localized-ref; resource disclosure-field-ref; }";

const API: &str = "package test:api@0.1.0;
    interface api { ping: func(); }";

/// The texts interface of `slot` at `version`, its keys `cases`.
fn texts_of(slot: &str, version: &str, cases: &str) -> String {
    format!(
        "package enclavid-ext:{slot}@{version} {{
             interface i18n {{
                 use enclavid:host/types@0.1.0.{{localized-ref}};
                 enum key {{ {cases} }}
                 localized: func(key: key) -> localized-ref;
             }}
         }}"
    )
}

/// The texts interface of `slot`, at the version the host serves.
fn texts(slot: &str, cases: &str) -> String {
    texts_of(slot, "0.1.0", cases)
}

/// The same, as a file of its own to put in `deps/`.
fn texts_dep(slot: &str, cases: &str) -> String {
    format!(
        "package enclavid-ext:{slot}@0.1.0;
         interface i18n {{
             use enclavid:host/types@0.1.0.{{localized-ref}};
             enum key {{ {cases} }}
             localized: func(key: key) -> localized-ref;
         }}"
    )
}

const POLICY_TEXTS: &str = r#"{ "greeting": "Hello!", "title": "Title" }"#;

/// A component's project: its WIT, the host's beside it, and its texts.
struct Built {
    _dir: tempfile::TempDir,
    project: Project,
}

/// A project of the `role` whose WIT is `world`, with `deps` as packages
/// beside the host's, and `en` as its English texts.
fn project(role: Role, world: &str, deps: &[(&str, &str)], en: Option<&str>) -> Built {
    let dir = tempfile::tempdir().unwrap();
    let wit = dir.path().join("wit");
    fs::create_dir_all(&wit).unwrap();
    fs::write(wit.join("world.wit"), world).unwrap();
    for (name, source) in [("host", HOST)].iter().chain(deps) {
        let dep = wit.join("deps").join(name);
        fs::create_dir_all(&dep).unwrap();
        fs::write(dep.join(format!("{name}.wit")), source).unwrap();
    }
    let i18n = dir.path().join("i18n");
    if let Some(en) = en {
        fs::create_dir_all(&i18n).unwrap();
        fs::write(i18n.join("en.json"), en).unwrap();
    }
    let project = Project { wit, i18n, role };
    Built { _dir: dir, project }
}

/// A component of the project's world, its functions doing nothing.
fn component(wit: &Path) -> Vec<u8> {
    let mut resolve = Resolve::default();
    let (package, _) = resolve.push_dir(wit).unwrap();
    let world = resolve.select_world(&[package], None).unwrap();
    let mut module = dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8).unwrap();
    ComponentEncoder::default()
        .module(&module)
        .unwrap()
        .validate(true)
        .encode()
        .unwrap()
}

/// The project's component, embedded.
fn embedded(built: &Built) -> Vec<u8> {
    let checked = embed::check(&built.project).unwrap();
    assert!(checked.report.ok(), "{:?}", checked.report.errors);
    embed::embed(&component(&built.project.wit), &checked).unwrap()
}

/// The test policy: its own texts, and `imports` beside them.
fn policy(imports: &str, deps: &[(&str, &str)]) -> Built {
    project(
        Role::Policy,
        &format!(
            "package test:policy@0.1.0;
             world policy {{ import enclavid-ext:policy/i18n@0.1.0; {imports} }}
             {}",
            texts("policy", "greeting, title")
        ),
        deps,
        Some(POLICY_TEXTS),
    )
}

/// A plugin serving `test:api`, with texts of its own, `en`, in its slot,
/// `plugin`.
fn plugin_with(en: &str) -> Built {
    project(
        Role::Plugin,
        &format!(
            "package test:plugin@0.1.0;
             world plugin {{ import enclavid-ext:plugin/i18n@0.1.0; export test:api/api@0.1.0; }}
             {}",
            texts("plugin", "title")
        ),
        &[("api", API)],
        Some(en),
    )
}

fn plugin() -> Built {
    plugin_with(r#"{ "title": "The plugin's title" }"#)
}

/// `policy` with `plugins` compiled, or the fault the compile refuses it for.
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

fn name(s: &str) -> InterfaceName {
    InterfaceName::new(s).expect("a legal name")
}

/// The slots of `parts`, by name, each with the catalog it is served from,
/// which must be one of the catalogs `parts` carries.
fn slots(parts: &BundleParts) -> Vec<(&str, [u8; 32])> {
    let mut slots: Vec<(&str, [u8; 32])> = parts
        .embedded_imports
        .iter()
        .map(|slot| {
            assert!(
                parts
                    .catalogs
                    .iter()
                    .any(|(hash, _)| *hash == slot.catalog_hash),
                "{} is served from no carried catalog",
                slot.instance_name
            );
            (slot.instance_name.as_str(), slot.catalog_hash)
        })
        .collect();
    slots.sort_unstable();
    slots
}

#[test]
fn a_components_texts_come_through_its_slot() {
    let parts = compile(embedded(&policy("", &[])), vec![]).expect("it compiles");
    assert_eq!(
        slots(&parts)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        ["enclavid-ext:policy/i18n@0.1.0"]
    );
}

/// A component whose texts were not embedded imports a slot no catalog names.
#[test]
fn texts_not_embedded_are_refused() {
    let built = policy("", &[]);
    assert_eq!(
        compile(component(&built.project.wit), vec![]).err(),
        Some(CompileFault::Unsatisfied(name(
            "enclavid-ext:policy/i18n@0.1.0"
        )))
    );
}

/// A slot's texts at a version the host does not serve are not served.
#[test]
fn a_slots_texts_at_another_version_are_refused() {
    let built = project(
        Role::Policy,
        &format!(
            "package test:policy@0.1.0;
             world policy {{ import enclavid-ext:policy/i18n@0.2.0; }}
             {}",
            texts_of("policy", "0.2.0", "greeting, title")
        ),
        &[],
        Some(POLICY_TEXTS),
    );
    assert_eq!(
        compile(embedded(&built), vec![]).err(),
        Some(CompileFault::Unsatisfied(name(
            "enclavid-ext:policy/i18n@0.2.0"
        )))
    );
}

/// The interface texts were once resolved through by a string key is not one
/// the host serves.
#[test]
fn the_texts_by_a_string_key_are_not_served() {
    let built = project(
        Role::Policy,
        "package test:policy@0.1.0;
         world policy { import enclavid:host/embedded-i18n@0.1.0; }",
        &[(
            "host",
            "package enclavid:host@0.1.0;
             interface types { resource localized-ref; resource disclosure-field-ref; }
             interface embedded-i18n {
                 use types.{localized-ref};
                 localized: func(key: string) -> localized-ref;
             }",
        )],
        None,
    );
    assert_eq!(
        compile(component(&built.project.wit), vec![]).err(),
        Some(CompileFault::Unsatisfied(name(
            "enclavid:host/embedded-i18n@0.1.0"
        )))
    );
}

/// Fused by the compile, or before it by a consumer with plain `wac plug`, a
/// policy and a plugin take their texts through two slots, each served from
/// its own catalog.
#[test]
fn every_components_slot_survives_any_fusion() {
    let policy = embedded(&policy("import test:api/api@0.1.0;", &[("api", API)]));
    let plugin = embedded(&plugin());

    let parts = compile(policy.clone(), vec![plugin.clone()]).expect("the compile fuses it");
    let fused = slots(&parts);
    assert_eq!(
        fused.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        [
            "enclavid-ext:plugin/i18n@0.1.0",
            "enclavid-ext:policy/i18n@0.1.0"
        ]
    );
    assert_ne!(fused[0].1, fused[1].1, "each slot, its own catalog");

    let mut graph = CompositionGraph::new();
    let socket = Package::from_bytes("socket", None, policy, graph.types_mut()).unwrap();
    let socket = graph.register_package(socket).unwrap();
    let plug = Package::from_bytes("plug", None, plugin, graph.types_mut()).unwrap();
    let plug = graph.register_package(plug).unwrap();
    wac_graph::plug(&mut graph, vec![plug], socket).unwrap();
    let plugged = graph.encode(EncodeOptions::default()).unwrap();

    let parts = compile(plugged, vec![]).expect("a consumer's own fusion compiles");
    assert_eq!(parts.catalogs.len(), 2, "both catalogs, nested, are found");
    assert_eq!(slots(&parts), fused);
}

/// A policy importing a plugin's texts by its slot shares them: the fusion
/// makes one import of the two, served from the plugin's catalog.
#[test]
fn a_slot_two_components_import_is_one_served_from_its_catalog() {
    let policy = embedded(&policy(
        "import test:api/api@0.1.0; import enclavid-ext:plugin/i18n@0.1.0;",
        &[
            ("api", API),
            ("plugin-texts", &texts_dep("plugin", "title")),
        ],
    ));
    let parts = compile(policy, vec![embedded(&plugin())]).expect("it compiles");
    let shared = slots(&parts);
    assert_eq!(
        shared.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        [
            "enclavid-ext:plugin/i18n@0.1.0",
            "enclavid-ext:policy/i18n@0.1.0"
        ]
    );

    let alone = slots(&compile(embedded(&self::policy("", &[])), vec![]).unwrap())[0].1;
    assert_eq!(
        shared[1].1, alone,
        "the policy's slot, from the policy's catalog"
    );
    assert_ne!(shared[0].1, alone, "the plugin's slot, from the plugin's");
}

/// A policy built against other keys of a plugin's texts than the plugin's
/// own does not fuse with it: one import cannot be of two types.
#[test]
fn a_slot_imported_with_other_keys_than_its_owners_is_refused() {
    let policy = embedded(&policy(
        "import test:api/api@0.1.0; import enclavid-ext:plugin/i18n@0.1.0;",
        &[
            ("api", API),
            ("plugin-texts", &texts_dep("plugin", "title, subtitle")),
        ],
    ));
    assert_eq!(
        compile(policy, vec![embedded(&plugin())]).err(),
        Some(CompileFault::Mismatched(name(
            "enclavid-ext:plugin/i18n@0.1.0"
        )))
    );
}

/// The texts of a slot no pinned artifact carries a catalog of are served by
/// nothing.
#[test]
fn a_slot_no_catalog_names_is_refused() {
    let policy = embedded(&policy(
        "import enclavid-ext:plugin/i18n@0.1.0;",
        &[("plugin-texts", &texts_dep("plugin", "title"))],
    ));
    assert_eq!(
        compile(policy, vec![]).err(),
        Some(CompileFault::Unsatisfied(name(
            "enclavid-ext:plugin/i18n@0.1.0"
        )))
    );
}

/// Two catalogs of one slot are refused, unless they are the same bytes —
/// one artifact pinned twice.
#[test]
fn a_second_catalog_of_a_slot_is_refused() {
    let policy = embedded(&policy("import test:api/api@0.1.0;", &[("api", API)]));
    let plugin = embedded(&plugin());
    let another = embedded(&plugin_with(r#"{ "title": "Another title" }"#));

    compile(policy.clone(), vec![plugin.clone(), plugin.clone()])
        .expect("one catalog, twice, is one");
    assert_eq!(
        compile(policy, vec![plugin, another]).err(),
        Some(CompileFault::CatalogInvalid(Artifact::Plugin(
            "test:plugin1".into()
        )))
    );
}

/// The slot `policy` is the policy's: a plugin carrying a catalog that names
/// it is refused.
#[test]
fn the_policys_slot_is_the_policys_alone() {
    let policy = embedded(&policy("import test:api/api@0.1.0;", &[("api", API)]));
    let policys = embed::check(&self::policy("", &[]).project).unwrap();
    let impostor = embed::embed(&component(&plugin().project.wit), &policys).unwrap();
    assert_eq!(
        compile(policy, vec![impostor]).err(),
        Some(CompileFault::CatalogInvalid(Artifact::Plugin(
            "test:plugin0".into()
        )))
    );
}

/// Texts embedded into a component whose keys are not the ones they were
/// checked against: the slot's keys do not fit its catalog.
#[test]
fn a_catalog_its_slots_keys_do_not_fit_is_refused() {
    let checked_against = policy("", &[]);
    let other_keys = project(
        Role::Policy,
        &format!(
            "package test:policy@0.1.0;
             world policy {{ import enclavid-ext:policy/i18n@0.1.0; }}
             {}",
            texts("policy", "greeting, subtitle")
        ),
        &[],
        None,
    );
    let checked = embed::check(&checked_against.project).unwrap();
    let wasm = embed::embed(&component(&other_keys.project.wit), &checked).unwrap();
    assert_eq!(
        compile(wasm, vec![]).err(),
        Some(CompileFault::CatalogInvalid(Artifact::Policy))
    );
}

/// Texts embedded into a component whose `key` is a variant, a case able to
/// carry a value: no slot of that shape is what the host serves.
#[test]
fn a_slot_whose_key_is_not_an_enum_is_refused() {
    let checked_against = policy("", &[]);
    let variant_keys = project(
        Role::Policy,
        "package test:policy@0.1.0;
         world policy { import enclavid-ext:policy/i18n@0.1.0; }
         package enclavid-ext:policy@0.1.0 {
             interface i18n {
                 use enclavid:host/types@0.1.0.{localized-ref};
                 variant key { greeting, title }
                 localized: func(key: key) -> localized-ref;
             }
         }",
        &[],
        None,
    );
    let checked = embed::check(&checked_against.project).unwrap();
    let wasm = embed::embed(&component(&variant_keys.project.wit), &checked).unwrap();
    let refused = compile(wasm, vec![]).err().expect("refused");
    assert!(
        matches!(refused, CompileFault::Mismatched(_)),
        "{refused:?}"
    );
}

/// A policy declaring two disclosure fields, the cases of its `key`, and
/// `function` beside them.
fn with_disclosure_fields(function: &str) -> Built {
    project(
        Role::Policy,
        &format!(
            "package test:policy@0.1.0;
             world policy {{ import enclavid-ext:policy/disclosure-fields@0.1.0; }}
             package enclavid-ext:policy@0.1.0 {{
                 interface disclosure-fields {{
                     use enclavid:host/types@0.1.0.{{disclosure-field-ref}};
                     enum key {{ passport-number, full-name }}
                     {function}
                 }}
             }}"
        ),
        &[],
        None,
    )
}

const DISCLOSURE_FIELD: &str = "disclosure-field: func(key: key) -> disclosure-field-ref;";

/// A policy's disclosure fields are the cases of its `key`, which its
/// embedding lists in its catalog — what the consent screen counts.
#[test]
fn disclosure_fields_come_through_the_cases_the_catalog_lists() {
    let built = with_disclosure_fields(DISCLOSURE_FIELD);
    let parts = compile(embedded(&built), vec![]).expect("it compiles");
    let (_, decls) = &parts.catalogs[0];
    let mut fields: Vec<&str> = decls.disclosure_fields.iter().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(fields, ["full-name", "passport-number"]);
}

/// Cases no catalog lists — a policy whose embedding did not write its list —
/// are refused as the policy's catalog; a function the host does not serve as
/// another type.
#[test]
fn disclosure_fields_the_catalogs_do_not_list_are_refused() {
    let built = with_disclosure_fields(DISCLOSURE_FIELD);
    assert_eq!(
        compile(component(&built.project.wit), vec![]).err(),
        Some(CompileFault::CatalogInvalid(Artifact::Policy))
    );

    for function in [
        "disclosure-field: func(key: string) -> disclosure-field-ref;",
        "disclosure-field: func(key: key) -> string;",
        "disclosure-field: func(key: key) -> disclosure-field-ref; other: func();",
    ] {
        let built = with_disclosure_fields(function);
        assert_eq!(
            compile(component(&built.project.wit), vec![]).err(),
            Some(CompileFault::Mismatched(name(
                "enclavid-ext:policy/disclosure-fields@0.1.0"
            ))),
            "{function}"
        );
    }
}

/// The disclosure fields are the policy's list alone: a plugin carrying a list
/// of its own is refused.
#[test]
fn disclosure_fields_are_the_policys_alone() {
    let policy = embedded(&policy("import test:api/api@0.1.0;", &[("api", API)]));
    let fields = embed::check(&with_disclosure_fields(DISCLOSURE_FIELD).project).unwrap();
    let listing = embed::embed(&component(&plugin().project.wit), &fields).unwrap();
    assert_eq!(
        compile(policy, vec![listing]).err(),
        Some(CompileFault::CatalogInvalid(Artifact::Plugin(
            "test:plugin0".into()
        )))
    );
}
