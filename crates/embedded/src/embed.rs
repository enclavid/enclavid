//! Embedding a component's catalogs, as `enclavid {policy,plugin} embed` and
//! every other builder do it: read its project, check its texts against the
//! keys its WIT declares, write both catalogs into the component as custom
//! sections, and rename its `i18n` import to the slot its catalog names.
//!
//! The rename is what lets any fusion — the TEE's, or one a consumer runs with
//! plain `wac` — keep every component's texts apart without knowing about
//! them: two components' slots differ by name wherever their catalogs differ,
//! and the host serves each slot from the catalog its name points at.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use wac_graph::types::{ItemKind, Package};
use wac_graph::{CompositionGraph, EncodeOptions};
use wasm_encoder::{ComponentSection, CustomSection};
use wit_parser::{PackageId, Resolve, Span, TypeDefKind};

use crate::keys;
use crate::{
    Catalog, DisclosureFieldsSection, I18nSection, MAX_DECLARED_DISCLOSURE_FIELDS, MAX_KEY_LENGTH,
    MAX_LANGUAGES, SECTION_DISCLOSURE_FIELDS, SECTION_I18N, catalog_hash, embedded_import_name,
    is_valid_text_ref, language_problems,
};

/// Where a component's project keeps what is embedded.
pub struct Project {
    /// The WIT the component was built from: its world's package declares
    /// the keys of its texts (`interface i18n { enum key { … } }`).
    pub wit: PathBuf,
    /// The texts: a directory of `<language>.json` files, each a language's
    /// texts by key, or one JSON file of every language's texts, by language;
    /// absent for none.
    pub i18n: PathBuf,
    /// Whether the component is a policy, whose disclosure fields are the
    /// cases of `key` in `enclavid:host-ext/disclosure-fields`.
    pub disclosure_fields: bool,
}

/// Something wrong with a project's catalogs, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The file it is in, as the project's paths name it.
    pub file: String,
    /// 1-based, when it is known.
    pub line: Option<usize>,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}: {}", self.file, self.message),
            None => write!(f, "{}: {}", self.file, self.message),
        }
    }
}

/// What checking a project found: errors refuse the embed, warnings do not.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub errors: Vec<Finding>,
    pub warnings: Vec<Finding>,
}

impl Report {
    fn error(&mut self, file: &str, line: Option<usize>, message: impl Into<String>) {
        self.errors.push(Finding {
            file: file.to_string(),
            line,
            message: message.into(),
        });
    }

    fn warn(&mut self, file: &str, line: Option<usize>, message: impl Into<String>) {
        self.warnings.push(Finding {
            file: file.to_string(),
            line,
            message: message.into(),
        });
    }

    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// A project read and checked: what was found, and the sections it embeds.
pub struct Checked {
    pub report: Report,
    /// `namespace:name` of the world's package, whose `i18n` the component
    /// imports.
    pub package: String,
    /// The `i18n` keys the WIT declares, the languages the texts come in,
    /// and the disclosure fields.
    pub keys: Option<Vec<String>>,
    pub languages: Vec<String>,
    pub disclosure_fields: Option<Vec<String>>,
    i18n_section: Option<Vec<u8>>,
    disclosure_fields_section: Option<Vec<u8>>,
}

/// Read `project` and check its texts against its keys, and a policy's
/// disclosure fields against the bounds the engine holds them to. An error is
/// what the project's WIT or texts cannot be read as; the rest is in the
/// [`Report`].
pub fn check(project: &Project) -> Result<Checked> {
    let mut report = Report::default();
    let wit_file = project.wit.display().to_string();

    let mut resolve = Resolve::default();
    let (package, _) = resolve
        .push_dir(&project.wit)
        .with_context(|| format!("reading the WIT in {wit_file}"))?;
    let name = &resolve.packages[package].name;
    let package_name = format!("{}:{}", name.namespace, name.name);

    let keys = match text_keys(&resolve, package) {
        Ok(keys) => keys,
        Err(problem) => {
            report.error(&wit_file, None, problem);
            None
        }
    };

    let disclosure_fields = if project.disclosure_fields {
        match disclosure_fields(&resolve) {
            Ok(fields) => fields,
            Err(problem) => {
                report.error(&wit_file, None, problem);
                None
            }
        }
    } else {
        None
    };
    if let Some(fields) = &disclosure_fields {
        if fields.len() > MAX_DECLARED_DISCLOSURE_FIELDS {
            report.error(
                &wit_file,
                None,
                format!(
                    "declares {} disclosure fields, at most {MAX_DECLARED_DISCLOSURE_FIELDS}",
                    fields.len()
                ),
            );
        }
        for field in fields.iter().filter(|field| !is_valid_text_ref(field)) {
            report.error(
                &wit_file,
                None,
                format!(
                    "the disclosure field `{field}` is not lowercase letters, digits and `-`, \
                     at most {MAX_KEY_LENGTH} bytes"
                ),
            );
        }
    }

    let catalog = read_texts(&project.i18n, &mut report)?;
    if catalog.len() > MAX_LANGUAGES {
        report.error(
            &project.i18n.display().to_string(),
            None,
            format!("holds {} languages, at most {MAX_LANGUAGES}", catalog.len()),
        );
    }
    for (language, texts) in &catalog {
        let (file, of) = text_place(&project.i18n, language);
        for problem in language_problems(language, texts) {
            report.error(&file, None, format!("{of}{problem}"));
        }
    }

    match &keys {
        Some(declared) => {
            let names: Vec<String> = declared.iter().map(|(key, _)| key.clone()).collect();
            for problem in keys::check(&names, &catalog) {
                let (file, line, of) = match &problem.language {
                    Some(language) => {
                        let (file, of) = text_place(&project.i18n, language);
                        (file, None, of)
                    }
                    None => {
                        let (file, line) = declared
                            .iter()
                            .find(|(key, _)| *key == problem.key)
                            .and_then(|(_, span)| place_of_span(&resolve, *span))
                            .map_or((wit_file.clone(), None), |(file, line)| {
                                (file, Some(line))
                            });
                        (file, line, String::new())
                    }
                };
                let message = format!("{of}`{}` {}", problem.key, problem.message);
                if problem.warning {
                    report.warn(&file, line, message);
                } else {
                    report.error(&file, line, message);
                }
            }
        }
        None if !catalog.is_empty() => report.error(
            &project.i18n.display().to_string(),
            None,
            format!("holds texts, but `{package_name}` declares no `i18n` interface with a `key` to name them"),
        ),
        None => {}
    }

    let i18n_section = (!catalog.is_empty()).then(|| {
        serde_json::to_vec(&I18nSection {
            languages: catalog.clone(),
        })
        .expect("a map of strings serializes")
    });
    let disclosure_fields_section = disclosure_fields.as_ref().map(|fields| {
        serde_json::to_vec(&DisclosureFieldsSection {
            fields: fields.clone(),
        })
        .expect("a list of strings serializes")
    });
    Ok(Checked {
        report,
        package: package_name,
        keys: keys.map(|keys| keys.into_iter().map(|(key, _)| key).collect()),
        languages: catalog.keys().cloned().collect(),
        disclosure_fields,
        i18n_section,
        disclosure_fields_section,
    })
}

/// `component` with the catalogs `checked` holds written into it, and its
/// `i18n` import, if it has one, renamed to the slot they name. Refused when
/// the check found errors.
pub fn embed(component: &[u8], checked: &Checked) -> Result<Vec<u8>> {
    ensure!(
        checked.report.ok(),
        "the catalogs did not check: {} error(s)",
        checked.report.errors.len()
    );
    let mut wasm = component.to_vec();
    for (name, data) in [
        (
            SECTION_DISCLOSURE_FIELDS,
            &checked.disclosure_fields_section,
        ),
        (SECTION_I18N, &checked.i18n_section),
    ] {
        if let Some(bytes) = data {
            CustomSection {
                name: name.into(),
                data: bytes.as_slice().into(),
            }
            .append_to_component(&mut wasm);
        }
    }
    let hash = catalog_hash(
        checked.disclosure_fields_section.as_deref(),
        checked.i18n_section.as_deref(),
    );
    route(wasm, &checked.package, &hash)
}

/// `wasm` wrapped so that its import of `<package>/i18n` is the slot `hash`
/// names; `wasm` itself when it imports no such interface (it shows no text).
fn route(wasm: Vec<u8>, package: &str, hash: &[u8; 32]) -> Result<Vec<u8>> {
    let mut graph = CompositionGraph::new();
    let component = Package::from_bytes("enclavid:embedded", None, wasm.clone(), graph.types_mut())
        .context("reading the component")?;
    let interface = format!("{package}/i18n");
    let found = graph.types()[component.ty()]
        .imports
        .iter()
        .find(|(name, _)| name.as_str() == interface || name.starts_with(&format!("{interface}@")))
        .map(|(name, kind)| (name.clone(), *kind));
    let Some((import, kind)) = found else {
        return Ok(wasm);
    };
    let ItemKind::Instance(imported) = kind else {
        bail!("`{import}` is imported as something other than an interface");
    };
    let version = import.rsplit_once('@').map_or("", |(_, version)| version);
    let slot = embedded_import_name(hash, "i18n", version);

    let exports: Vec<String> = graph.types()[component.ty()]
        .exports
        .keys()
        .cloned()
        .collect();
    let id = graph.register_package(component)?;
    let instance = graph.instantiate(id);
    // A twin of the interface under the slot's name: wac keeps imports apart
    // by interface, so a renamed clone, not a new name alone.
    let mut twin = graph.types()[imported].clone();
    twin.id = Some(slot.clone());
    let twin = graph.types_mut().add_interface(twin);
    let node = graph.import(&slot, ItemKind::Instance(twin))?;
    graph.set_instantiation_argument(instance, &import, node)?;
    for name in exports {
        let export = graph.alias_instance_export(instance, &name)?;
        graph.export(export, &name)?;
    }
    graph
        .encode(EncodeOptions::default())
        .context("writing the component out")
}

/// The keys `package` declares for its texts — the cases of the `key` enum in
/// its interface `i18n` — each with where it is declared; `None` for a package
/// with no such interface.
fn text_keys(resolve: &Resolve, package: PackageId) -> Result<Option<Vec<(String, Span)>>, String> {
    let Some(interface) = resolve.packages[package].interfaces.get("i18n") else {
        return Ok(None);
    };
    let Some(key) = resolve.interfaces[*interface].types.get("key") else {
        return Err("the `i18n` interface declares no `key`".into());
    };
    let TypeDefKind::Enum(cases) = &resolve.types[*key].kind else {
        return Err("the `key` of `i18n` must be an enum, a case for each text".into());
    };
    Ok(Some(
        cases
            .cases
            .iter()
            .map(|case| (case.name.clone(), case.span))
            .collect(),
    ))
}

/// The disclosure fields a policy declares: the cases of `key` in
/// `enclavid:host-ext/disclosure-fields`; `None` when it declares none.
fn disclosure_fields(resolve: &Resolve) -> Result<Option<Vec<String>>, String> {
    let Some((_, package)) = resolve.packages.iter().find(|(_, package)| {
        package.name.namespace == "enclavid" && package.name.name == "host-ext"
    }) else {
        return Ok(None);
    };
    let Some(interface) = package.interfaces.get("disclosure-fields") else {
        return Ok(None);
    };
    let Some(key) = resolve.interfaces[*interface].types.get("key") else {
        return Err("`enclavid:host-ext/disclosure-fields` declares no `key`".into());
    };
    let TypeDefKind::Enum(cases) = &resolve.types[*key].kind else {
        return Err(
            "the `key` of `disclosure-fields` must be an enum, a case for each field".into(),
        );
    };
    Ok(Some(
        cases.cases.iter().map(|case| case.name.clone()).collect(),
    ))
}

/// The texts at `path`: a directory of `<language>.json` files, each a
/// language's texts by key and named for it, or one JSON file of every
/// language's texts, by language; nothing when there is neither. What is not
/// of that shape is an error in the report, and left out.
fn read_texts(path: &Path, report: &mut Report) -> Result<Catalog> {
    if path.is_file() {
        let file = path.display().to_string();
        let source = fs::read(path).with_context(|| format!("reading {file}"))?;
        return Ok(match serde_json::from_slice::<Catalog>(&source) {
            Ok(catalog) => catalog,
            Err(e) => {
                report.error(
                    &file,
                    Some(e.line()),
                    format!("is not an object of each language's texts by key: {e}"),
                );
                Catalog::new()
            }
        });
    }
    let mut catalog = Catalog::new();
    if !path.is_dir() {
        return Ok(catalog);
    }
    let entries = fs::read_dir(path).with_context(|| format!("reading {}", path.display()))?;
    for entry in entries {
        let entry = entry?.path();
        let file = entry.display().to_string();
        if entry.extension().and_then(|e| e.to_str()) != Some("json") {
            report.warn(&file, None, "is not a `.json` file, so it is left out");
            continue;
        }
        let Some(language) = entry.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let source = fs::read(&entry).with_context(|| format!("reading {file}"))?;
        match serde_json::from_slice::<BTreeMap<String, String>>(&source) {
            Ok(texts) => {
                catalog.insert(language.to_string(), texts);
            }
            Err(e) => report.error(
                &file,
                Some(e.line()),
                format!("is not an object of texts by key: {e}"),
            ),
        }
    }
    Ok(catalog)
}

/// Where a language's texts are written, and how a finding about them names
/// the language: by its own file in a directory of them, or by its key in the
/// one file of every language.
fn text_place(i18n: &Path, language: &str) -> (String, String) {
    if i18n.is_file() {
        (i18n.display().to_string(), format!("`{language}`: "))
    } else {
        let file = i18n.join(format!("{language}.json"));
        (file.display().to_string(), String::new())
    }
}

/// The file and line a WIT span starts on, as the parser renders them.
fn place_of_span(resolve: &Resolve, span: Span) -> Option<(String, usize)> {
    let rendered = resolve.render_location(span);
    let mut parts = rendered.rsplitn(3, ':');
    let _column = parts.next()?;
    let line = parts.next()?.parse().ok()?;
    Some((parts.next()?.to_string(), line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wit_component::{ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata};
    use wit_parser::ManglingAndAbi;

    const WORLD: &str = "package test:policy@0.1.0;

        interface i18n {
            use enclavid:host/types@0.1.0.{localized-ref};
            enum key { greeting, title }
            localized: func(key: key) -> localized-ref;
        }

        world policy { import i18n; }";

    /// A project of `WORLD` with `en` as its English texts' file.
    fn project(en: &str) -> (tempfile::TempDir, Project) {
        project_at("i18n", &[("i18n/en.json", en)])
    }

    /// A project of `WORLD` whose texts are at `i18n`, with `files` written at
    /// their paths in it.
    fn project_at(i18n: &str, files: &[(&str, &str)]) -> (tempfile::TempDir, Project) {
        let dir = tempfile::tempdir().unwrap();
        let wit = dir.path().join("wit");
        fs::create_dir_all(wit.join("deps/host")).unwrap();
        fs::write(wit.join("world.wit"), WORLD).unwrap();
        fs::write(
            wit.join("deps/host/types.wit"),
            "package enclavid:host@0.1.0; interface types { resource localized-ref; }",
        )
        .unwrap();
        for (path, source) in files {
            let path = dir.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        let project = Project {
            wit,
            i18n: dir.path().join(i18n),
            disclosure_fields: false,
        };
        (dir, project)
    }

    /// A component of the project's world, its functions doing nothing.
    fn component(project: &Project) -> Vec<u8> {
        let mut resolve = Resolve::default();
        let (package, _) = resolve.push_dir(&project.wit).unwrap();
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

    fn imports(wasm: &[u8]) -> Vec<String> {
        let mut types = wac_graph::types::Types::default();
        let package = Package::from_bytes("test", None, wasm.to_vec(), &mut types).unwrap();
        types[package.ty()].imports.keys().cloned().collect()
    }

    #[test]
    fn the_texts_import_is_renamed_to_the_slot_its_catalog_names() {
        let (_dir, project) = project(r#"{ "greeting": "Hello!", "title": "Title" }"#);
        let checked = check(&project).unwrap();
        assert!(checked.report.ok(), "{:?}", checked.report.errors);

        let embedded = embed(&component(&project), &checked).unwrap();
        let imports = imports(&embedded);
        let slot = embedded_import_name(
            &catalog_hash(None, checked.i18n_section.as_deref()),
            "i18n",
            "0.1.0",
        );
        assert!(imports.contains(&slot), "{imports:?}");
        assert!(
            !imports
                .iter()
                .any(|name| name.starts_with("test:policy/i18n"))
        );
    }

    #[test]
    fn a_text_no_key_names_is_placed_in_its_file() {
        let (_dir, project) =
            project(r#"{ "greeting": "Hello!", "title": "Title", "subtitle": "Sub" }"#);
        let checked = check(&project).unwrap();
        let error = &checked.report.errors[0];
        assert!(error.file.ends_with("en.json"), "{error}");
        assert!(error.message.contains("`subtitle`"), "{error}");
        assert!(embed(&component(&project), &checked).is_err());
    }

    #[test]
    fn a_key_without_a_text_is_placed_on_its_case() {
        let (_dir, project) = project(r#"{ "greeting": "Hello!" }"#);
        let checked = check(&project).unwrap();
        let error = &checked.report.errors[0];
        assert!(error.file.ends_with("world.wit"), "{error}");
        assert_eq!(error.line, Some(5), "{error}");
        assert!(error.message.contains("`title` has no text"), "{error}");
    }

    /// Every language in one file embeds as a directory of one file each does:
    /// the same section, so the same slot.
    #[test]
    fn one_file_of_every_language_embeds_as_a_directory_of_them() {
        let en = r#"{ "greeting": "Hello!", "title": "Title" }"#;
        let ru = r#"{ "greeting": "Привет!", "title": "Заголовок" }"#;
        let (_dir, files) = project_at("i18n", &[("i18n/en.json", en), ("i18n/ru.json", ru)]);
        let (_one, one) = project_at(
            "i18n.json",
            &[("i18n.json", &format!(r#"{{ "en": {en}, "ru": {ru} }}"#))],
        );
        let (files, one) = (check(&files).unwrap(), check(&one).unwrap());
        assert!(one.report.ok(), "{:?}", one.report.errors);
        assert_eq!(one.languages, ["en", "ru"]);
        assert_eq!(one.i18n_section, files.i18n_section);
    }

    /// In one file of every language, what is wrong is placed in that file and
    /// names the language it is about.
    #[test]
    fn in_one_file_a_finding_names_its_language() {
        let (_dir, project) = project_at(
            "i18n.json",
            &[(
                "i18n.json",
                r#"{ "en": { "greeting": "Hello!", "title": "Title" }, "ru": { "subtitle": "Подзаголовок" } }"#,
            )],
        );
        let checked = check(&project).unwrap();
        let error = &checked.report.errors[0];
        assert!(error.file.ends_with("i18n.json"), "{error}");
        assert!(error.message.starts_with("`ru`: `subtitle`"), "{error}");
    }

    #[test]
    fn a_file_that_is_not_texts_by_key_is_refused() {
        let (_dir, project) =
            project("{\n  \"greeting\": { \"one\": \"Hi\" },\n  \"title\": \"Title\"\n}");
        let checked = check(&project).unwrap();
        let error = &checked.report.errors[0];
        assert!(error.file.ends_with("en.json"), "{error}");
        assert_eq!(error.line, Some(2), "{error}");
    }
}
