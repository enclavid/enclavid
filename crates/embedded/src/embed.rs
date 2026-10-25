//! Embedding a component's catalogs, as `enclavid {policy,plugin} embed` and
//! every other builder do it: read its project, check its texts against the
//! keys its slot declares, and write both catalogs into the component as
//! custom sections, the texts with the slot they are served through.
//!
//! The component's imports stay as they are: a slot's name is the component's
//! own (see the crate docs), so any fusion — the TEE's, or one a consumer runs
//! with plain `wac` — keeps every component's texts apart, and one component
//! importing another's texts by the slot's name shares them.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use wasm_encoder::{ComponentSection, CustomSection};
use wit_parser::{PackageId, Resolve, Span, TypeDefKind};

use crate::keys;
use crate::{
    Catalog, DisclosureFieldsSection, EXTENSIONS, I18nSection, MAX_DECLARED_DISCLOSURE_FIELDS,
    MAX_KEY_LENGTH, MAX_LANGUAGES, MAX_SLOT_LENGTH, POLICY_SLOT, SECTION_DISCLOSURE_FIELDS,
    SECTION_I18N, is_valid_slot, is_valid_text_ref, language_problems,
};

/// The preamble of a component's binary: the wasm magic, then the component
/// encoding's version and layer.
const COMPONENT_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

/// Which artifact a project is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Its slot is [`POLICY_SLOT`], and its disclosure fields are the cases of
    /// `key` in `enclavid-ext:policy/disclosure-fields`.
    Policy,
    /// Its slot is named for its own package.
    Plugin,
}

/// Where a component's project keeps what is embedded.
pub struct Project {
    /// The WIT the component was built from, with its slot: the keys of its
    /// texts are the cases of `key` in `enclavid-ext:<slot>/i18n`.
    pub wit: PathBuf,
    /// The texts: a directory of `<language>.json` files, each a language's
    /// texts by key, or one JSON file of every language's texts, by language;
    /// absent for none.
    pub i18n: PathBuf,
    pub role: Role,
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
    /// `namespace:name` of the world's package.
    pub package: String,
    /// The component's slot: its texts are served through
    /// `enclavid-ext:<slot>`.
    pub slot: String,
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

    let slot = match project.role {
        Role::Policy => POLICY_SLOT.to_string(),
        Role::Plugin => name.name.clone(),
    };
    if project.role == Role::Plugin {
        if slot == POLICY_SLOT {
            report.error(
                &wit_file,
                None,
                format!(
                    "a plugin's slot is named for its package, and `{EXTENSIONS}:{POLICY_SLOT}` \
                     is the policy's: give `{package_name}` another name"
                ),
            );
        } else if extension(&resolve, POLICY_SLOT).is_some() {
            report.error(
                &wit_file,
                None,
                format!(
                    "`{EXTENSIONS}:{POLICY_SLOT}` is the policy's slot; a plugin's texts are in \
                     `{EXTENSIONS}:{slot}`"
                ),
            );
        }
        if !is_valid_slot(&slot) {
            report.error(
                &wit_file,
                None,
                format!(
                    "a plugin's slot is named for its package, and `{slot}` is not lowercase \
                     words of letters and digits joined by `-`, at most {MAX_SLOT_LENGTH} bytes"
                ),
            );
        }
    }
    let slot_package = extension(&resolve, &slot);

    let keys = match slot_package.map_or(Ok(None), |id| text_keys(&resolve, id)) {
        Ok(keys) => keys,
        Err(problem) => {
            report.error(&wit_file, None, problem);
            None
        }
    };

    let disclosure_fields = match (project.role, slot_package) {
        (Role::Policy, Some(id)) => match disclosure_fields(&resolve, id) {
            Ok(fields) => fields,
            Err(problem) => {
                report.error(&wit_file, None, problem);
                None
            }
        },
        _ => None,
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
                            .map_or((wit_file.clone(), None), |(file, line)| (file, Some(line)));
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
            format!(
                "holds texts, but `{EXTENSIONS}:{slot}` declares no `i18n` interface with a `key` \
                 to name them"
            ),
        ),
        None => {}
    }

    let i18n_section = (!catalog.is_empty()).then(|| {
        serde_json::to_vec(&I18nSection {
            slot: slot.clone(),
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
        slot,
        keys: keys.map(|keys| keys.into_iter().map(|(key, _)| key).collect()),
        languages: catalog.keys().cloned().collect(),
        disclosure_fields,
        i18n_section,
        disclosure_fields_section,
    })
}

/// `component` with the catalogs `checked` holds written into it. Refused when
/// the check found errors, or when `component` is not a component.
pub fn embed(component: &[u8], checked: &Checked) -> Result<Vec<u8>> {
    ensure!(
        checked.report.ok(),
        "the catalogs did not check: {} error(s)",
        checked.report.errors.len()
    );
    ensure!(
        component.starts_with(&COMPONENT_PREAMBLE),
        "not a wasm component: componentize the module before embedding its catalogs"
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
    Ok(wasm)
}

/// The package of the slot `slot`, `enclavid-ext:<slot>`, when the WIT has it.
fn extension(resolve: &Resolve, slot: &str) -> Option<PackageId> {
    resolve
        .packages
        .iter()
        .find(|(_, package)| package.name.namespace == EXTENSIONS && package.name.name == slot)
        .map(|(id, _)| id)
}

/// The keys the slot `package` declares for its texts — the cases of the `key`
/// enum in its interface `i18n` — each with where it is declared; `None` for a
/// slot with no such interface.
fn text_keys(resolve: &Resolve, package: PackageId) -> Result<Option<Vec<(String, Span)>>, String> {
    let Some(interface) = resolve.packages[package].interfaces.get("i18n") else {
        return Ok(None);
    };
    let Some(key) = resolve.interfaces[*interface].types.get("key") else {
        return Err(format!(
            "`{EXTENSIONS}:{}/i18n` declares no `key`",
            resolve.packages[package].name.name
        ));
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

/// The disclosure fields the policy's slot `package` declares: the cases of
/// `key` in its `disclosure-fields`; `None` when it declares none.
fn disclosure_fields(resolve: &Resolve, package: PackageId) -> Result<Option<Vec<String>>, String> {
    let Some(interface) = resolve.packages[package]
        .interfaces
        .get("disclosure-fields")
    else {
        return Ok(None);
    };
    let Some(key) = resolve.interfaces[*interface].types.get("key") else {
        return Err(format!(
            "`{EXTENSIONS}:{POLICY_SLOT}/disclosure-fields` declares no `key`"
        ));
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

        world policy { import enclavid-ext:policy/i18n@0.1.0; }

        package enclavid-ext:policy@0.1.0 {
            interface i18n {
                use enclavid:host/types@0.1.0.{localized-ref};
                enum key { greeting, title }
                localized: func(key: key) -> localized-ref;
            }
        }";

    /// A plugin's texts, in the slot named for its package.
    const PLUGIN: &str = "package test:ocr@0.1.0;

        world plugin { import enclavid-ext:ocr/i18n@0.1.0; }

        package enclavid-ext:ocr@0.1.0 {
            interface i18n {
                use enclavid:host/types@0.1.0.{localized-ref};
                enum key { retake }
                localized: func(key: key) -> localized-ref;
            }
        }";

    /// A project of `WORLD` with `en` as its English texts' file.
    fn project(en: &str) -> (tempfile::TempDir, Project) {
        project_at("i18n", &[("i18n/en.json", en)])
    }

    /// A project of `WORLD` whose texts are at `i18n`, with `files` written at
    /// their paths in it.
    fn project_at(i18n: &str, files: &[(&str, &str)]) -> (tempfile::TempDir, Project) {
        project_of(WORLD, Role::Policy, i18n, files)
    }

    /// A project of the `role` whose world is `world`, its texts at `i18n` and
    /// `files` written at their paths in it.
    fn project_of(
        world: &str,
        role: Role,
        i18n: &str,
        files: &[(&str, &str)],
    ) -> (tempfile::TempDir, Project) {
        let dir = tempfile::tempdir().unwrap();
        let wit = dir.path().join("wit");
        fs::create_dir_all(wit.join("deps/host")).unwrap();
        fs::write(wit.join("world.wit"), world).unwrap();
        fs::write(
            wit.join("deps/host/types.wit"),
            "package enclavid:host@0.1.0;
             interface types { resource localized-ref; resource disclosure-field-ref; }",
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
            role,
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
        let wit_component::DecodedWasm::Component(resolve, world) =
            wit_component::decode(wasm).unwrap()
        else {
            panic!("not a component");
        };
        resolve.worlds[world]
            .imports
            .keys()
            .map(|key| resolve.name_world_key(key))
            .collect()
    }

    /// The texts are written in with the slot they are served through, and
    /// the component's imports stay as they are: the slot's name is its own.
    #[test]
    fn the_texts_are_embedded_with_their_slot() {
        let (_dir, project) = project(r#"{ "greeting": "Hello!", "title": "Title" }"#);
        let checked = check(&project).unwrap();
        assert!(checked.report.ok(), "{:?}", checked.report.errors);
        assert_eq!(checked.slot, POLICY_SLOT);

        let component = component(&project);
        let embedded = embed(&component, &checked).unwrap();
        assert_eq!(imports(&embedded), imports(&component));
        assert!(imports(&embedded).contains(&"enclavid-ext:policy/i18n@0.1.0".to_string()));
        let section = crate::read_i18n(checked.i18n_section.as_deref().unwrap()).unwrap();
        assert_eq!(section.slot, POLICY_SLOT);
        assert_eq!(section.languages["en"]["title"], "Title");
    }

    /// A plugin's slot is named for its package; the texts of another slot it
    /// imports are not its own.
    #[test]
    fn a_plugins_slot_is_named_for_its_package() {
        let (_dir, project) = project_of(
            PLUGIN,
            Role::Plugin,
            "i18n",
            &[("i18n/en.json", r#"{ "retake": "Try again" }"#)],
        );
        let checked = check(&project).unwrap();
        assert!(checked.report.ok(), "{:?}", checked.report.errors);
        assert_eq!(checked.slot, "ocr");
        assert_eq!(checked.keys.as_deref(), Some(&["retake".to_string()][..]));
        let section = crate::read_i18n(checked.i18n_section.as_deref().unwrap()).unwrap();
        assert_eq!(section.slot, "ocr");
    }

    /// Texts a policy imports from another slot are that slot's: the
    /// policy's keys are its own slot's alone.
    #[test]
    fn a_policys_keys_are_its_own_slots() {
        let world = format!(
            "{WORLD}
            package enclavid-ext:ocr@0.1.0 {{
                interface i18n {{
                    use enclavid:host/types@0.1.0.{{localized-ref}};
                    enum key {{ retake }}
                    localized: func(key: key) -> localized-ref;
                }}
            }}"
        )
        .replace(
            "world policy { import enclavid-ext:policy/i18n@0.1.0; }",
            "world policy {
                import enclavid-ext:policy/i18n@0.1.0;
                import enclavid-ext:ocr/i18n@0.1.0;
            }",
        );
        let (_dir, project) = project_of(
            &world,
            Role::Policy,
            "i18n",
            &[(
                "i18n/en.json",
                r#"{ "greeting": "Hello!", "title": "Title" }"#,
            )],
        );
        let checked = check(&project).unwrap();
        assert!(checked.report.ok(), "{:?}", checked.report.errors);
        assert_eq!(
            checked.keys.as_deref(),
            Some(&["greeting".to_string(), "title".to_string()][..])
        );
    }

    /// The slot `policy` is the policy's: a plugin declaring it, or named
    /// for it, is refused.
    #[test]
    fn a_plugin_does_not_take_the_policys_slot() {
        let declaring = PLUGIN.replace("enclavid-ext:ocr", "enclavid-ext:policy");
        let (_dir, project) = project_of(&declaring, Role::Plugin, "i18n", &[]);
        let checked = check(&project).unwrap();
        assert!(
            checked.report.errors[0]
                .message
                .contains("`enclavid-ext:policy` is the policy's slot"),
            "{:?}",
            checked.report.errors
        );

        let named = PLUGIN
            .replace("test:ocr", "test:policy")
            .replace("enclavid-ext:ocr", "enclavid-ext:policy");
        let (_dir, project) = project_of(&named, Role::Plugin, "i18n", &[]);
        let checked = check(&project).unwrap();
        assert!(
            checked.report.errors[0]
                .message
                .contains("give `test:policy` another name"),
            "{:?}",
            checked.report.errors
        );
    }

    /// A policy's disclosure fields are the cases of `key` in its slot's
    /// `disclosure-fields`.
    #[test]
    fn a_policys_disclosure_fields_are_its_slots() {
        let world = WORLD.replace(
            "interface i18n {",
            "interface disclosure-fields {
                use enclavid:host/types@0.1.0.{disclosure-field-ref};
                enum key { full-name, date-of-birth }
                disclosure-field: func(key: key) -> disclosure-field-ref;
            }
            interface i18n {",
        );
        let (_dir, project) = project_of(
            &world,
            Role::Policy,
            "i18n",
            &[(
                "i18n/en.json",
                r#"{ "greeting": "Hello!", "title": "Title" }"#,
            )],
        );
        let checked = check(&project).unwrap();
        assert!(checked.report.ok(), "{:?}", checked.report.errors);
        assert_eq!(
            checked.disclosure_fields.as_deref(),
            Some(&["full-name".to_string(), "date-of-birth".to_string()][..])
        );
    }

    #[test]
    fn a_core_module_is_not_embedded_into() {
        let (_dir, project) = project(r#"{ "greeting": "Hello!", "title": "Title" }"#);
        let checked = check(&project).unwrap();
        let module = b"\0asm\x01\0\0\0";
        assert!(embed(module, &checked).is_err());
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
        assert_eq!(error.line, Some(8), "{error}");
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
