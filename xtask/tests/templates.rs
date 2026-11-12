//! A project made from a template carries the WIT its policy builds against —
//! the platform's and the plugins' it imports — as copies under `wit/deps`,
//! since the project lives outside this repository. A copy that drifted from
//! its source would build a policy against interfaces the runtime does not
//! have, so each must stay byte for byte what it copies.

use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits in the repository root")
        .to_path_buf()
}

/// Every name in `dir` that `keep` keeps, sorted.
fn names(dir: &Path, keep: impl Fn(&str) -> bool) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .filter(|name| keep(name))
        .collect();
    names.sort();
    names
}

/// Every `.wit` file in `dir`, by name.
fn wit_files(dir: &Path) -> Vec<String> {
    names(dir, |name| name.ends_with(".wit"))
}

/// A copy under `wit/deps`: its directory, its source, and the one file it
/// copies of the source, or all of them.
type Copy = (&'static str, &'static str, Option<&'static str>);

/// What every template copies: the platform's WIT.
const PLATFORM: [Copy; 5] = [
    ("host", "wit/host", None),
    ("host-capture", "wit/host-capture", None),
    ("host-disclosure", "wit/host-disclosure", None),
    ("host-icons", "wit/host-icons", None),
    ("policy", "wit/policy", None),
];

/// What a template that asks for well-known's capture specs copies besides.
const WELL_KNOWN: [Copy; 2] = [
    ("well-known", "plugins/well-known/wit", Some("world.wit")),
    (
        "well-known-texts",
        "plugins/well-known/ext",
        Some("i18n.wit"),
    ),
];

/// What a template that finds a face copies besides: the vision plugin's
/// package and face-detect's. A face plugin's `world.wit` holds its contract
/// alone; the world an implementation is built as, whose slot names the models
/// it runs, is in a file of its own, which no template copies.
const FACES: [Copy; 2] = [
    ("vision", "plugins/vision/wit", Some("world.wit")),
    ("face-detect", "plugins/face-detect/wit", Some("world.wit")),
];

/// The package of a plugin a template reads the face with.
const AGE: [Copy; 1] = [("face-age", "plugins/face-age/wit", Some("world.wit"))];
const LIVENESS: [Copy; 1] = [(
    "face-liveness",
    "plugins/face-liveness/wit",
    Some("world.wit"),
)];

/// WASI's copy is not checked: it is the registry's, and the host serves any
/// 0.2.x of it on its semver track.
const WASI: &str = "wasi-random";

#[test]
fn the_typescript_templates_carry_the_wit_they_copy() {
    let repo = repo();
    let templates = [
        ("kyc", [&PLATFORM[..], &WELL_KNOWN].concat()),
        (
            "age-verification",
            [&PLATFORM[..], &WELL_KNOWN, &FACES, &AGE].concat(),
        ),
        (
            "liveness",
            [&PLATFORM[..], &WELL_KNOWN, &FACES, &LIVENESS].concat(),
        ),
    ];
    for (template, copies) in &templates {
        let deps = repo
            .join("templates/typescript")
            .join(template)
            .join("wit/deps");
        let mut expected: Vec<String> = copies.iter().map(|(copy, ..)| copy.to_string()).collect();
        expected.push(WASI.into());
        expected.sort();
        assert_eq!(
            names(&deps, |_| true),
            expected,
            "{} holds other copies",
            deps.display()
        );
        for &(copy, source, only) in copies {
            let copy = deps.join(copy);
            let source = repo.join(source);
            let names = wit_files(&copy);
            if let Some(only) = only {
                assert_eq!(names, [only], "{}", copy.display());
            } else {
                assert_eq!(
                    names,
                    wit_files(&source),
                    "{} lists other files",
                    copy.display()
                );
            }
            for name in names {
                assert_eq!(
                    fs::read(copy.join(&name)).expect("the copy"),
                    fs::read(source.join(&name)).expect("its source"),
                    "{} differs from {}; copy it again",
                    copy.join(&name).display(),
                    source.join(&name).display(),
                );
            }
        }
    }
}
