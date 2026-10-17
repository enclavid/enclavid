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

/// Every `.wit` file in `dir`, by name.
fn wit_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .filter(|name| name.ends_with(".wit"))
        .collect();
    names.sort();
    names
}

#[test]
fn the_typescript_template_carries_the_wit_it_copies() {
    let repo = repo();
    let deps = repo.join("templates/policy-ts-qjs/wit/deps");
    // A copy of a whole directory, or of the one file named.
    for (copy, source, only) in [
        ("host", "wit/host", None),
        ("policy", "wit/policy", None),
        ("shared-types", "wit/shared-types", None),
        ("well-known", "plugins/well-known/wit", Some("world.wit")),
        ("wasi-random", "wit/wasi", Some("random.wit")),
    ] {
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
