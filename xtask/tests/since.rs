//! Every item of the platform's WIT says which version it is there since, as
//! WASI's does: `@since(version = …)`. Interfaces, the types each defines, and
//! the functions and resource methods; a `use` names a type that says it where
//! it is defined. wit/README.md says what a version may change.

use std::path::Path;

use wit_parser::{Resolve, Stability, Type, TypeDefKind, TypeOwner};

/// The platform's packages, each before those that use it.
const PACKAGES: [&str; 5] = [
    "host",
    "host-icons",
    "host-capture",
    "host-disclosure",
    "policy",
];

#[test]
fn every_platform_item_says_since_when() {
    let wit = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits in the repository root")
        .join("wit");
    let mut resolve = Resolve {
        all_features: true,
        ..Resolve::default()
    };
    for package in PACKAGES {
        let dir = wit.join(package);
        resolve
            .push_dir(&dir)
            .unwrap_or_else(|e| panic!("resolving {}: {e:?}", dir.display()));
    }
    let unmarked = |stability: &Stability| !matches!(stability, Stability::Stable { .. });
    let mut missing = Vec::new();
    for (id, interface) in resolve.interfaces.iter() {
        let package = &resolve.packages[interface.package.expect("a named package")].name;
        let at = format!(
            "{}:{}/{}",
            package.namespace,
            package.name,
            interface.name.as_deref().expect("a named interface")
        );
        if unmarked(&interface.stability) {
            missing.push(at.clone());
        }
        for (name, ty) in &interface.types {
            let ty = &resolve.types[*ty];
            let used = matches!(ty.kind, TypeDefKind::Type(Type::Id(other))
                if resolve.types[other].owner != TypeOwner::Interface(id));
            if !used && unmarked(&ty.stability) {
                missing.push(format!("{at}: {name}"));
            }
        }
        for (name, function) in &interface.functions {
            if unmarked(&function.stability) {
                missing.push(format!("{at}: {name}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "{} item(s) without @since:\n{}",
        missing.len(),
        missing.join("\n")
    );
}
