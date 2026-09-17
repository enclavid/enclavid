//! Compiles the applicant's page into this binary.
//!
//! The page lives with the handlers it calls, so ONE measurement covers both.
//! An applicant asking what code they are running gets a single digest rather
//! than two that only mean something checked together.
//!
//! It is carried IN the executable rather than beside it in the initramfs, and
//! that is the point rather than a convenience. What must be true is that the
//! bytes a browser runs are part of the measurement — a table of
//! `include_bytes!` makes that true by construction, with no path handling, no
//! filesystem read and nothing for a runtime to resolve differently. It also
//! retires `ENCLAVID_FRONTEND_DIR`, which pointed this process at a directory
//! the host named at RUN time.
//!
//! What it does NOT rest on is who terminates the browser's TLS session. That
//! party can replace whatever is served over it, whoever produced it — which is
//! why the terminator has to be measured too, and is, and why the leg from it to
//! here is mutual RA-TLS with this image's measurement pinned.
//!
//! No crate is pulled in to do it. `include_dir` and `rust-embed` both exist and
//! both would work, and neither earns a new dependency in a measured binary for
//! what is a directory walk and a `write!`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Where the built page comes from. Set by `image/app`, which takes it from the
/// nix derivation that builds `frontend/`.
const DIST: &str = "ENCLAVID_FRONTEND_DIST";

fn main() {
    println!("cargo::rerun-if-env-changed={DIST}");

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let generated = out.join("assets.rs");

    let Some(dist) = std::env::var_os(DIST) else {
        // An attested build must carry the page. `vsock` is the axis that says
        // this build is the one that ships — the same axis that decides whether
        // it terminates RA-TLS — so a measured gateway cannot be built without
        // the thing it exists to serve.
        assert!(
            std::env::var_os("CARGO_FEATURE_VSOCK").is_none(),
            "{DIST} is not set, so this build carries no page. An attested gateway \
             serves the applicant's page out of its own measurement and cannot be \
             built without it. Build through `image/app`, which supplies it."
        );
        // A developer build has no page and says so. Vite serves it on its own
        // port, which is what `frontend/vite.config.ts` is arranged for.
        std::fs::write(&generated, "pub const ASSETS: &[Asset] = &[];\n")
            .expect("write the empty asset table");
        return;
    };

    let dist = PathBuf::from(dist);
    println!("cargo::rerun-if-changed={}", dist.display());

    let mut files = Vec::new();
    collect(&dist, &dist, &mut files);
    // Directory iteration order is not defined, and the generated table is an
    // input to a published digest. Sorted, so two builds of one tree agree.
    files.sort();

    let mut table = String::from("pub const ASSETS: &[Asset] = &[\n");
    for route in &files {
        let source = dist.join(route.trim_start_matches('/'));
        writeln!(
            table,
            "    Asset {{ path: {route:?}, content_type: {:?}, bytes: include_bytes!({:?}) }},",
            content_type(route),
            source
        )
        .expect("writing to a String");
    }
    table.push_str("];\n");

    std::fs::write(&generated, table).expect("write the asset table");
}

/// Every file under `dir`, as the request path it answers to.
fn collect(root: &Path, dir: &Path, into: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("a directory entry");
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, into);
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("every file is under the root")
            .to_str()
            .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()));
        // Built on the host that runs this build script, served to a browser, so
        // the separator is the URL's and not the platform's.
        into.push(format!(
            "/{}",
            relative.replace(std::path::MAIN_SEPARATOR, "/")
        ));
    }
}

/// What to say a file is.
///
/// A fixed table rather than sniffing, and it refuses what it does not know: an
/// extension nobody listed is a file nobody meant to ship, and guessing
/// `application/octet-stream` for it would hide that behind a download prompt.
fn content_type(route: &str) -> &'static str {
    let extension = route.rsplit_once('.').map(|(_, e)| e).unwrap_or_default();
    match extension {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "woff2" => "font/woff2",
        "png" => "image/png",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        other => panic!(
            "the built page carries `{route}`, and nothing here says what a `.{other}` \
             is. Add it to `content_type` in build.rs, or stop shipping the file."
        ),
    }
}
