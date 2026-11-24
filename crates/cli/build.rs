// The CLI is released as the npm package that package.json describes, and says
// that package's version.
fn main() {
    println!("cargo::rerun-if-changed=package.json");
    let package = std::fs::read_to_string("package.json").expect("crates/cli/package.json is read");
    let package: serde_json::Value =
        serde_json::from_str(&package).expect("crates/cli/package.json is JSON");
    let version = package["version"]
        .as_str()
        .expect("crates/cli/package.json has a version");
    println!("cargo::rustc-env=ENCLAVID_CLI_VERSION={version}");
}
