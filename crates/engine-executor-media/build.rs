//! The narrow C face over libvpx's VP8 decoder (`src/vpx.c`), compiled against
//! libvpx's headers, and libvpx linked in statically: `VPX_INCLUDE` names the
//! headers, `VPX_LIB` the directory holding `libvpx.a`. Without them the crate
//! checks but does not link. Built without `video`, there is neither.

fn main() {
    println!("cargo:rerun-if-changed=src/vpx.c");
    println!("cargo:rerun-if-env-changed=VPX_INCLUDE");
    println!("cargo:rerun-if-env-changed=VPX_LIB");
    if std::env::var_os("CARGO_FEATURE_VIDEO").is_none() {
        return;
    }
    let (Ok(include), Ok(lib)) = (std::env::var("VPX_INCLUDE"), std::env::var("VPX_LIB")) else {
        println!(
            "cargo:warning=VPX_INCLUDE and VPX_LIB are unset: engine-executor-media checks but \
             does not link"
        );
        return;
    };
    cc::Build::new()
        .file("src/vpx.c")
        .include(include)
        .opt_level(2)
        .compile("enclavid_vpx");
    println!("cargo:rustc-link-search=native={lib}");
    println!("cargo:rustc-link-lib=static=vpx");
    println!("cargo:rustc-link-lib=m");
}
