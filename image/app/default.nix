# Role applications — reproducible build.
#
# The last unpinned input to the measurement. With this, a published launch
# digest becomes a function of one repository commit and nothing else: firmware
# version, kernel config, busybox config, these binaries, and the cmdline.
#
#   nix-build image/app -A api
#   nix-build image/app -A storage
#
# Static musl, because the initramfs carries no libc and no dynamic loader —
# see image/initramfs.
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  static = pkgs.pkgsStatic;

  # The workspace, minus everything that is an output rather than a source.
  # Filtering matters for more than build time: an unfiltered `target/` would
  # put the previous build's artefacts into this build's input hash.
  src = builtins.path {
    name = "enclavid-src";
    path = ../..;
    filter = path: type:
      let base = baseNameOf path; in
      !(base == "target" || base == ".git" || base == "node_modules" || base == "result");
  };

  mkApp = { pname, package, binary, features ? [ ] }:
    static.rustPlatform.buildRustPackage {
      inherit pname src;
      version = "0.1.0";

      cargoLock.lockFile = ../../Cargo.lock;

      cargoBuildFlags = [ "-p" package ];
      buildFeatures = features;

      # The workspace has crates that do not belong in a guest image and do not
      # cross-compile cleanly (the CLI, host-side daemons). Build one package.
      doCheck = false;

      installPhase = ''
        runHook preInstall
        mkdir -p $out
        install -m 0755 "target/${static.stdenv.hostPlatform.rust.rustcTarget}/release/${binary}" $out/${binary}
        (cd $out && sha256sum ${binary} > ${binary}.sha256)
        runHook postInstall
      '';
    };
in
{
  # The api CVM: HTTP over vsock, session lifecycle. `vsock` is the production
  # transport — without it the binary listens on TCP, which a guest with no IP
  # stack cannot do.
  api = mkApp {
    pname = "enclavid-app-api";
    package = "enclavid-api";
    binary = "enclavid-api";
    features = [ "vsock" ];
  };

  # The storage CVM: the blind ciphertext store.
  storage = mkApp {
    pname = "enclavid-app-storage";
    package = "enclavid-storage";
    binary = "storage-cvm";
  };
}
