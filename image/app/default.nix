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

  # `noDefaultFeatures` is per role rather than blanket: `--no-default-features`
  # applies to the selected package, so setting it where a package has no
  # feature table changes nothing and only obscures which roles depend on it.
  mkApp = { pname, package, binary, features ? [ ], noDefaultFeatures ? false }:
    static.rustPlatform.buildRustPackage {
      inherit pname src;
      version = "0.1.0";

      cargoLock.lockFile = ../../Cargo.lock;

      cargoBuildFlags = [ "-p" package ];
      buildFeatures = features;
      buildNoDefaultFeatures = noDefaultFeatures;

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
  # The api CVM: HTTP over vsock, session lifecycle.
  #
  # Both features are load-bearing and neither has a default that would supply
  # it. `vsock` is the transport — without it the binary listens on TCP, which
  # a guest with no IP stack cannot do. `sev-snp` is the attestation backend,
  # and it is reached by turning the defaults OFF: cargo features are additive,
  # so asking for `sev-snp` on top of the default `dev-attestation` would leave
  # a software test key compiled in beside the real one. Taking defaults here
  # is what produced an image whose quotes were signed by a key generated at
  # each process start.
  api = mkApp {
    pname = "enclavid-app-api";
    package = "enclavid-api";
    binary = "enclavid-api";
    noDefaultFeatures = true;
    features = [ "sev-snp" "vsock" ];
  };

  # The storage CVM: the blind ciphertext store.
  storage = mkApp {
    pname = "enclavid-app-storage";
    package = "enclavid-storage";
    binary = "storage-cvm";
  };
}
