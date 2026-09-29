# The two host-side programs, from the same source and the same package set
# as the images they serve.
{ pkgs }:
let
  # What the images' apps are built from, the same way — so a commit that
  # leaves these two alone builds them to the same bytes.
  inherit (import ../image/app/workspace.nix { inherit (pkgs) lib; }) src fixedSeed;

  build = { package, features ? [ ] }:
    pkgs.rustPlatform.buildRustPackage {
      pname = package;
      version = "0.1.0";
      inherit src;
      preBuild = fixedSeed;
      cargoLock.lockFile = ../Cargo.lock;
      cargoBuildFlags = [ "-p" package ];
      buildFeatures = features;
      doCheck = false;
    };
in
{
  host-relay = build { package = "host-relay"; };
  # The guests dial it over vsock; without the feature it listens on TCP.
  host-hatch = build { package = "host-hatch"; features = [ "vsock" ]; };
}
