# The two host-side programs, from the same source and the same package set
# as the images they serve.
{ pkgs }:
let
  # The workspace, minus what is an output rather than a source — as in
  # image/app.
  src = builtins.path {
    name = "enclavid-src";
    path = ../.;
    filter = path: type:
      let base = baseNameOf path; in
      !(base == "target" || base == ".git" || base == "node_modules" || base == "result"
        || builtins.substring 0 7 base == "result-");
  };

  build = { package, features ? [ ] }:
    pkgs.rustPlatform.buildRustPackage {
      pname = package;
      version = "0.1.0";
      inherit src;
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
