# What a cargo build of this workspace is given, for every build of it — the
# role applications here and the host-side programs in deploy/ — so that two
# commits whose Rust did not change build the same bytes.
#
# Two things would otherwise tie the bytes to the whole repository. The input:
# a source that took the whole tree moved with any file in it, docs and
# deploy/ included. And the seed: nixpkgs seeds every C compile with the start
# of the output path (`-frandom-seed`, its reproducible-builds hook), and that
# path is a hash over the input — so a README edit changed the C objects inside
# every binary, and every measurement with them.
{ lib }:
{
  # The files cargo reads: the manifests, the crates, the task crate the
  # manifests name, and the WIT the crates generate bindings from. Outputs and
  # the Finder's litter are left out even there, since either would move the
  # hash as surely as a source would.
  src = builtins.path {
    name = "enclavid-src";
    path = ../..;
    filter = path: type:
      let
        top = builtins.head (lib.splitString "/" (lib.removePrefix (toString ../.. + "/") (toString path)));
        base = baseNameOf path;
      in
      builtins.elem top [ "Cargo.toml" "Cargo.lock" "crates" "xtask" "wit" ]
      && !(base == "target" || base == "node_modules" || base == ".DS_Store");
  };

  # A seed that is the same for every build, in place of the hook's, set in a
  # build phase once the hook has run. In place of, not after: the compiler
  # takes the last seed it is given, but writes every flag it was given into
  # each object's debug information, so a hook seed left in the line would still
  # carry the output path into the binary.
  fixedSeed = ''
    seeded=()
    for flag in ''${NIX_CFLAGS_COMPILE:-}; do
      case $flag in -frandom-seed=*) ;; *) seeded+=("$flag") ;; esac
    done
    export NIX_CFLAGS_COMPILE="''${seeded[*]} -frandom-seed=enclavid"
  '';
}
