# The whole fleet on one AMD SEV-SNP host — every guest, the host side they
# reach, and the gateway's configuration — built from this commit and put in
# place as systemd units by system-manager. A minimal starting point, with
# defaults for one host: see README.md.
#
#   nix-build deploy --arg idKeys /path/to/keys --arg configuration ./fleet.nix
#   sudo ./result/bin/enclavid-switch
{ idKeys, configuration }:
let
  image = import ../image { inherit idKeys; };
  inherit (image) pkgs;
  host = import ./host.nix { inherit pkgs; };

  # system-manager, on its branch that tracks the images' nixpkgs release.
  system-manager = builtins.fetchTarball {
    url = "https://github.com/numtide/system-manager/archive/185062bb39493a74599bb3cf7731ee0614cade9b.tar.gz";
    sha256 = "13j0102wh7h9way5lprfz5209xli88jaa4544ky9l6hgqncw6ysh";
  };
  systemManager = import "${system-manager}/nix/lib.nix" {
    nixpkgs = pkgs.path;
    # Its user management is switched off in fleet.nix, but the package it would
    # run is still named, so the one from the same package set is given.
    userborn.packages.${pkgs.stdenv.hostPlatform.system}.default = pkgs.userborn;
  };
  toplevel = systemManager.makeSystemConfig {
    modules = [ ./fleet.nix configuration ];
    specialArgs = {
      inherit host;
      fleet = import ./lib.nix { inherit lib pkgs idKeys host; };
    };
  };
  cfg = toplevel.config.enclavid;
  inherit (pkgs) lib;

  preflight = pkgs.writeShellApplication {
    name = "enclavid-preflight";
    runtimeInputs = [ pkgs.coreutils pkgs.gawk pkgs.gnugrep pkgs.iproute2 ];
    text = ''
      QEMUS=(${lib.escapeShellArgs cfg.qemus})
      MEMORY=(${lib.escapeShellArgs cfg.memory})
      LISTENS=(${lib.escapeShellArgs (lib.mapAttrsToList (_: g: g.listen) cfg.gateways)})
    '' + builtins.readFile ./bin/preflight.sh;
  };
  switch = pkgs.writeShellApplication {
    name = "enclavid-switch";
    runtimeInputs = [ pkgs.bash pkgs.coreutils pkgs.gawk pkgs.gnugrep ];
    text = ''
      TOPLEVEL=${toplevel}
      PREFLIGHT=${lib.getExe preflight}
      HEALTH=(${lib.escapeShellArgs cfg.health})
      UNITS=(${lib.escapeShellArgs cfg.units})
    '' + builtins.readFile ./bin/switch.sh;
  };
in
pkgs.symlinkJoin {
  name = "enclavid-fleet";
  paths = [ switch preflight ];
} // { inherit toplevel; }
