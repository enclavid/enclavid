# The blocks a fleet is assembled from, given to every module as `fleet` — so a
# module beside fleet.nix builds on them rather than copying them.
{ lib, pkgs, idKeys, host }:
rec {
  # The port on the host the fleet's own hatch listens on.
  hatchPort = 8000;

  # A command line as the words the kernel splits it into, so a setting is
  # matched whole: 8001 is not found inside 80011.
  words = text: lib.filter (word: word != "") (lib.splitString " " (lib.removeSuffix "\n" text));

  # A path inside an enclavid tree: this checkout, or a fetched one.
  within = src: sub: if builtins.isPath src then src + "/${sub}" else "${src}/${sub}";

  # A release, from its tree: its images and their measurements, the command
  # lines they were measured with, and the QEMU they were measured for.
  # Everything comes from the tree itself, so a release rebuilt from its commit
  # is the one already running.
  release = variant: src:
    let
      built = import (within src "image") { inherit idKeys; };
      suffix = if variant == "debug" then "-debug" else "";
    in
    {
      image = role: built.images."${role}${suffix}";
      measurement = role: built.measurements."${role}${suffix}";
      cmdline = role: words (builtins.readFile (within src "image/cmdline/${role}/${variant}"));
      qemu = lib.getExe' built.pkgs.qemu_kvm "qemu-system-x86_64";
    };

  # One launcher per QEMU, since a release boots under the QEMU its
  # measurements were computed for.
  bootCvm = qemu: pkgs.writeShellApplication {
    name = "enclavid-boot-cvm";
    runtimeInputs = [ pkgs.coreutils pkgs.e2fsprogs ];
    text = "QEMU=${lib.escapeShellArg qemu}\n" + builtins.readFile ./bin/boot-cvm.sh;
  };

  cvmService = { name, image, qemu, cid, memory, disk ? null, environment ? { } }: {
    description = "Enclavid confidential VM: ${name}";
    wantedBy = [ "enclavid-fleet.target" ];
    partOf = [ "enclavid-fleet.target" ];
    after = [ "enclavid-host.target" ];
    enableDefaultPath = false;
    # A guest that cannot come up is tried five times, then left failed for a
    # person to look at rather than rebooted for ever. Its application ending
    # powers the guest off, and QEMU exits 0 for that as for any shutdown — so
    # every exit is a failure here, and only a stop is not.
    startLimitIntervalSec = 300;
    startLimitBurst = 5;
    inherit environment;
    serviceConfig = {
      Type = "exec";
      ExecStart = lib.concatStringsSep " " (
        [ (lib.getExe (bootCvm qemu)) name "${image}" cid memory ]
        ++ lib.optionals (disk != null) [ disk.path disk.size ]
      );
      Restart = "always";
      RestartSec = 2;
      TimeoutStartSec = 120;
      TimeoutStopSec = 10;
      StandardInput = "null";
      LogsDirectory = "enclavid";
      StateDirectory = [ "enclavid" ] ++ lib.optional (disk != null) disk.state;
    };
  };

  # Where the host reaches a gateway's configuration port, as HOST:PORT, by the
  # gateway's index: where its table is pushed and its requests to an ACME
  # issuer are signed.
  gatewayConfig = index: "127.0.0.1:${toString (18448 + 100 * index)}";

  # Pushes a gateway, at the configuration port given, its table and the issued
  # certificates on disk for the key it serves on.
  pushGateway = pkgs.writeShellApplication {
    name = "enclavid-push-gateway";
    runtimeInputs = [ pkgs.coreutils pkgs.curl pkgs.jq pkgs.openssl ];
    text = builtins.readFile ./bin/push-gateway.sh;
  };

  # Keeps a gateway on a certificate issued to its own ACME account for
  # `names`, from the directory `issue` — `enclavid.acme.issue` — names. Which
  # gateway, which ones answer the issuer's validation, and where the
  # certificate goes are the run's arguments: see bin/certificate.sh.
  certificate = { names, issue }: pkgs.writeShellApplication {
    name = "enclavid-certificate";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.curl
      pkgs.gnugrep
      pkgs.jq
      pkgs.openssl
      pkgs.util-linux
      pushGateway
    ];
    text = ''
      NAMES=(${lib.escapeShellArgs names})
      RENEW_DAYS=${toString issue.renewDays}
      SERVER=${lib.escapeShellArg issue.server}
      CA_BUNDLE=${lib.escapeShellArg (if issue.caBundle == null then "" else issue.caBundle)}
    '' + builtins.readFile ./bin/certificate.sh;
  };

  relayService = name: r: {
    description = "Enclavid host relay: ${name}";
    wantedBy = [ "enclavid-host.target" ];
    partOf = [ "enclavid-host.target" ];
    enableDefaultPath = false;
    serviceConfig = {
      Type = "exec";
      ExecStart = lib.concatStringsSep " " (
        [ (lib.getExe' host.host-relay "host-relay") "--listen" r.listen "--to" r.to ]
        ++ (r.flags or [ ])
      );
      Restart = "on-failure";
      RestartSec = 1;
      TimeoutStopSec = 15;
      StandardInput = "null";
    };
  };

  # A hatch built from `src`'s own tree, listening on `port`, checking
  # consumers' tokens as `settings` — `enclavid.hatch` — says.
  hatchService = { name, port, src, settings }:
    let
      built = import (within src "image") { inherit idKeys; };
      hatch = (import (within src "deploy/host.nix") { inherit (built) pkgs; }).host-hatch;
    in
    {
      description = "Enclavid hatch ${name}: what the guests reach outside";
      wantedBy = [ "enclavid-host.target" ];
      partOf = [ "enclavid-host.target" ];
      enableDefaultPath = false;
      environment = { HATCH_LISTEN_ADDR = toString port; } // (
        if settings.auth == "oidc" then {
          HATCH_AUTH = "oidc";
          HATCH_AUTH_OIDC_ISSUER = settings.issuer;
          HATCH_AUTH_OIDC_AUDIENCE = settings.audience;
        } else {
          HATCH_AUTH = "none";
          HATCH_AUTH_PRINCIPAL = settings.principal;
        }
      );
      serviceConfig = {
        Type = "exec";
        ExecStart = lib.getExe' hatch "host-hatch";
        Restart = "on-failure";
        RestartSec = 1;
        StandardInput = "null";
      };
    };
}
