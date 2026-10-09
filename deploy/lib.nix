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

  # The program a hatch runs, from `src`'s own tree.
  hatchProgram = src:
    let built = import (within src "image") { inherit idKeys; };
    in (import (within src "deploy/host.nix") { inherit (built) pkgs; }).host-hatch;

  # The directory the hatch `name` runs in as its root. The service manager
  # needs it to exist before the hatch starts, so the fleet declares it.
  hatchRootPath = name: "/var/lib/enclavid/hatch-${name}-root";

  # What the hatch `unit`, built from `src`'s tree, sees of the store: its
  # program's closure and the CA bundle, each bound into its empty root by a
  # drop-in, and nothing else. The list is the closure's own, written when the
  # drop-in is built, so evaluating the fleet builds nothing. Every hatch unit
  # takes one — without it, its root holds no program to run.
  hatchRoot = { unit, src }: pkgs.runCommand "${unit}-root"
    { closure = pkgs.closureInfo { rootPaths = [ (hatchProgram src) pkgs.cacert ]; }; }
    ''
      mkdir -p $out/lib/systemd/system/${unit}.d
      { echo '[Service]'; sed 's/^/BindReadOnlyPaths=/' $closure/store-paths; } \
        >$out/lib/systemd/system/${unit}.d/root.conf
    '';

  # A hatch built from `src`'s own tree, listening on `port`, checking
  # consumers' tokens, and how often each asks, as `settings` —
  # `enclavid.hatch` — says. It keeps nothing
  # it could not fetch again, so it is started again however often it ends.
  hatchService = { name, port, src, settings }: {
    description = "Enclavid hatch ${name}: what the guests reach outside";
    wantedBy = [ "enclavid-host.target" ];
    partOf = [ "enclavid-host.target" ];
    enableDefaultPath = false;
    startLimitIntervalSec = 0;
    environment = {
      HATCH_LISTEN_ADDR = toString port;
      # The registry client checks servers against the system's CA bundle,
      # and the host's own is out of its sight: this one, which hatchRoot
      # binds in.
      SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    } // lib.mapAttrs (_: toString) (lib.filterAttrs (_: n: n != null) {
      HATCH_SESSION_CREATE_PER_MINUTE = settings.perMinute.sessionCreate;
      HATCH_SESSION_READ_PER_MINUTE = settings.perMinute.sessionRead;
      HATCH_DATA_READ_PER_MINUTE = settings.perMinute.dataRead;
    }) // (
      if settings.auth == "oidc" then {
        HATCH_AUTH = "oidc";
        HATCH_AUTH_OIDC_ISSUER = settings.issuer;
        HATCH_AUTH_OIDC_AUDIENCE = settings.audience;
        HATCH_AUTH_OIDC_PRINCIPAL_CLAIM = settings.principalClaim;
      } else {
        HATCH_AUTH = "none";
        HATCH_AUTH_PRINCIPAL = settings.principal;
      }
    );
    serviceConfig = {
      Type = "exec";
      ExecStart = lib.getExe' (hatchProgram src) "host-hatch";
      Restart = "on-failure";
      RestartSec = 1;
      StandardInput = "null";
      # Nothing of the host beyond what a hatch uses: a user of its own, no
      # privilege, and no way to gain one or to leave its namespaces; sockets
      # of the three families it opens and no other, so no unix or netlink
      # socket of anything here; and of the host's files only those it reads,
      # read-only — its program's closure, the CA bundle, its resolver's — in
      # a root that holds nothing else, so whatever the host keeps, now or
      # later, is not there for it.
      DynamicUser = true;
      CapabilityBoundingSet = "";
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_VSOCK" ];
      # The families are checked on the native socket call, which the 32-bit
      # one and io_uring would go round: neither is left to it.
      SystemCallArchitectures = "native";
      SystemCallFilter = [ "@system-service" "~@privileged @resources @aio" ];
      SystemCallErrorNumber = "EPERM";
      RestrictNamespaces = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      RestrictRealtime = true;
      PrivateDevices = true;
      PrivateIPC = true;
      ProtectHome = true;
      ProtectHostname = true;
      ProtectClock = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectProc = "invisible";
      ProcSubset = "pid";
      # Its root: a directory of its own on the host, holding nothing but the
      # mount points the service manager makes there, under a tmpfs that hides
      # even those from the hatch. Not a copy made for each run
      # (`RootEphemeral=`): the service manager deletes that under a running
      # service on any daemon-reload, and every file the hatch opens after it
      # is missing. Nor a directory in the store, where those mount points
      # would be left behind. And not the tmpfs alone: `DynamicUser=` brings
      # `ProtectSystem=strict`, whose read-only view of the host's whole `/`
      # takes the tmpfs's place unless a root of its own is given.
      RootDirectory = hatchRootPath name;
      TemporaryFileSystem = "/:ro";
      MountAPIVFS = true;
      BindReadOnlyPaths = [ "/etc/resolv.conf" ];
      # What a consumer names is fetched by the hatch itself, never through a
      # proxy the service manager's environment might name.
      UnsetEnvironment = [ "HTTP_PROXY" "http_proxy" "HTTPS_PROXY" "https_proxy" "ALL_PROXY" "all_proxy" "NO_PROXY" "no_proxy" ];
      # Four pulls at once, each a manifest of at most 256 KiB or a blob passed
      # through a piece at a time, beside a hatch at rest of some 50 MiB, with
      # room besides: past it, the hatch alone is stopped and started again,
      # never a guest beside it.
      MemoryMax = "1G";
    };
  };
}
