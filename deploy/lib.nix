# The blocks a fleet is assembled from, given to every module as `fleet` — so a
# module beside fleet.nix builds on them rather than copying them.
{ lib, pkgs, idKeys, host }:
rec {
  # A release's guest's vsock context ID, from the release's index: 3 + 10 ×
  # index onward, so a release's guests take 3 to 6 and 8 of every ten — a
  # gateway's is the 7 between. Index 0 has the numbers a single release has
  # always had.
  cidOf = r: role: toString (r.index * 10 + {
    api = 3;
    storage = 4;
    execution-worker = 5;
    compile-worker = 6;
    hatch = 8;
  }.${role});

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

  # The NTS servers a tree's guests keep their clocks by, each a port and a
  # name, as its crates/timesync/servers lists them. A tree from before the
  # list has guests that dial none.
  timeServers = src:
    let file = within src "crates/timesync/servers";
    in lib.optionals (builtins.pathExists file) (map
      (line: { port = lib.elemAt (words line) 0; name = lib.elemAt (words line) 1; })
      (lib.filter (line: words line != [ ] && !lib.hasPrefix "#" line)
        (lib.splitString "\n" (builtins.readFile file))));

  # One launcher per QEMU, since a release boots under the QEMU its
  # measurements were computed for.
  bootCvm = qemu: pkgs.writeShellApplication {
    name = "enclavid-boot-cvm";
    runtimeInputs = [ pkgs.coreutils pkgs.e2fsprogs ];
    text = "QEMU=${lib.escapeShellArg qemu}\n" + builtins.readFile ./bin/boot-cvm.sh;
  };

  # A guest's unit. `files` are fw_cfg entries read from a file as it boots,
  # by name; `nic` the socket its network interface is carried over, for the
  # one role that has one; `needs` the units it starts after and pulls in —
  # without taking a restart of one as a reason to restart.
  cvmService = { name, image, qemu, cid, memory, disk ? null, environment ? { }, files ? { }, nic ? null, needs ? [ ] }: {
    description = "Enclavid confidential VM: ${name}";
    wantedBy = [ "enclavid-fleet.target" ];
    partOf = [ "enclavid-fleet.target" ];
    after = [ "enclavid-host.target" ] ++ needs;
    wants = needs;
    enableDefaultPath = false;
    # A guest that cannot come up is tried five times, then left failed for a
    # person to look at rather than rebooted for ever. Its application ending
    # powers the guest off, and QEMU exits 0 for that as for any shutdown — so
    # every exit is a failure here, and only a stop is not.
    startLimitIntervalSec = 300;
    startLimitBurst = 5;
    environment = environment // lib.optionalAttrs (files != { }) {
      FW_CFG_FILES = lib.concatStringsSep " " (lib.mapAttrsToList (entry: path: "${entry}=${path}") files);
    } // lib.optionalAttrs (nic != null) { NIC = nic; };
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

  # Started again however often it ends: a relay to a public name — an NTS
  # server's — resolves it as it starts, and fails for as long as the host's
  # resolver is not up yet. With the default limit on starts, a few such
  # failures in a row would leave it stopped for good.
  relayService = name: r: {
    description = "Enclavid host relay: ${name}";
    wantedBy = [ "enclavid-host.target" ];
    partOf = [ "enclavid-host.target" ];
    enableDefaultPath = false;
    startLimitIntervalSec = 0;
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
    } // lib.optionalAttrs (r.unprivileged or false) {
      # A relay that listens on a vsock port above the reserved ones and dials
      # out needs nothing of root's, and one every guest here reaches should
      # hold nothing a guest could turn: a user of its own, no capability, no
      # way to gain one, and a bound on the memory its callers can make it hold.
      DynamicUser = true;
      CapabilityBoundingSet = "";
      NoNewPrivileges = true;
      MemoryMax = "256M";
    };
  };

  # Where the host keeps the certificate AMD issues its chip — the one api is
  # given at launch — and the unit keeping it there: see bin/vcek.sh.
  vcekPath = "/var/lib/enclavid/vcek/vcek.der";
  vcekService = {
    description = "Enclavid: keep the certificate AMD issues this chip";
    wantedBy = [ "enclavid-host.target" ];
    partOf = [ "enclavid-host.target" ];
    before = [ "enclavid-host.target" ];
    enableDefaultPath = false;
    # The certificate's own roots, not whatever the host's are.
    environment.SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = lib.getExe (pkgs.writeShellApplication {
        name = "enclavid-vcek";
        runtimeInputs = [ pkgs.coreutils pkgs.curl pkgs.openssl pkgs.snphost ];
        text = builtins.readFile ./bin/vcek.sh;
      });
      # Five tries at AMD of half a minute each, and the waits between.
      TimeoutStartSec = 300;
      StateDirectory = "enclavid/vcek";
      # Root for /dev/sev, which names the chip and its TCB, and nothing of the
      # host's but that and its own directory to write.
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      NoNewPrivileges = true;
    };
  };

  # Where the network interface of the hatch guest `name` is carried, and the
  # unit carrying it: a passt, which opens on this host's network the
  # connections the guest opens — TCP and UDP over IPv4 — and takes none in.
  # The guest is 10.0.2.15, its gateway 10.0.2.2, and neither address is
  # mapped to anything of this host: the host's loopback is out of the guest's
  # reach, but for a resolver. The guest asks 10.0.2.3 for names, whatever
  # answers: passt carries what it sends there on ports 53 and 853, and nothing
  # else, to `nameserver`, or, where null, to this host's own resolver — the
  # first in its /etc/resolv.conf, loopback or not, which passt reads as it
  # starts only when told no resolver to hand out itself. So the guest's
  # resolver is the same address whatever network its passt is on, and a passt
  # started again on another one resolves through that one at once.
  netSocket = name: "/run/enclavid-${name}-net/sock";
  netService = { name, nameserver }: {
    description = "Enclavid: the network of the hatch ${name}";
    wantedBy = [ "enclavid-host.target" ];
    partOf = [ "enclavid-host.target" ];
    enableDefaultPath = false;
    startLimitIntervalSec = 0;
    serviceConfig = {
      Type = "exec";
      ExecStart = lib.concatStringsSep " " ([
        (lib.getExe' pkgs.passt "passt")
        "--foreground"
        "--quiet"
        "--socket"
        (netSocket name)
        "--ipv4-only"
        "--no-icmp"
        "--tcp-ports"
        "none"
        "--udp-ports"
        "none"
        "--address"
        "10.0.2.15"
        "--netmask"
        "24"
        "--gateway"
        "10.0.2.2"
        "--map-host-loopback"
        "none"
        "--map-guest-addr"
        "none"
        "--search"
        "none"
        "--dns-forward"
        "10.0.2.3"
      ] ++ lib.optionals (nameserver != null) [ "--dns" "10.0.2.3" "--dns-host" nameserver ]);
      # The guest reconnects to a passt started again, at the same addresses.
      Restart = "always";
      RestartSec = 1;
      StandardInput = "null";
      # A user of its own, given the one capability passt's own sandbox needs
      # on a host that keeps unprivileged users from making user namespaces; it
      # drops that, and every other, once the sandbox is made.
      DynamicUser = true;
      AmbientCapabilities = "CAP_SYS_ADMIN";
      CapabilityBoundingSet = "CAP_SYS_ADMIN";
      RuntimeDirectory = "enclavid-${name}-net";
      # And bounds of its own beside passt's: sockets of the families it opens
      # and no other — no vsock, which no network namespace holds, so a passt
      # turned by what it carries reaches no guest and no relay — no privilege
      # to gain, nothing of the kernel's to change, and memory past which only
      # it is stopped. Its sandbox, which makes namespaces of its own, is left to
      # it.
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
      NoNewPrivileges = true;
      SystemCallArchitectures = "native";
      LockPersonality = true;
      PrivateDevices = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      MemoryMax = "256M";
    };
  };
}
