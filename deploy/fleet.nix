# The fleet as a system-manager module: every guest, the host side they reach,
# and the gateway's configuration. Everything has a default for one host except
# what only its operator can know — the public names, and how consumers' tokens
# are checked. See example.nix.
{ config, lib, pkgs, image, host, ... }:
let
  cfg = config.enclavid;
  inherit (lib) mkOption types;

  suffix = if cfg.variant == "debug" then "-debug" else "";
  imageOf = role: image.images."${role}${suffix}";
  cid = role: toString cfg.cvms.${role}.cid;

  # One guest's settings, each defaulting to what that role needs.
  cvm = role: defaults: mkOption {
    description = "The ${role} guest.";
    default = { };
    type = types.submodule {
      options = {
        cid = mkOption {
          type = types.ints.between 3 4294967294;
          default = defaults.cid;
          description = "Its vsock context ID, unique on the host.";
        };
        memory = mkOption {
          # With its unit: the same string sizes the memory backend, where a
          # bare number is bytes rather than -m's MiB.
          type = types.strMatching "[1-9][0-9]*[MG]";
          default = defaults.memory;
          description = "Its memory, in MiB or GiB with the unit: 3072M, 3G.";
        };
      } // lib.optionalAttrs (defaults ? disk) {
        disk = {
          path = mkOption {
            type = types.str;
            default = defaults.disk.path;
            description = "The file its data volume lives in, made at its first start.";
          };
          size = mkOption {
            type = types.str;
            default = defaults.disk.size;
            description = "How large to make that file; read only when it is made.";
          };
        };
      };
    };
  };

  # The ports the guests listen on, and the hatch's that api dials, are on their
  # measured command lines. Each is written here once, in the relay that reaches
  # it, and the settings below that a command line must carry are made from
  # these relays and checked against those lines — so a change to one that the
  # other misses fails the build instead of carrying nothing. The ports api's
  # fleet legs dial are not on its command line: they are handed to it at
  # launch, from these same relays.
  relays = {
    api-storage = { listen = "vsock:8001"; to = "vsock:${cid "storage"}:8001"; };
    api-compile = { listen = "vsock:8002"; to = "vsock:${cid "compile-worker"}:8002"; };
    api-exec = { listen = "vsock:8003"; to = "vsock:${cid "execution-worker"}:8003"; };
    gateway-api = { listen = "vsock:9443"; to = "vsock:${cid "api"}:8443"; };
    gateway-applicant = { listen = "vsock:9444"; to = "vsock:${cid "api"}:8444"; };
    public = {
      inherit (cfg.public) listen;
      to = "vsock:${cid "gateway"}:8446";
      flags = lib.optional cfg.public.proxyHeader "--proxy-protocol";
    };
    api-health = { listen = "tcp:127.0.0.1:18445"; to = "vsock:${cid "api"}:8445"; };
    gateway-health = { listen = "tcp:127.0.0.1:18447"; to = "vsock:${cid "gateway"}:8447"; };
    gateway-config = { listen = "tcp:127.0.0.1:18448"; to = "vsock:${cid "gateway"}:8448"; };
  } // lib.optionalAttrs (acme != null) {
    # The gateway carries a validator's connection to this port, and the relay
    # on to the host's ACME client.
    acme = { listen = "vsock:${toString acme.port}"; to = acme.client; };
  };
  acme = cfg.acme.tls-alpn-01;
  # The hatch listens on the host itself, so it has no relay; api dials it here.
  hatchPort = "8000";
  # The guest's own port a relay reaches: the last field of its `to`.
  into = relay: lib.last (lib.splitString ":" relays.${relay}.to);
  carried = {
    api = [
      "ENCLAVID_ADDRESS_OUT=vsock://2:${hatchPort}"
      "ENCLAVID_ADDRESS_IN_CLIENT=${into "gateway-api"}"
      "ENCLAVID_ADDRESS_IN_APPLICANT=${into "gateway-applicant"}"
      "ENCLAVID_ADDRESS_IN_HEALTH=${into "api-health"}"
    ];
    storage = [ "ENCLAVID_STORAGE_LISTEN=${into "api-storage"}" ];
    compile-worker = [ "ENCLAVID_COMPILE_WORKER_LISTEN=${into "api-compile"}" ];
    execution-worker = [ "ENCLAVID_EXECUTION_WORKER_LISTEN=${into "api-exec"}" ];
    gateway = [
      "ENCLAVID_ADDRESS_IN_PUBLIC=${into "public"}"
      "ENCLAVID_ADDRESS_IN_HEALTH=${into "gateway-health"}"
      "ENCLAVID_ADDRESS_IN_CONFIG=${into "gateway-config"}"
    ];
  };
  # A command line as the words the kernel splits it into, so a setting is
  # matched whole: 8001 is not found inside 80011.
  cmdline = role: lib.filter (word: word != "")
    (lib.splitString " " (lib.removeSuffix "\n" (builtins.readFile (../image/cmdline + "/${role}/${cfg.variant}"))));

  # What api's legs dial: the port each of their relays listens on, as fw_cfg
  # entries (crates/api/src/fleet/legs.rs), so a relay and the dial that reaches it
  # are one definition.
  legPorts = lib.concatStringsSep " " (lib.mapAttrsToList
    (name: relay: "${name}-port=${lib.removePrefix "vsock:" relays.${relay}.listen}")
    {
      storage = "api-storage";
      compile-worker = "api-compile";
      execution-worker = "api-exec";
    });

  # The gateway's table: one group running this commit's api, reached under
  # both names; a request that creates a session is placed by the gateway, and
  # every other names the group its link carries.
  named = [
    { path = "/"; flags = [ "require_named_group" ]; }
    { path = "/{*rest}"; flags = [ "require_named_group" ]; }
  ];
  table = {
    groups.main.measurement = "";
    names = {
      ${cfg.names.verify}.main = [ "vsock://2:9444" ];
      ${cfg.names.api}.main = [ "vsock://2:9443" ];
    };
    routes = {
      ${cfg.names.api} = [
        { method = "POST"; path = "/api/v1/sessions"; flags = [ "reject_named_group" ]; }
      ] ++ named;
      ${cfg.names.verify} = named;
    };
  } // lib.optionalAttrs (acme != null) {
    acme.tls-alpn-01 = "vsock://2:${toString acme.port}";
  };
  gatewayJson = pkgs.runCommand "enclavid-gateway.json" { nativeBuildInputs = [ pkgs.jq ]; } ''
    jq --rawfile m ${image.measurements."api${suffix}"} '.groups.main.measurement = $m' \
      ${pkgs.writeText "enclavid-table.json" (builtins.toJSON table)} >$out
    jq -e '.groups.main.measurement | test("^[0-9a-f]{96}$")' $out >/dev/null
  '';

  bootCvm = pkgs.writeShellApplication {
    name = "enclavid-boot-cvm";
    runtimeInputs = [ pkgs.coreutils pkgs.e2fsprogs ];
    text = "QEMU=${lib.escapeShellArg cfg.qemu}\n" + builtins.readFile ./bin/boot-cvm.sh;
  };
  pushGateway = pkgs.writeShellApplication {
    name = "enclavid-push-gateway";
    runtimeInputs = [ pkgs.coreutils pkgs.curl pkgs.jq ];
    text = builtins.readFile ./bin/push-gateway.sh;
  };

  issue = cfg.acme.issue;
  certificate = pkgs.writeShellApplication {
    name = "enclavid-certificate";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.curl
      pkgs.findutils
      pkgs.gnugrep
      pkgs.lego
      pkgs.openssl
      pushGateway
    ];
    text = ''
      NAMES=(${lib.escapeShellArgs [ cfg.names.verify cfg.names.api ]})
      RENEW_DAYS=${toString issue.renewDays}
      EMAIL=${lib.escapeShellArg issue.email}
      SERVER=${lib.escapeShellArg issue.server}
      CA_BUNDLE=${lib.escapeShellArg (if issue.caBundle == null then "" else issue.caBundle)}
      LISTEN=${lib.escapeShellArg (lib.removePrefix "tcp:" acme.client)}
    '' + builtins.readFile ./bin/certificate.sh;
  };

  cvmService = role: c: {
    description = "Enclavid confidential VM: ${role}";
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
    environment = lib.optionalAttrs (role == "api") { FW_CFG = legPorts; };
    serviceConfig = {
      Type = "exec";
      ExecStart = lib.concatStringsSep " " (
        [ (lib.getExe bootCvm) role "${imageOf role}" (toString c.cid) c.memory ]
        ++ lib.optionals (c ? disk) [ c.disk.path c.disk.size ]
      );
      Restart = "always";
      RestartSec = 2;
      TimeoutStartSec = 120;
      TimeoutStopSec = 10;
      StandardInput = "null";
      LogsDirectory = "enclavid";
      StateDirectory = "enclavid";
    };
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

  hatchEnvironment = { HATCH_LISTEN_ADDR = hatchPort; } // (
    if cfg.hatch.auth == "oidc" then {
      HATCH_AUTH = "oidc";
      HATCH_AUTH_OIDC_ISSUER = cfg.hatch.issuer;
      HATCH_AUTH_OIDC_AUDIENCE = cfg.hatch.audience;
    } else {
      HATCH_AUTH = "none";
      HATCH_AUTH_PRINCIPAL = cfg.hatch.principal;
    }
  );
in
{
  options.enclavid = {
    names = {
      verify = mkOption {
        type = types.str;
        example = "verify.example.com";
        description = "The name applicants are sent to.";
      };
      api = mkOption {
        type = types.str;
        example = "api.example.com";
        description = "The name consumers call.";
      };
    };
    hatch = {
      auth = mkOption {
        type = types.enum [ "oidc" "none" ];
        description = ''
          How consumers' tokens are checked: against an OIDC issuer, or not at
          all, with every request taken to be `principal` — for development only.
        '';
      };
      issuer = mkOption { type = types.nullOr types.str; default = null; };
      audience = mkOption { type = types.nullOr types.str; default = null; };
      principal = mkOption { type = types.nullOr types.str; default = null; };
    };
    variant = mkOption {
      type = types.enum [ "production" "debug" ];
      default = "production";
      description = ''
        Which images. Every guest writes what it logs to its serial console,
        /var/log/enclavid/ROLE.serial; debug ones add the kernel's console and
        what their dependencies log.
      '';
    };
    public = {
      listen = mkOption {
        type = types.str;
        default = "tcp:0.0.0.0:443";
        description = "Where callers reach the gateway.";
      };
      proxyHeader = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether the relay writes the PROXY header naming each caller. The
          gateway requires one, so turn this off only behind a front that writes
          its own — and then make sure nothing else reaches the relay.
        '';
      };
    };
    acme.issue = {
      enable = lib.mkEnableOption ''
        issuing and renewing the gateway's certificate from an ACME certificate
        authority, validated over TLS-ALPN-01 through the gateway. The
        certificate is checked daily and after every start of the gateway, and
        issued again when it lapses within `renewDays`, is for another key than
        the gateway's, or does not cover both names
      '';
      email = mkOption {
        type = types.str;
        description = "The ACME account's contact.";
      };
      server = mkOption {
        type = types.str;
        default = "https://acme-v02.api.letsencrypt.org/directory";
        example = "https://acme-staging-v02.api.letsencrypt.org/directory";
        description = "The ACME directory the certificate is issued from.";
      };
      caBundle = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "A file of CA certificates the ACME server's own TLS is checked against — for a private ACME server.";
      };
      renewDays = mkOption {
        type = types.ints.positive;
        default = 30;
        description = "Issue again once fewer days than this remain.";
      };
    };
    acme.tls-alpn-01 = mkOption {
      default = null;
      description = ''
        The host's ACME client, when it validates the names over TLS-ALPN-01:
        the gateway carries a validator's connection to it, and it answers.
        Set by `acme.issue` to the client it runs; unset otherwise, and then
        such a connection is refused.
      '';
      type = types.nullOr (types.submodule {
        options = {
          client = mkOption {
            type = types.str;
            example = "tcp:127.0.0.1:444";
            description = "Where the ACME client listens for the validator, as host-relay names it.";
          };
          port = mkOption {
            type = types.port;
            default = 444;
            description = "The vsock port on the host the gateway carries the connection to.";
          };
        };
      });
    };
    startAtBoot = mkOption {
      type = types.bool;
      default = true;
      description = "Whether the fleet comes up when the host boots.";
    };
    qemu = mkOption {
      type = types.str;
      default = lib.getExe' pkgs.qemu_kvm "qemu-system-x86_64";
      defaultText = "qemu-system-x86_64 from the images' package set";
      description = "The QEMU the guests boot under; it has to run SEV-SNP guests.";
    };
    cvms = {
      storage = cvm "storage" {
        cid = 4;
        memory = "2G";
        disk = { path = "/var/lib/enclavid/storage.img"; size = "8G"; };
      };
      compile-worker = cvm "compile-worker" { cid = 6; memory = "3G"; };
      execution-worker = cvm "execution-worker" { cid = 5; memory = "3G"; };
      api = cvm "api" { cid = 3; memory = "3G"; };
      gateway = cvm "gateway" { cid = 7; memory = "2G"; };
    };
    health = mkOption {
      type = types.listOf types.str;
      internal = true;
      readOnly = true;
      description = "Where each guest that has one answers its health, as HOST:PORT on the host.";
    };
    units = mkOption {
      type = types.listOf types.str;
      internal = true;
      readOnly = true;
      description = "The units meant to stay up once the fleet is: every one but the certificate run.";
    };
  };

  config = {
    nixpkgs.hostPlatform = "x86_64-linux";

    enclavid.health = map (relay: lib.removePrefix "tcp:" relays.${relay}.listen) [
      "api-health"
      "gateway-health"
    ];
    enclavid.units =
      map (role: "enclavid-${role}.service") (lib.attrNames cfg.cvms)
      ++ map (name: "enclavid-relay-${name}.service") (lib.attrNames relays)
      ++ [ "enclavid-hatch.service" "enclavid-gateway-push.service" ];

    # system-manager would otherwise take over /etc/passwd and /etc/group.
    services.userborn.enable = false;

    # The device every guest is reached through, at every boot.
    environment.etc."modules-load.d/enclavid.conf".text = "vhost_vsock\n";

    # The ACME client `acme.issue` runs listens here, for the gateway to carry
    # validators to.
    enclavid.acme.tls-alpn-01 = lib.mkIf issue.enable (lib.mkDefault { client = "tcp:127.0.0.1:444"; });

    assertions =
      lib.concatLists (lib.mapAttrsToList
        (role: settings: map
          (setting: {
            assertion = lib.elem setting (cmdline role);
            message = "enclavid: image/cmdline/${role}/${cfg.variant} no longer carries ${setting}";
          })
          settings)
        carried)
      ++ [
        {
          assertion = cfg.hatch.auth != "oidc" || (cfg.hatch.issuer != null && cfg.hatch.audience != null);
          message = "enclavid.hatch: auth = \"oidc\" needs issuer and audience";
        }
        {
          assertion = cfg.hatch.auth != "none" || cfg.hatch.principal != null;
          message = "enclavid.hatch: auth = \"none\" needs principal";
        }
        {
          assertion = lib.allUnique (lib.mapAttrsToList (_: c: c.cid) cfg.cvms);
          message = "enclavid.cvms: every guest needs a vsock context ID of its own";
        }
        {
          assertion = !issue.enable || (acme != null && lib.hasPrefix "tcp:" acme.client);
          message = "enclavid.acme.issue: its ACME client listens on TCP, so acme.tls-alpn-01.client is a tcp: address";
        }
      ];

    systemd.services = lib.mkMerge [
      (lib.mapAttrs' (role: c: lib.nameValuePair "enclavid-${role}" (cvmService role c)) cfg.cvms)
      (lib.mapAttrs' (name: r: lib.nameValuePair "enclavid-relay-${name}" (relayService name r)) relays)
      {
        # The gateway keeps no configuration across a start: while it is up, its
        # table is pushed — again after every start, since the push is bound to
        # it; and when only the table changes, only the push runs again.
        enclavid-gateway.unitConfig.Upholds = "enclavid-gateway-push.service";
        enclavid-gateway-push = {
          description = "Enclavid: push the gateway its configuration";
          bindsTo = [ "enclavid-gateway.service" ];
          after = [ "enclavid-gateway.service" ];
          enableDefaultPath = false;
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${lib.getExe pushGateway} ${gatewayJson}";
            TimeoutStartSec = 150;
          };
        };

        # After every push — so after every start of the gateway, whose key a
        # new build changes — and daily, by its timer. The relay that carries a
        # validator to the ACME client is its own to start: a push can run it
        # before the switch has started a relay new to this generation.
        enclavid-certificate = lib.mkIf issue.enable {
          description = "Enclavid: keep the gateway on an issued certificate";
          wantedBy = [ "enclavid-gateway-push.service" ];
          wants = [ "enclavid-relay-acme.service" ];
          after = [ "enclavid-gateway-push.service" "enclavid-relay-acme.service" ];
          enableDefaultPath = false;
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${lib.getExe certificate} ${gatewayJson}";
            StateDirectory = [ "enclavid/acme" "enclavid/certificates" ];
            StateDirectoryMode = "0700";
            TimeoutStartSec = 600;
          };
        };

        enclavid-hatch = {
          description = "Enclavid hatch: what the guests reach outside";
          wantedBy = [ "enclavid-host.target" ];
          partOf = [ "enclavid-host.target" ];
          enableDefaultPath = false;
          environment = hatchEnvironment;
          serviceConfig = {
            Type = "exec";
            ExecStart = lib.getExe' host.host-hatch "host-hatch";
            Restart = "on-failure";
            RestartSec = 1;
            StandardInput = "null";
          };
        };
      }
    ];

    systemd.timers.enclavid-certificate = lib.mkIf issue.enable {
      description = "Enclavid: check the gateway's certificate daily";
      wantedBy = [ "enclavid-fleet.target" ];
      partOf = [ "enclavid-fleet.target" ];
      timerConfig = {
        OnCalendar = "daily";
        RandomizedDelaySec = "1h";
        Persistent = true;
      };
    };

    # Members join a target through their own `wantedBy`, so a target's text
    # does not change when the fleet does — and a target is never restarted
    # under the units that are part of it.
    systemd.targets = {
      enclavid-host.description = "Enclavid host side: the relays and the hatch";
      enclavid-fleet = {
        description = "Enclavid fleet: the confidential VMs, and the host side they reach";
        wants = [ "enclavid-host.target" ];
        after = [ "enclavid-host.target" ];
        wantedBy = lib.optional cfg.startAtBoot "system-manager.target";
      };
    };
  };
}
