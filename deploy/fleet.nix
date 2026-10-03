# The fleet as a system-manager module: the gateway, the release it serves —
# api and the three guests it reaches, with the host side they all reach — and
# the gateway's configuration. Everything has a default for one host running
# this checkout, except what only its operator can know: the public names, and
# how consumers' tokens are checked. See example.nix.
{ config, lib, pkgs, fleet, ... }:
let
  cfg = config.enclavid;
  inherit (lib) mkOption types;

  releases = lib.mapAttrsToList
    (name: r: r // { inherit name; built = fleet.release cfg.variant r.src; })
    cfg.releases;
  # The releases whose guests run on this host.
  local = lib.filter (r: r.guests) releases;
  gateways = lib.mapAttrsToList
    (name: g: g // { inherit name; built = fleet.release cfg.variant g.src; })
    cfg.gateways;
  gatewayHere = gateways != [ ];
  roles = [ "api" "storage" "compile-worker" "execution-worker" ];

  # Where a release's guests are, from its index: context IDs from 3 + 10 ×
  # index, host ports from their base + 100 × index. Index 0 has the numbers a
  # single release has always had.
  cidOf = r: role: toString (r.index * 10 + {
    api = 3;
    storage = 4;
    execution-worker = 5;
    compile-worker = 6;
  }.${role});
  portOf = r: base: toString (base + 100 * r.index);

  # The ports the guests listen on are on their measured command lines. Each is
  # written here once, in the relay that reaches it — api's two surfaces in
  # `apiPort`, which both ways of reaching them use — and the settings a
  # command line must carry are made from these and checked against the lines,
  # so a change to one that the other misses fails the build instead of
  # carrying nothing. The ports api's legs dial are not on its command line:
  # they are handed to it at launch, from these same relays and its hatch.
  apiPort = { client = "8443"; applicant = "8444"; };
  releaseRelays = r: {
    storage = { listen = "vsock:${portOf r 8001}"; to = "vsock:${cidOf r "storage"}:8001"; };
    compile = { listen = "vsock:${portOf r 8002}"; to = "vsock:${cidOf r "compile-worker"}:8002"; };
    exec = { listen = "vsock:${portOf r 8003}"; to = "vsock:${cidOf r "execution-worker"}:8003"; };
    health = { listen = "tcp:127.0.0.1:${portOf r 18445}"; to = "vsock:${cidOf r "api"}:8445"; };
  } // lib.optionalAttrs (r.entrances != null) {
    # Where a gateway on another host reaches this release's api: over the
    # network, to a relay here, and on into the guest. Nothing is opened on the
    # way — the gateway's leg is RA-TLS to api itself.
    client-entrance = { listen = entrance r 19443; to = "vsock:${cidOf r "api"}:${apiPort.client}"; };
    applicant-entrance = { listen = entrance r 19444; to = "vsock:${cidOf r "api"}:${apiPort.applicant}"; };
  };
  entrance = r: base: "tcp:${r.entrances}:${portOf r base}";
  # How the gateways here reach a release's api: straight into its guest on
  # this host, or to its entrances wherever they are. One relay each, which
  # every gateway dials.
  gatewayToRelease = r: {
    client = {
      listen = "vsock:${portOf r 9443}";
      to = if r.entrances == null then "vsock:${cidOf r "api"}:${apiPort.client}" else entrance r 19443;
    };
    applicant = {
      listen = "vsock:${portOf r 9444}";
      to = if r.entrances == null then "vsock:${cidOf r "api"}:${apiPort.applicant}" else entrance r 19444;
    };
  };
  # Where a gateway is, from its index: the context ID 7 + 10 × index — a
  # release's guests take 3 to 6 of every ten — and host ports as a release's.
  # Its public listener is where it says: the one callers reach is the one
  # serving.
  gatewayCid = g: toString (g.index * 10 + 7);
  gatewayRelays = g: {
    public = {
      inherit (g) listen;
      to = "vsock:${gatewayCid g}:8446";
      flags = lib.optional cfg.public.proxyHeader "--proxy-protocol";
    };
    health = { listen = "tcp:127.0.0.1:${portOf g 18447}"; to = "vsock:${gatewayCid g}:8447"; };
    config = { listen = "tcp:${fleet.gatewayConfig g.index}"; to = "vsock:${gatewayCid g}:8448"; };
  };
  perRelease = relaysOf: rs: lib.listToAttrs (lib.concatMap
    (r: lib.mapAttrsToList (name: relay: lib.nameValuePair "${r.name}-${name}" relay) (relaysOf r))
    rs);
  perGateway = lib.listToAttrs (lib.concatMap
    (g: lib.mapAttrsToList (name: relay: lib.nameValuePair "gateway-${g.name}-${name}" relay) (gatewayRelays g))
    gateways);
  releaseSide = perRelease releaseRelays local
    // lib.optionalAttrs gatewayHere (perRelease gatewayToRelease releases);
  relays = releaseSide // perGateway;
  # A certificate run arms every gateway here, the one listening where callers
  # reach — `public.listen` — above all: the issuer's validator comes to it.
  configs = gs: lib.concatMapStringsSep "," (g: "http://${fleet.gatewayConfig g.index}") gs;
  reached = lib.filter (g: g.listen == cfg.public.listen) gateways;
  unreached = lib.filter (g: g.listen != cfg.public.listen) gateways;
  arming = lib.optionals (reached != [ ]) [ "--reached" (configs reached) ]
    ++ lib.optionals (unreached != [ ]) [ "--also" (configs unreached) ];

  # A hatch's allowance a minute: a count it holds as one, or -1 for none.
  perMinute = types.nullOr (types.either (types.enum [ (-1) ]) (types.ints.between 1 4294967295));

  # The guest's own port a relay reaches: the last field of its `to`.
  into = relay: lib.last (lib.splitString ":" relay.to);
  carried = r: with releaseRelays r; {
    api = [
      "ENCLAVID_ADDRESS_IN_CLIENT=${apiPort.client}"
      "ENCLAVID_ADDRESS_IN_APPLICANT=${apiPort.applicant}"
      "ENCLAVID_ADDRESS_IN_HEALTH=${into health}"
    ];
    storage = [ "ENCLAVID_STORAGE_LISTEN=${into storage}" ];
    compile-worker = [ "ENCLAVID_COMPILE_WORKER_LISTEN=${into compile}" ];
    execution-worker = [ "ENCLAVID_EXECUTION_WORKER_LISTEN=${into exec}" ];
  };
  gatewayCarried = g:
    let relay = gatewayRelays g;
    in [
      "ENCLAVID_ADDRESS_IN_PUBLIC=${into relay.public}"
      "ENCLAVID_ADDRESS_IN_HEALTH=${into relay.health}"
      "ENCLAVID_ADDRESS_IN_CONFIG=${into relay.config}"
    ];

  # What a release's api legs dial: its hatch's port, and the port each peer's
  # relay listens on, as fw_cfg entries (crates/api/src/fleet/legs.rs) — so a
  # relay, or the hatch, and the dial that reaches it are one definition.
  legPorts = r: with releaseRelays r; lib.concatStringsSep " " [
    "hatch-port=${toString r.hatchPort}"
    "storage-port=${lib.removePrefix "vsock:" storage.listen}"
    "compile-worker-port=${lib.removePrefix "vsock:" compile.listen}"
    "execution-worker-port=${lib.removePrefix "vsock:" exec.listen}"
  ];

  # The gateway's table: a group per release, running that release's api and
  # reached under both names. A request that creates a session is placed by
  # the gateway — never on a draining release's build — and every other names
  # the group its link carries. A browser at the bare verify name, which has
  # no link, is sent to `public.landing` if it is set — off the verify origin,
  # which every release's pages share.
  named = [
    { path = "/"; group = "required"; }
    { path = "/{*rest}"; group = "required"; }
  ];
  table = {
    groups = lib.listToAttrs (map (r: lib.nameValuePair r.name { measurement = ""; }) releases);
    names = {
      ${cfg.names.verify} = lib.listToAttrs (map (r: lib.nameValuePair r.name [ "vsock://2:${portOf r 9444}" ]) releases);
      ${cfg.names.api} = lib.listToAttrs (map (r: lib.nameValuePair r.name [ "vsock://2:${portOf r 9443}" ]) releases);
    };
    routes = {
      ${cfg.names.api} = [{
        method = "POST";
        path = "/api/v1/sessions";
        group = "forbidden";
        refuse_measurements = [ ];
      }] ++ named;
      ${cfg.names.verify} = lib.optional (cfg.public.landing != null) {
        method = "GET";
        path = "/";
        external_origin_redirect_307_to = cfg.public.landing;
      } ++ named;
    };
  };
  # A measurement is a build output, so it is filled in by a build rather than
  # read here.
  measured = r: "m${toString r.index}";
  fill = lib.concatStringsSep " | " (
    map (r: ".groups[${builtins.toJSON r.name}].measurement = \$${measured r}") releases
    ++ [ ".routes[][] |= (if has(\"refuse_measurements\") then .refuse_measurements = [${
      lib.concatMapStringsSep ", " (r: "\$${measured r}") (lib.filter (r: r.draining) releases)
    }] else . end)" ]
  );
  gatewayJson = pkgs.runCommand "enclavid-gateway.json" { nativeBuildInputs = [ pkgs.jq ]; } ''
    jq ${lib.concatMapStringsSep " " (r: "--rawfile ${measured r} ${r.built.measurement "api"}") releases} \
      ${lib.escapeShellArg (if releases == [ ] then "." else fill)} \
      ${pkgs.writeText "enclavid-table.json" (builtins.toJSON table)} >$out
    jq -e '[.groups[].measurement] | all(test("^[0-9a-f]{96}$"))' $out >/dev/null
    # The gateway lets one build on one part carry at most this many groups
    # (MOST_LABELS_PER_DOMAIN, crates/gateway/src/upstream/mod.rs); past it, a
    # group's legs are refused and its share of new sessions fails.
    jq -e '[.groups[].measurement] | group_by(.) | all(length <= 8)' $out >/dev/null || {
      echo "enclavid.releases: more than 8 run one api build, and the gateway takes at most 8 groups of a build on one host" >&2
      exit 1
    }
    # New sessions are refused by build, so a build draining in one release
    # would be refused in every other that runs it too.
    jq -e --argjson open ${lib.escapeShellArg (builtins.toJSON (map (r: r.name) (lib.filter (r: !r.draining) releases)))} '
      [.routes[][] | .refuse_measurements? // [] | .[]] as $refused
      | [.groups | to_entries[] | select(.key as $k | $open | index($k)) | .value.measurement]
      | all(. as $m | $refused | index($m) | not)' $out >/dev/null || {
      echo "enclavid.releases: a build draining in one release runs undrained in another, and new sessions are refused by build — drain all of them or none" >&2
      exit 1
    }
  '';

  issue = cfg.acme.issue;
  certificate = fleet.certificate {
    names = [ cfg.names.verify cfg.names.api ];
    inherit issue;
  };

  releaseServices = r: lib.listToAttrs (map
    (role: lib.nameValuePair "enclavid-${r.name}-${role}" (fleet.cvmService {
      name = "${r.name}-${role}";
      image = r.built.image role;
      inherit (r.built) qemu;
      cid = cidOf r role;
      inherit (cfg.cvms.${role}) memory;
      # A disk per release: what one release's storage wrote, only that
      # release's api can open.
      disk = if role == "storage" then {
        path = "/var/lib/enclavid/${r.name}/storage.img";
        state = "enclavid/${r.name}";
        inherit (cfg.cvms.storage.disk) size;
      } else null;
      environment = lib.optionalAttrs (role == "api") { FW_CFG = legPorts r; };
    }))
    roles);

  # A gateway keeps no configuration across a start: while it is up, its table
  # is pushed — again after every start, since the push is bound to it; and
  # when only the table changes, only the push runs again. Every gateway takes
  # the same table.
  gatewayServices = g:
    let
      unit = "enclavid-gateway-${g.name}";
      port = "http://${fleet.gatewayConfig g.index}";
    in
    {
      ${unit} = fleet.cvmService
        {
          name = "gateway-${g.name}";
          image = g.built.image "gateway";
          inherit (g.built) qemu;
          cid = gatewayCid g;
          inherit (cfg.cvms.gateway) memory;
        } // { unitConfig.Upholds = "${unit}-push.service"; };
      "${unit}-push" = {
        description = "Enclavid: push the gateway ${g.name} its configuration";
        bindsTo = [ "${unit}.service" ];
        after = [ "${unit}.service" ];
        enableDefaultPath = false;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${lib.getExe fleet.pushGateway} ${port} ${gatewayJson}";
          TimeoutStartSec = 150;
        };
      };
    } // lib.optionalAttrs issue.enable {
      # After every push — so after every start of the gateway, whose keys a
      # new build changes — at every switch, which starts it, and every six
      # hours, by its timer. A run that fails is tried again a quarter of an
      # hour later, unless the issuer refused to validate the names: refusals
      # in a row get the account paused for them, so one waits for the next
      # check, or a restart by hand. Nothing of the account is kept here: its
      # key is the gateway's, and the issuer finds the account by it on every
      # run.
      "enclavid-certificate-${g.name}" = {
        description = "Enclavid: keep the gateway ${g.name} on an issued certificate";
        wantedBy = [ "${unit}-push.service" ];
        # After every gateway's push, not only its own: the one callers reach
        # opens its public listener at its first push.
        after = map (o: "enclavid-gateway-${o.name}-push.service") gateways;
        enableDefaultPath = false;
        serviceConfig = {
          Type = "oneshot";
          # This gateway's certificate, validated through the gateway callers
          # reach, and pushed to it with its table.
          ExecStart = lib.concatStringsSep " " (
            [ (lib.getExe certificate) "--for" port ] ++ arming ++ [ "--push" gatewayJson ]
          );
          Restart = "on-failure";
          RestartSec = "15min";
          RestartPreventExitStatus = 3;
          StateDirectory = "enclavid/certificates";
          StateDirectoryMode = "0700";
          TimeoutStartSec = 600;
        };
      };
    };

  # A role's settings, which every release's guest of that role takes.
  cvm = role: defaults: mkOption {
    description = "The ${role} guests' settings.";
    default = { };
    type = types.submodule {
      options = {
        memory = mkOption {
          # With its unit: the same string sizes the memory backend, where a
          # bare number is bytes rather than -m's MiB.
          type = types.strMatching "[1-9][0-9]*[MG]";
          default = defaults.memory;
          description = "Its memory, in MiB or GiB with the unit: 3072M, 3G.";
        };
      } // lib.optionalAttrs (defaults ? disk) {
        disk.size = mkOption {
          type = types.str;
          default = defaults.disk.size;
          description = "How large to make its volume; read only when it is made.";
        };
      };
    };
  };

  # A list other modules add to, and which only the fleet reads.
  internalList = description: mkOption {
    type = types.listOf types.str;
    internal = true;
    inherit description;
  };
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
      # How often one principal may ask for each, a minute, all at once if
      # need be; -1 for no limit, null for the hatch's own. With
      # `auth = "none"` every request is the one principal, credential or
      # none, so a limit is the host's, and anyone can spend it for everyone.
      perMinute = {
        sessionCreate = mkOption {
          type = perMinute;
          default = null;
          description = ''
            Sessions one principal may create a minute; the hatch's own is 60.
            Every session is later fetched and compiled for its applicant, so
            this is also what a consumer may have the guests do.
          '';
        };
        sessionRead = mkOption {
          type = perMinute;
          default = null;
          description = "Reads of a session's state one principal may make a minute; the hatch's own is 600.";
        };
        dataRead = mkOption {
          type = perMinute;
          default = null;
          description = "Pulls of a session's disclosures one principal may make a minute; the hatch's own is 120.";
        };
      };
    };
    variant = mkOption {
      type = types.enum [ "production" "debug" ];
      default = "production";
      description = ''
        Which images. Every guest writes what it logs to its serial console,
        /var/log/enclavid/NAME.serial; debug ones add the kernel's console and
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
      landing = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "https://example.com/from-verify";
        description = ''
          Where a browser at the bare verify name, with no link to a session, is
          sent: an https page under a name the gateway does not serve, which it
          refuses to send one to. Null answers it 400, as any request naming no
          group.
        '';
      };
    };
    acme.issue = {
      enable = lib.mkEnableOption ''
        issuing and renewing the gateway's certificate from an ACME certificate
        authority, to an account whose key is the gateway's own, validated over
        TLS-ALPN-01 by the gateway. The certificate is checked every six hours
        and after every start of the gateway, and issued again when it lapses
        within `renewDays` or its issuer asks, is for another key than the
        gateway's, does not cover both names, or came from another `server`
      '';
      acceptTerms = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Agreement to the certificate authority's terms of service, which the
          gateway's account is opened under. Issuance needs it.
        '';
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
    startAtBoot = mkOption {
      type = types.bool;
      default = true;
      description = "Whether the fleet comes up when the host boots.";
    };
    cvms = {
      storage = cvm "storage" { memory = "2G"; disk.size = "8G"; };
      compile-worker = cvm "compile-worker" { memory = "3G"; };
      execution-worker = cvm "execution-worker" { memory = "3G"; };
      api = cvm "api" { memory = "3G"; };
      gateway = cvm "gateway" { memory = "2G"; };
    };

    releases = mkOption {
      internal = true;
      default = { main = { }; };
      description = ''
        The releases the gateway serves: this checkout, by default, as `main`.
        Where a module beside this one puts others — each a full set of guests
        with host ports and a storage disk of its own, reached under a gateway
        group of its name.
      '';
      type = types.attrsOf (types.submodule {
        options = {
          index = mkOption {
            type = types.ints.between 0 99;
            default = 0;
            description = "Fixes the release's guests' vsock context IDs and its host ports.";
          };
          src = mkOption {
            type = types.path;
            default = ../.;
            description = "The enclavid tree it is built from.";
          };
          draining = mkOption {
            type = types.bool;
            default = false;
            description = "Whether the gateway refuses its build new sessions, while its links still route.";
          };
          hatchPort = mkOption {
            type = types.port;
            default = fleet.hatchPort;
            description = "The port of the hatch its api reaches outside through.";
          };
          guests = mkOption {
            type = types.bool;
            default = true;
            description = "Whether this host runs the release's guests, or only serves it from its gateway.";
          };
          entrances = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              The address of the host running the release, where a gateway on
              another host reaches its api over TCP; null when the gateway runs
              beside it and reaches it over vsock.
            '';
          };
        };
      });
    };
    gateways = mkOption {
      internal = true;
      default = { main = { }; };
      description = ''
        The gateways this host runs: this checkout's, by default, as `main`,
        where `public.listen` says. Where a module beside this one puts others
        — each a guest of its own, from its own tree, with a context ID and
        host ports fixed by its index and its public listener where it says —
        or none, on a host whose releases a gateway elsewhere serves. Every one
        takes the same table and keeps a certificate of its own; the one callers
        reach is the one serving.
      '';
      type = types.attrsOf (types.submodule {
        options = {
          index = mkOption {
            type = types.ints.between 0 99;
            default = 0;
            description = "Fixes the gateway's vsock context ID and its host ports.";
          };
          src = mkOption {
            type = types.path;
            default = ../.;
            description = "The enclavid tree it is built from.";
          };
          listen = mkOption {
            type = types.str;
            default = cfg.public.listen;
            description = "Where its public listener is reached, as host-relay names an address.";
          };
        };
      });
    };
    health = internalList "Where each guest that has one answers its health, as HOST:PORT on the host.";
    units = internalList "The units meant to stay up once the fleet is: every one but the certificate run.";
    memory = internalList "Every guest's memory, for the preflight to sum.";
    qemus = internalList "Every QEMU a guest boots under, for the preflight to try.";
    vsockPorts = internalList "Every vsock port on the host something of the fleet listens on.";
  };

  config = {
    nixpkgs.hostPlatform = "x86_64-linux";

    enclavid.health = map (r: lib.removePrefix "tcp:" r.listen)
      (map (g: (gatewayRelays g).health) gateways ++ map (r: (releaseRelays r).health) local);
    enclavid.units =
      lib.concatMap (g: [ "enclavid-gateway-${g.name}.service" "enclavid-gateway-${g.name}-push.service" ]) gateways
      ++ lib.optional (local != [ ]) "enclavid-hatch.service"
      ++ lib.concatMap (r: map (role: "enclavid-${r.name}-${role}.service") roles) local
      ++ map (name: "enclavid-relay-${name}.service") (lib.attrNames relays);
    enclavid.memory = map (_: cfg.cvms.gateway.memory) gateways
      ++ lib.concatMap (_: map (role: cfg.cvms.${role}.memory) roles) local;
    enclavid.qemus = lib.unique (map (g: g.built.qemu) gateways ++ map (r: r.built.qemu) local);
    enclavid.vsockPorts = lib.optional (local != [ ]) (toString fleet.hatchPort)
      ++ map (r: lib.removePrefix "vsock:" r.listen) (lib.filter (r: lib.hasPrefix "vsock:" r.listen) (lib.attrValues relays));

    # system-manager would otherwise take over /etc/passwd and /etc/group.
    services.userborn.enable = false;

    # The device every guest is reached through, at every boot.
    environment.etc."modules-load.d/enclavid.conf".text = "vhost_vsock\n";

    assertions =
      lib.concatMap
        (r: lib.concatLists (lib.mapAttrsToList
          (role: settings: map
            (setting: {
              assertion = lib.elem setting (r.built.cmdline role);
              message = "enclavid.releases.${r.name}: its image/cmdline/${role}/${cfg.variant} no longer carries ${setting}";
            })
            settings)
          (carried r)))
        local
      ++ lib.concatMap
        (g: map
          (setting: {
            assertion = lib.elem setting (g.built.cmdline "gateway");
            message = "enclavid.gateways.${g.name}: its image/cmdline/gateway/${cfg.variant} no longer carries ${setting}";
          })
          (gatewayCarried g))
        gateways
      ++ [
        {
          assertion = lib.all (r: r.guests || r.entrances != null) releases;
          message = "enclavid.releases: a release whose guests run on another host is reached at its entrances there";
        }
        {
          assertion = lib.all (r: r.guests || gatewayHere) releases;
          message = "enclavid.releases: a release is run here, or served by the gateway here";
        }
        {
          assertion = gatewayHere || lib.all (r: r.entrances != null) local;
          message = "enclavid.releases: with the gateway on another host, a release's api is reached at its entrances";
        }
        {
          assertion = cfg.hatch.auth != "oidc" || (cfg.hatch.issuer != null && cfg.hatch.audience != null);
          message = "enclavid.hatch: auth = \"oidc\" needs issuer and audience";
        }
        {
          assertion = cfg.hatch.auth != "none" || cfg.hatch.principal != null;
          message = "enclavid.hatch: auth = \"none\" needs principal";
        }
        {
          assertion = lib.all (r: builtins.match "[a-z0-9-]{1,32}" r.name != null) releases;
          message = "enclavid.releases: a release's name is the gateway group it is reached under — 1 to 32 characters of a-z, 0-9 or -";
        }
        {
          assertion = lib.allUnique (map (r: r.index) releases);
          message = "enclavid.releases: every release needs an index of its own";
        }
        {
          assertion = lib.all (g: builtins.match "[a-z0-9-]{1,32}" g.name != null) gateways
            && lib.allUnique (map (g: g.index) gateways);
          message = "enclavid.gateways: every gateway needs an index of its own, and a name of 1 to 32 characters of a-z, 0-9 or -";
        }
        {
          assertion = lib.all (name: !(releaseSide ? ${name})) (lib.attrNames perGateway);
          message = "enclavid.releases: a release named gateway-<a gateway's name> would share its relays' names";
        }
        {
          assertion = lib.allUnique cfg.vsockPorts
            && lib.allUnique (map (r: r.listen) (lib.filter (r: lib.hasPrefix "tcp:" r.listen) (lib.attrValues relays)));
          message = "enclavid: two of the relays and hatches listen on one host port";
        }
        {
          assertion = !issue.enable || issue.acceptTerms;
          message = "enclavid.acme.issue: the gateway's account is opened under the certificate authority's terms of service — read them and set acceptTerms = true";
        }
      ];

    systemd.services = lib.mkMerge ([
      (lib.mapAttrs' (name: r: lib.nameValuePair "enclavid-relay-${name}" (fleet.relayService name r)) relays)
      (lib.mkIf (local != [ ]) {
        enclavid-hatch = fleet.hatchService {
          name = "shared";
          port = fleet.hatchPort;
          src = ../.;
          settings = cfg.hatch;
        };
      })
    ] ++ map releaseServices local ++ map gatewayServices gateways);
    systemd.packages = lib.optional (local != [ ]) (fleet.hatchRoot {
      unit = "enclavid-hatch.service";
      src = ../.;
    });

    # Every six hours, which is how often Let's Encrypt asks to be asked when a
    # certificate should be renewed — an early renewal it asks for ahead of
    # revoking some is seen within the day it gives.
    systemd.timers = lib.mkIf issue.enable (lib.listToAttrs (map
      (g: lib.nameValuePair "enclavid-certificate-${g.name}" {
        description = "Enclavid: check the gateway ${g.name}'s certificate every six hours";
        wantedBy = [ "enclavid-fleet.target" ];
        partOf = [ "enclavid-fleet.target" ];
        timerConfig = {
          OnCalendar = "00/6:00";
          RandomizedDelaySec = "30min";
          Persistent = true;
        };
      })
      gateways));

    # Members join a target through their own `wantedBy`, so a target's text
    # does not change when the fleet does — and a target is never restarted
    # under the units that are part of it.
    systemd.targets = {
      enclavid-host.description = "Enclavid host side: the relays and the hatches";
      enclavid-fleet = {
        description = "Enclavid fleet: the confidential VMs, and the host side they reach";
        wants = [ "enclavid-host.target" ];
        after = [ "enclavid-host.target" ];
        wantedBy = lib.optional cfg.startAtBoot "system-manager.target";
      };
    };
  };
}
