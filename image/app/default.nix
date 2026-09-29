# Role applications — reproducible build.
#
# The last unpinned input to the measurement. With this, a published launch
# digest becomes a function of one repository commit and nothing else: firmware
# version, kernel config, busybox config, these binaries, and the cmdline.
#
#   nix-build image/app -A api
#   nix-build image/app -A storage
#
# Every role also has an `-A <role>-debug` twin, which differs by one feature
# and belongs with `cmdline/<role>/debug`. See `withDebug` below.
#
# Static musl, because the initramfs carries no libc and no dynamic loader —
# see image/initramfs.
#
# `measurements` is the three leaves' launch digests, and only api's part reads
# them — the gateway pins nothing, so it needs none. It is an argument rather
# than something computed here because computing them needs the leaves' images,
# which need this file; `image/default.nix` owns that ordering and is where a
# complete build starts.
{ measurements ? null }:
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  static = pkgs.pkgsStatic;

  # Only what cargo reads, and a fixed seed for the C it compiles — see
  # workspace.nix for why a measurement needs both.
  inherit (import ./workspace.nix { inherit (pkgs) lib; }) src fixedSeed;

  # ONE cargo invocation over ONE package, and the binaries to keep from it.
  #
  # `noDefaultFeatures` is per part rather than blanket: `--no-default-features`
  # applies to the selected package, so setting it where a package has no
  # feature table changes nothing and only obscures which roles depend on it.
  mkPart = { pname, package, binaries, features ? [ ], noDefaultFeatures ? false
           , preBuild ? "", nativeBuildInputs ? [ ] }:
    static.rustPlatform.buildRustPackage {
      inherit pname src nativeBuildInputs;
      version = "0.1.0";
      preBuild = fixedSeed + preBuild;

      # A part that asks for cmake gets the tool and not the hook: a Rust build
      # configures itself, and the hook would try to configure the source tree
      # as a cmake project before cargo ever runs.
      dontUseCmakeConfigure = true;

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
        for b in ${builtins.concatStringsSep " " binaries}; do
          install -m 0755 "target/${static.stdenv.hostPlatform.rust.rustcTarget}/release/$b" $out/$b
          (cd $out && sha256sum "$b" > "$b.sha256")
        done
        runHook postInstall
      '';
    };

  # A role's binaries, each part built by its OWN cargo invocation, merged into
  # one output. The workers exec a fresh child per request and look for it next
  # to their own executable, so the two must ship together — but they must not
  # BUILD together.
  #
  # That is the whole reason a role is a list. Cargo unifies features across
  # everything in one invocation, so compiling a worker beside its child would
  # hand the child every feature the worker asked for. The child's manifest is
  # deliberately short — it is how the image says what the process that runs
  # untrusted wasm can reach — and a shared invocation would quietly make it say
  # nothing. One build per package keeps each dependency graph its own.
  #
  # The cost is real: the shared libraries below the split (wasmtime, above all)
  # compile once per part. Paid on purpose.
  mkApp = { pname, parts, features ? [ ] }:
    pkgs.symlinkJoin {
      name = pname;
      paths = map
        (part: mkPart (part // {
          pname = "${pname}-${part.package}";
          features = (part.features or [ ]) ++ features;
        }))
        parts;
    };

  # Each role ships as two derivations, `<role>` and `<role>-debug`. They differ
  # in one feature: `debug` compiles the `debug!` sites in. Without it those
  # calls are not built at all, so a production binary carries no diagnostic
  # that nobody wrote a reason for — see crates/safe-logger.
  #
  # Why the app and not just the command line. `cmdline/<role>/debug` already
  # opens a kernel console, and that alone would have been one switch instead of
  # two. But then both tiers of output would hang off the same `console=null`:
  # one wrong line in kernel/ or cmdline/ and every `debug!` in the tree — some
  # carrying a session id and an error chain — reaches the host at once. Not
  # compiling them decouples the tiers, so that mistake can only leak what
  # dependencies print.
  #
  # The cost is that the pair must be kept together: a debug app wants a debug
  # command line. Getting it wrong is confusing, never unsafe — the mismatches
  # are "writes into ttynull" and "says nothing", in that order.
  withDebug = name: args: {
    "${name}" = mkApp args;
    "${name}-debug" = mkApp (args // {
      pname = args.pname + "-debug";
      features = (args.features or [ ]) ++ [ "debug" ];
    });
  };
in
builtins.foldl' (a: b: a // b) { } [
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
  #
  # api is also the one role written out per variant rather than through
  # `withDebug`, because the two differ by more than a feature: each pins the
  # three leaf images of ITS OWN variant. A production api that pinned debug
  # leaves would refuse every peer it was given, correctly and confusingly.
  (let
    apiPart = variant: {
      package = "enclavid-api";
      binaries = [ "enclavid-api" ];
      noDefaultFeatures = true;
      features = [ "sev-snp" "vsock" ];
      # Exported into the build environment rather than substituted into the
      # source, because that is what `env!` reads. Each file holds one digest and
      # no newline — `endorsement.rs` checks for exactly 96 lowercase hex
      # characters, so `$(cat …)` has to be the whole of it.
      preBuild =
        let m = measurements.${variant} or (throw
          "image/app: api is built from the three leaf measurements, and none were \
           given. Build it through `image/default.nix`, which measures the leaves \
           first — `nix-build image -A images.api`.");
        in ''
          export ENCLAVID_MEASUREMENT_STORAGE=$(cat ${m.storage})
          export ENCLAVID_MEASUREMENT_COMPILE_WORKER=$(cat ${m.compile-worker})
          export ENCLAVID_MEASUREMENT_EXECUTION_WORKER=$(cat ${m.execution-worker})
          export ENCLAVID_FRONTEND_DIST=${import ../../frontend { inherit pkgs; }}
        '';
    };
  in
  {
    api = mkApp {
      pname = "enclavid-app-api";
      parts = [ (apiPart "production") ];
    };
    api-debug = mkApp {
      pname = "enclavid-app-api-debug";
      parts = [ (apiPart "debug") ];
      features = [ "debug" ];
    };
  })

  # The storage CVM: the blind ciphertext store. `vsock` for the same reason as
  # api — a guest kernel with no IP stack cannot bind a TCP listener.
  #
  # `sev-snp` off the defaults, for the same reason api does it: cargo features
  # are additive, so asking for the hardware backend on top of the default would
  # leave the dev fleet's shared software identity compiled in beside it. That
  # identity is a seed literal in this repository — anyone who can read the
  # source can be this role — which is what made shipping it in a measured image
  # the thing to fix.
  #
  # This used to say the role had no attestation axis to choose, because the
  # endorsement a hardware attestor needs would have to reach a guest that by
  # design dials nothing. True of fetching one; not true of needing one. The
  # chip signs the report either way, and api — which does reach AMD — verifies
  # it against its own copy of the same chip's certificate.
  (withDebug "storage" {
    pname = "enclavid-app-storage";
    parts = [{
      package = "enclavid-storage";
      binaries = [ "storage-cvm" ];
      noDefaultFeatures = true;
      features = [ "vsock" "sev-snp" ];
    }];
  })

  # The compile half of the engine: fuses a policy with its pinned plugins and
  # Cranelift-compiles the result. Diskless — everything it produces goes back
  # over the wire. `guest-hardening` is what makes the per-round child isolation
  # its own containment rests on an enforced floor rather than an assumption.
  (withDebug "compile-worker" {
    pname = "enclavid-app-compile-worker";
    parts = [
      {
        package = "engine-compiler";
        binaries = [ "compile-worker" ];
        # `sev-snp` off the defaults — see the storage part above for why the
        # software identity must not come along with it.
        noDefaultFeatures = true;
        features = [ "vsock" "guest-hardening" "sev-snp" ];
      }
      # The child takes neither `vsock` nor `guest-hardening`: it has no
      # transport of its own (its one connection is the socketpair the supervisor
      # hands it on fd 0), and the ptrace floor is asserted by the parent, before
      # any child exists. It takes `contained`, which compiles its assertion that
      # this build carries no outward log tier — true here because this is one
      # `cargo build -p` and nothing in it asks for one.
      {
        package = "engine-compiler-child";
        binaries = [ "engine-compiler-child" ];
        features = [ "contained" ];
      }
    ];
  })

  # The execute half: runs one reducer round per disposable child. This is the
  # role that touches applicant data in the clear, and the only one that runs
  # the consumer's own untrusted wasm.
  (withDebug "execution-worker" {
    pname = "enclavid-app-execution-worker";
    parts = [
      {
        package = "engine-executor";
        binaries = [ "execution-worker" ];
        # `sev-snp` off the defaults — see the storage part above for why the
        # software identity must not come along with it.
        noDefaultFeatures = true;
        features = [ "vsock" "guest-hardening" "sev-snp" ];
      }
      # The child takes neither `vsock` nor `guest-hardening`: it has no
      # transport of its own (its one connection is the socketpair the supervisor
      # hands it on fd 0), and the ptrace floor is asserted by the parent, before
      # any child exists. It takes `contained`, which compiles its assertion that
      # this build carries no outward log tier — true here because this is one
      # `cargo build -p` and nothing in it asks for one.
      {
        package = "engine-executor-child";
        binaries = [ "engine-executor-child" ];
        features = [ "contained" ];
      }
    ];
  })

  # The role that terminates client TLS. `vsock` for the same reason as every
  # other role, and it applies to the PUBLIC listener too: a guest kernel with
  # no IP stack cannot bind a TCP socket, so the host carries the public
  # connection in over vsock WITHOUT terminating it, and the TLS session begins
  # inside this measurement.
  #
  # `sev-snp` off the defaults, like every other attested part — cargo features
  # are additive, so asking for the hardware backend on top of the default would
  # leave the dev fleet's shared software identity compiled in beside it.
  #
  # No `preBuild` and no measurement, unlike api. This role pins nothing: which
  # api build a caller is served by is named by the caller, per request, and
  # proved at the handshake. So the gateway is built from source alone and its
  # digest does not move when api's does — which is what lets api be upgraded
  # under it, and what keeps a certificate sealed to this measurement alive
  # across an api release.
  (withDebug "gateway" {
    pname = "enclavid-app-gateway";
    parts = [{
      package = "enclavid-gateway";
      binaries = [ "gateway" ];
      noDefaultFeatures = true;
      features = [ "sev-snp" "vsock" ];
    }];
  })
]
