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
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  static = pkgs.pkgsStatic;

  # The workspace, minus everything that is an output rather than a source.
  # Filtering matters for more than build time: an unfiltered `target/` would
  # put the previous build's artefacts into this build's input hash.
  src = builtins.path {
    name = "enclavid-src";
    path = ../..;
    filter = path: type:
      let base = baseNameOf path; in
      !(base == "target" || base == ".git" || base == "node_modules" || base == "result");
  };

  # `noDefaultFeatures` is per role rather than blanket: `--no-default-features`
  # applies to the selected package, so setting it where a package has no
  # feature table changes nothing and only obscures which roles depend on it.
  # `siblings` are the other [[bin]] targets of the same package that the role
  # execs at runtime — the workers spawn a fresh child per round and look for it
  # next to their own executable. They build together and must ship together, so
  # they are one derivation rather than a dependency between two.
  mkApp = { pname, package, binary, siblings ? [ ], features ? [ ], noDefaultFeatures ? false }:
    static.rustPlatform.buildRustPackage {
      inherit pname src;
      version = "0.1.0";

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
        for b in ${binary} ${builtins.concatStringsSep " " siblings}; do
          install -m 0755 "target/${static.stdenv.hostPlatform.rust.rustcTarget}/release/$b" $out/$b
          (cd $out && sha256sum "$b" > "$b.sha256")
        done
        runHook postInstall
      '';
    };

  # Each role ships as two derivations, `<role>` and `<role>-debug`. They differ
  # in one feature: `debug` compiles the `debug!` sites in. Without it those
  # calls are not built at all, so a production binary carries no diagnostic
  # that nobody wrote a reason for — see crates/public-logger.
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
  (withDebug "api" {
    pname = "enclavid-app-api";
    package = "enclavid-api";
    binary = "enclavid-api";
    noDefaultFeatures = true;
    features = [ "sev-snp" "vsock" ];
  })

  # The storage CVM: the blind ciphertext store. `vsock` for the same reason as
  # api — a guest kernel with no IP stack cannot bind a TCP listener. It has no
  # attestation axis to choose: the endorsement a hardware attestor needs would
  # have to reach a role that, by design, dials nothing.
  (withDebug "storage" {
    pname = "enclavid-app-storage";
    package = "enclavid-storage";
    binary = "storage-cvm";
    features = [ "vsock" ];
  })

  # The compile half of the engine: fuses a policy with its pinned plugins and
  # Cranelift-compiles the result. Diskless — everything it produces goes back
  # over the wire. `guest-hardening` is what makes the per-round child isolation
  # its own containment rests on an enforced floor rather than an assumption.
  (withDebug "compile-worker" {
    pname = "enclavid-app-compile-worker";
    package = "engine-compiler";
    binary = "compile-worker";
    siblings = [ "compile-child" ];
    features = [ "vsock" "guest-hardening" ];
  })

  # The execute half: runs one reducer round per disposable child. This is the
  # role that touches applicant data in the clear, and the only one that runs
  # the consumer's own untrusted wasm.
  (withDebug "execution-worker" {
    pname = "enclavid-app-execution-worker";
    package = "engine-executor";
    binary = "execution-worker";
    siblings = [ "session-child" ];
    features = [ "vsock" "guest-hardening" ];
  })
]
