# The measured launch, as one expression.
#
#   nix-build image -A images.storage        # kernel + initramfs + cmdline
#   nix-build image -A measurements.storage  # the launch digest of exactly that
#   nix-build image -A images.api            # api, pinned to the three above
#
# Until this file existed, a role's image was assembled by hand and its digest
# computed by a second hand-written command, from arguments that had to agree.
# They did not: the launchers on one bench disagreed with each other about the
# vCPU count, and the one recorded measurement had been taken with a third
# value. Nothing catches that — a digest computed from parameters the guest was
# not launched with is a perfectly well-formed digest of a machine that does not
# exist. Here the launch line and the measurement are generated from the same
# `launch` set below, so they cannot disagree.
#
# The ordering this file expresses is the one api's `endorsement.rs` depends on:
# the three leaves are built and measured, and api is built from their digests.
# It is a fact of the trust direction, not a build-system detail — api pins which
# image each peer is, and no leaf pins api back, because api's own digest is a
# function of the three it pins.
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;

  kernel = import ./kernel;
  ovmf = import ./ovmf;
  firmware = "${ovmf}/FV/OVMF.fd";

  # Everything the guest is started with that the measurement also depends on.
  # One set, two consumers: `qemuArgs` below writes the launch line and
  # `measure` writes the digest, so a change here moves both together.
  launch = {
    # Every possible vCPU contributes a VMSA page to the digest, so this is an
    # input and not a tuning knob: booting with a different count produces a
    # guest whose measurement no peer pins. Verified — 2, 4 and 8 give three
    # different digests on otherwise identical inputs.
    vcpus = 2;
    # Selects the CPUID signature written into each VMSA. `EPYC-Milan`,
    # `-Milan-v1` and `-Milan-v2` all resolve to family 25 model 1 stepping 1
    # and produce identical digests; the -v2 spelling is used because it is what
    # the `-cpu` flag says, and two names for one thing invites drift.
    vcpuType = "EPYC-Milan-v2";
    # The `sev_features` field of every VMSA page. Bit 0 is SNP_ACTIVE, which is
    # what KVM sets for a launch with no IGVM file — which is this one.
    guestFeatures = "0x1";
    # SMT_ALLOWED | reserved-bit-1. Debug is off and there is no migration
    # agent; `crates/attestation` refuses a report that says otherwise.
    policy = "0x30000";
    # Where the C-bit sits on Milan, and the physical address bits lost to it.
    cbitpos = 51;
    reducedPhysBits = 1;
  };

  # What each role is: which kernel it boots, which binaries its initramfs
  # carries, and what its PID 1 does.
  #
  # `siblings` is a name → binary map rather than a list because the workers
  # resolve their per-round child as a sibling of their own executable, so the
  # NAME is what has to be right; `/bin/app` alone would not do.
  roles = {
    api = {
      kernel = kernel.diskless;
      binary = "enclavid-api";
    };
    storage = {
      kernel = kernel.storage;
      binary = "storage-cvm";
      # The mount point for the data volume. The application makes `sessions/`
      # and `cache/` underneath at runtime; the image carries only what PID 1
      # needs before it starts.
      dirs = [ "data" ];
    };
    compile-worker = {
      kernel = kernel.diskless;
      binary = "compile-worker";
      siblings = [ "engine-compiler-child" ];
    };
    execution-worker = {
      kernel = kernel.diskless;
      binary = "execution-worker";
      siblings = [ "engine-executor-child" ];
    };
  };

  # The app attribute for a role in a variant: `storage` or `storage-debug`.
  appAttr = role: variant: if variant == "debug" then "${role}-debug" else role;

  # Assemble one role's initramfs.
  #
  # The binaries are INTERPOLATED out of the app derivation rather than passed as
  # store paths. That is not a style preference: a path argument arrives as a
  # fresh store object with no link to the derivation that produced it, so it is
  # not an input to this build and the sandbox cannot see it — the failure is an
  # `install: cannot stat` from inside the builder.
  initramfsFor = apps: role: variant:
    let
      spec = roles.${role};
      app = apps.${appAttr role variant};
    in
    import ./initramfs {
      name = "${role}-${variant}";
      app = app + "/${spec.binary}";
      inittab = ./init/inittab + "/${role}";
      dirs = spec.dirs or [ ];
      siblings = lib.listToAttrs (map
        (s: lib.nameValuePair s (app + "/${s}"))
        (spec.siblings or [ ]));
    };

  cmdlineFor = role: variant: ./cmdline + "/${role}/${variant}";

  # The launch digest of one assembled image.
  #
  # The output is the digest and nothing else — no trailing newline — because
  # api compiles it in through `env!` and checks it is exactly 96 lowercase hex
  # characters. A newline here is a build failure there, which is the right way
  # round but an obscure one to debug.
  #
  # The kernel, the initramfs and the command line reach the digest only because
  # the launch sets `kernel-hashes=on`: with it off, QEMU measures that region as
  # zeroes and this tool would compute a number describing a machine nobody
  # boots. The two are set from the same `launch` set for exactly that reason.
  measure = role: variant:
    let img = imageFor role variant; in
    pkgs.runCommand "enclavid-measurement-${role}-${variant}"
      { nativeBuildInputs = [ pkgs.sev-snp-measure ]; } ''
      sev-snp-measure --mode snp \
        --vcpus ${toString launch.vcpus} \
        --vcpu-type ${launch.vcpuType} \
        --guest-features ${launch.guestFeatures} \
        --ovmf ${firmware} \
        --kernel ${img}/bzImage \
        --initrd ${img}/initramfs.cpio.gz \
        --append "$(cat ${img}/cmdline)" \
      | tr -d '\n' > $out
    '';

  # One role's whole boot: the three files QEMU is pointed at, plus the argument
  # list that points at them. Collected into one derivation so that what is
  # measured and what is launched cannot be assembled from different places.
  imageFor = role: variant:
    let
      spec = roles.${role};
      apps = appsFor role variant;
      irfs = initramfsFor apps role variant;
    in
    pkgs.runCommand "enclavid-image-${role}-${variant}" { } ''
      mkdir -p $out
      ln -s ${spec.kernel}/bzImage        $out/bzImage
      ln -s ${irfs}/initramfs.cpio.gz     $out/initramfs.cpio.gz
      cp    ${cmdlineFor role variant}    $out/cmdline

      # The flags the digest depends on, ready to splice into a launch. What is
      # NOT here is what the measurement does not cover and the operator has to
      # choose: memory size, the vsock CID, any drive, where the serial goes.
      cat > $out/qemu-args <<'ARGS'
      -cpu ${launch.vcpuType}
      -smp ${toString launch.vcpus}
      -machine q35,confidential-guest-support=sev0,memory-backend=ram0
      -object sev-snp-guest,id=sev0,cbitpos=${toString launch.cbitpos},reduced-phys-bits=${toString launch.reducedPhysBits},kernel-hashes=on,policy=${launch.policy}
      -bios ${firmware}
      ARGS
      sed -i 's/^      //' $out/qemu-args
    '';

  # Which app set a role is built from. The three leaves need nothing from
  # anyone; api needs the leaves' digests, so it gets an app set that has them.
  #
  # Both variants' digests are handed over at once because one `image/app` call
  # produces both api builds. Laziness is what keeps that from costing anything:
  # asking for the production api forces the production leaves and never looks
  # at the debug ones.
  appsFor = role: _variant: if role == "api" then apiApps else leafApps;

  leafApps = import ./app { };
  apiApps = import ./app {
    measurements = lib.listToAttrs
      (map (v: lib.nameValuePair v (measurementsFor v)) variants);
  };

  leaves = [ "storage" "compile-worker" "execution-worker" ];

  measurementsFor = variant:
    lib.listToAttrs (map (r: lib.nameValuePair r (measure r variant)) leaves);

  variants = [ "production" "debug" ];
  everyRole = builtins.attrNames roles;

  # `<role>` and `<role>-debug`, matching how `image/app` names its two builds.
  named = f: lib.listToAttrs (lib.concatMap
    (role: map
      (variant: lib.nameValuePair
        (if variant == "debug" then "${role}-debug" else role)
        (f role variant))
      variants)
    everyRole);
in
{
  inherit launch;
  ovmf = ovmf;
  images = named imageFor;
  measurements = named measure;
}
