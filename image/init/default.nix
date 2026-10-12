# Guest PID 1 and the tool its services run — reproducible builds.
#
# Both land in the initramfs, which QEMU hashes into the measured SEV-SNP
# launch, so like the kernel each has to be a function of its declared inputs
# and nothing else. Same shape as image/kernel: nixpkgs pinned by revision,
# source pinned by digest, configuration stated rather than defaulted.
#
#   dinit     PID 1. Starts the services in `services/`, in the order their
#             dependencies give, and turns any of them ending into the guest
#             ending.
#   busybox   `mount` and `poweroff`, which dinit has no code for: it only ever
#             starts programs.
#
# Produces the binaries only. What PID 1 is TOLD to do differs per role — the
# storage role mounts a disk, the workers their memory controller — so the
# service files live beside this in `services/` and reach the image through
# `image/initramfs`, not through here.
#
#   nix-build image/init -A dinit
#   nix-build image/init -A busybox
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as image/kernel.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };

  # musl rather than glibc for both: a static glibc build of busybox's applets
  # comes out at 1.2 MB, the same thing against musl at 200 KB. Neither does
  # anything with memory that would make glibc's allocator worth it — the role
  # applications, which do, are glibc (see image/app).
  musl = pkgs.pkgsMusl;
  static = pkgs.pkgsStatic;
in
{
  # dinit, statically linked, with capability support — what lets a service
  # file say which capabilities a service keeps — and without the parts no
  # guest uses.
  #
  #   --default-auto-restart=never   a service that ends stays ended. dinit's own
  #                                  default restarts it, and every service here
  #                                  ending must end the guest instead.
  #   --disable-shutdown             its shutdown/poweroff programs: the guest is
  #                                  powered off by busybox's `poweroff -f`.
  #   --disable-cgroups              it places no service in a group; the workers
  #                                  build their own tree (engine-supervisor).
  #   --disable-utmpx                there is no login to record.
  #   --disable-strip                its install would call `strip` by that name,
  #                                  which this toolchain has under another; the
  #                                  build's own fixup strips the binaries anyway.
  #   --syscontrolsocket=/dinitctl   its control socket, which can load and start
  #                                  any service as full root, on the root
  #                                  filesystem rather than /run: `lockdown`
  #                                  takes every permission off it and then makes
  #                                  that filesystem read-only, so nothing without
  #                                  CAP_DAC_OVERRIDE can connect, nor give the
  #                                  permissions back. Under /run, which a tmpfs
  #                                  covers, a signal to PID 1 would have it bind
  #                                  a fresh one on that tmpfs.
  dinit = static.stdenv.mkDerivation {
    pname = "enclavid-guest-dinit";
    version = "0.22.0";

    src = pkgs.fetchFromGitHub {
      owner = "davmac314";
      repo = "dinit";
      rev = "v0.22.0";
      # The digest nixpkgs pins this release by, which is of the tree without
      # its BUILD file — removed there for case-insensitive filesystems.
      postFetch = ''
        [ -f "$out/BUILD" ] && rm "$out/BUILD"
      '';
      hash = "sha256-Axa993X17NdsNb+HwfzVzGGVTPVmdolNRxh3GfrpmBY=";
    };

    nativeBuildInputs = [ pkgs.m4 ];
    buildInputs = [ static.libcap ];

    configureFlags = [
      "--prefix=${placeholder "out"}"
      "--sbindir=${placeholder "out"}/bin"
      "--default-auto-restart=never"
      "--disable-shutdown"
      "--disable-cgroups"
      "--disable-utmpx"
      "--disable-strip"
      "--enable-capabilities"
      "--syscontrolsocket=/dinitctl"
      "LDFLAGS_LIBCAP=-lcap"
      "LDFLAGS_EXTRA=-static"
    ];

    enableParallelBuilding = true;
  };

  # The baseline here is `allnoconfig` rather than defconfig. For the kernel,
  # starting from a recognisable default and subtracting is the right trade —
  # the thing is too large to assemble from nothing. busybox is the opposite: it
  # is small enough to allowlist, and its default configuration is a toolbox
  # that has no business inside a CVM.
  busybox = musl.stdenv.mkDerivation rec {
    pname = "enclavid-guest-busybox";
    version = "1.38.0";

    src = pkgs.fetchurl {
      # busybox.net times out often enough to matter for a build that has to be
      # reproducible on someone else's machine; the digest makes any mirror safe.
      urls = [
        "https://busybox.net/downloads/busybox-${version}.tar.bz2"
        "https://www.busybox.net/downloads/busybox-${version}.tar.bz2"
      ];
      sha256 = "34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2";
    };

    # busybox reaches for kernel headers. The musl stdenv carries them, which is
    # the whole reason this is a derivation rather than the by-hand build it
    # replaces.
    nativeBuildInputs = [ pkgs.perl ];

    enableParallelBuilding = true;
    # busybox drives its own flags, and stdenv's hardening fights the static link.
    hardeningDisable = [ "all" ];

    configurePhase = ''
      runHook preConfigure
      make allnoconfig
      # Apply the fragment. Both forms matter: `CONFIG_X=y` and the negation
      # `# CONFIG_X is not set`. Treating the latter as a comment — the obvious
      # reading — silently drops every disable in the fragment, which is how a
      # shell ended up in the first build of this derivation.
      while read -r line; do
        case "$line" in
          "# CONFIG_"*" is not set")
            sym=''${line#\# }
            sym=''${sym%% is not set}
            ;;
          CONFIG_*=*)
            sym=''${line%%=*}
            ;;
          *) continue ;;
        esac
        sed -i "/^# $sym is not set\$/d; /^$sym=/d" .config
        echo "$line" >> .config
      done < ${./busybox.config}
      # busybox's kconfig only offers `oldconfig`, which is interactive, and it
      # errors out on EOF rather than taking defaults — so the empty lines have
      # to be fed to it. pipefail is off for exactly this line: when kconfig is
      # done it closes the pipe and `yes` dies of SIGPIPE, which is not a
      # failure.
      ( set +o pipefail; yes "" | make oldconfig >/dev/null )
      runHook postConfigure
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out
      cp busybox $out/busybox
      cp .config $out/config
      (cd $out && sha256sum busybox > busybox.sha256)
      runHook postInstall
    '';
  };
}
