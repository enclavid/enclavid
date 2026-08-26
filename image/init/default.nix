# Guest PID 1 — reproducible build.
#
# Lands in the initramfs, which QEMU hashes into the measured SEV-SNP launch, so
# like the kernel it has to be a function of its declared inputs and nothing
# else. Same shape as image/kernel: nixpkgs pinned by revision, source pinned by
# digest, configuration expressed as a fragment over an upstream baseline.
#
#   nix-build image/init
#   cat result/busybox.sha256
#
# The baseline here is `allnoconfig` rather than defconfig. For the kernel,
# starting from a recognisable default and subtracting is the right trade — the
# thing is too large to assemble from nothing. busybox is the opposite: it is
# small enough to allowlist, and its default configuration is a toolbox that has
# no business inside a CVM.
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as image/kernel.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };

  # musl rather than glibc: a static glibc build of these four applets comes out
  # at 1.2 MB, the same thing against musl at 200 KB. Nothing here needs glibc's
  # extras, and the difference is measured bytes in the image.
  musl = pkgs.pkgsMusl;

  version = "1.38.0";
in
musl.stdenv.mkDerivation {
  pname = "enclavid-guest-busybox";
  inherit version;

  src = pkgs.fetchurl {
    # busybox.net times out often enough to matter for a build that has to be
    # reproducible on someone else's machine; the digest makes any mirror safe.
    urls = [
      "https://busybox.net/downloads/busybox-${version}.tar.bz2"
      "https://www.busybox.net/downloads/busybox-${version}.tar.bz2"
    ];
    sha256 = "34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2";
  };

  # busybox reaches for kernel headers (init/init.c wants linux/vt.h). The musl
  # stdenv carries them, which is the whole reason this is a derivation rather
  # than the by-hand build it replaces.
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
    # errors out on EOF rather than taking defaults — so the empty lines have to
    # be fed to it. pipefail is off for exactly this line: when kconfig is done
    # it closes the pipe and `yes` dies of SIGPIPE, which is not a failure.
    ( set +o pipefail; yes "" | make oldconfig >/dev/null )
    runHook postConfigure
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp busybox $out/busybox
    cp .config $out/config
    cp ${./inittab} $out/inittab
    (cd $out && sha256sum busybox > busybox.sha256)
    runHook postInstall
  '';
}
