# Guest kernel — reproducible build, one derivation per role.
#
# The bzImage this produces is one of the inputs QEMU hashes into the measured
# SEV-SNP launch, so it has to be a function of its declared inputs and nothing
# else. Everything that could vary is pinned here: the compiler and every build
# tool (via a nixpkgs revision), the kernel source (by digest), and the three
# build variables the kernel embeds into the image.
#
#   nix-build image/kernel -A diskless   # api, executor, compiler, gateway
#   nix-build image/kernel -A storage    # the storage CVM
#   cat result/bzImage.sha256
#
# A reviewer verifies a published measurement by running exactly that and
# comparing digests. Note this pins nixpkgs by REVISION rather than using
# `<nixpkgs>`, which would resolve to whatever channel the builder happens to
# have configured and quietly make the result builder-dependent.
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./kernel_version.txt);

  # `role` selects the fragment layered over common.config. The two differ only
  # in whether the kernel can reach storage at all.
  kernelFor = role: pkgs.stdenv.mkDerivation {
    pname = "enclavid-guest-kernel-${role}";
    inherit version;

    src = pkgs.fetchurl {
      url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${version}.tar.xz";
      sha256 = "eb36801e119529b13513c3459dc20e2a32f7053629f3aabb63ea501a4d88f63d";
    };

    nativeBuildInputs = with pkgs; [ bc bison flex elfutils openssl perl python3 ];

    # The kernel manages its own hardening flags; stdenv's would fight them.
    hardeningDisable = [ "all" ];
    enableParallelBuilding = true;

    # Known property, deliberately left alone: the vDSO is a genuine shared
    # object, so stdenv's linker wrapper stamps a self-rpath ($out/lib) into its
    # .dynstr, and the kernel embeds the vDSO verbatim. The image therefore
    # depends on this derivation's own output path — renaming a role or a config
    # fragment changes every byte of the bzImage even when the effective .config
    # is identical. It does NOT weaken third-party verification: the same
    # expression yields the same derivation, the same output path and the same
    # bytes, which is what `nix-build --check` confirms. Suppressing the rpath
    # wholesale (NIX_DONT_SET_RPATH_*) is not a fix — it strips the rpath from
    # the host tools too, and objtool then cannot find libelf. Doing it only for
    # the vDSO link would take a patch to the kernel's own Makefile.

    # https://docs.kernel.org/kbuild/reproducible-builds.html
    # The timestamp is pinned to this kernel version's upstream release date, so
    # it moves only when kernel_version.txt moves.
    KBUILD_BUILD_USER = "user";
    KBUILD_BUILD_HOST = "host";
    KBUILD_BUILD_TIMESTAMP = "Sat Aug 23 00:00:00 UTC 2026";

    configurePhase = ''
      runHook preConfigure
      make defconfig
      ./scripts/kconfig/merge_config.sh -m .config \
        ${./common.config} ${./. + "/${role}.config"}
      make olddefconfig
      runHook postConfigure
    '';

    buildPhase = ''
      runHook preBuild
      make -j$NIX_BUILD_CORES bzImage
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out
      cp arch/x86/boot/bzImage $out/bzImage
      cp .config $out/config
      (cd $out && sha256sum bzImage > bzImage.sha256)
      runHook postInstall
    '';
  };
in
{
  diskless = kernelFor "diskless";
  storage = kernelFor "storage";
}
