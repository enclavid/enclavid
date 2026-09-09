# Guest firmware — reproducible build.
#
# The first thing the measured SEV-SNP launch hashes, and until now the one input
# to it that came from outside this repository: a distro binary
# (`ovmf-amdsev_2025.11-3ubuntu8`), pinned by digest but not buildable from it.
# Pinning bytes says WHICH firmware; it does not say what that firmware is, and
# this one runs at VMPL 0 before the kernel, brings up the SNP page state and
# owns the secrets page. Every other measured input — kernel, busybox, the role
# binaries — is built from pinned source here. This makes the firmware the same.
#
#   nix-build image/ovmf
#   cat result/FV/OVMF.fd.sha256
#
# What that trades: not "no third party" — nixpkgs' edk2 carries its own patches
# — but one fewer distinct supply chain, and the remaining one is the chain
# everything else in the image already rests on.
#
# The AmdSev package, not the general OvmfPkgX64 one. It builds the variable
# store and the code into ONE flash image (`AmdSevX64.fdf`: "Build the variable
# store and the firmware code as one unified flash device image"), which is what
# a measured launch needs — there is no split CODE/VARS pair to leave unmeasured
# — and it carries the SEV secret-page components unconditionally. It is also
# the only OVMF platform that verifies the kernel against the SEV hash table at
# all: `OvmfPkgX64.dsc` resolves `BlobVerifierLibNull`.
#
# Built through `EnclavidFwPkg/EnclavidFw.dsc` rather than AmdSevX64.dsc
# directly. That file `!include`s AmdSevX64.dsc and overrides two things; read
# it for what and why. edk2 itself is stock — the package is reached through
# PACKAGES_PATH.
#
# WHEN BUMPING edk2, these are the files whose behaviour this image depends on
# and whose diffs are worth reading, in the order they matter:
#
#   OvmfPkg/Library/GenericQemuLoadImageLib/   the file NoShim* is derived from
#   OvmfPkg/QemuKernelLoaderFsDxe/            serves etc/boot/*, verifies 3 names
#   OvmfPkg/AmdSev/BlobVerifierLibSevHashes/  the SEV hash-table check itself
#   OvmfPkg/AmdSev/AmdSevX64.{dsc,fdf}        what this platform inherits
#
# That is ~44 commits across the three years to 202602, so the rate is readable.
# It is not a formality: the commit that introduced the shim path this build
# removes is called "GenericQemuLoadImageLib: support booting via shim", and the
# platform description did not change when it landed.
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
in
pkgs.edk2.mkDerivation "EnclavidFwPkg/EnclavidFw.dsc" {
  pname = "enclavid-ovmf-amdsev";
  version = pkgs.lib.getVersion pkgs.edk2;

  nativeBuildInputs = [ pkgs.util-linux pkgs.nasm pkgs.acpica-tools ];

  # edk2's build system compiles firmware, not host code; the stdenv hardening
  # flags do not apply and break it. Same set the nixpkgs OVMF packages disable.
  hardeningDisable = [ "format" "stackprotector" "pic" "fortify" ];

  # `postPatch`, not `prePatch`: `edk2.mkDerivation` defines its own `prePatch`
  # to link BaseTools in, and an attribute of the same name would replace it
  # rather than run beside it.
  #
  # The DSC declares `PREBUILD = sh OvmfPkg/AmdSev/Grub/grub.sh`, which asks
  # grub-mkimage for the `sevsecret` and `linuxefi` modules. Neither exists in
  # this nixpkgs' grub, so the prebuild would fail. An existing `grub.efi` makes
  # the script take its early exit, and `Grub.inf` declares the file as a binary
  # so it has to be there for the module to compile at all.
  #
  # Its bytes do not reach the image: `EnclavidFw.fdf` does not place Grub in
  # any volume. The empty file exists only to satisfy a prebuild and a module
  # that the inherited [Components] still names and nothing uses.
  #
  # `EnclavidFwPkg` is copied to the workspace root because that is where edk2
  # resolves a package-relative path from: `mkDerivation` sets WORKSPACE to $PWD
  # and passes the DSC path through unchanged. Copied rather than symlinked so
  # the build can write beside the sources.
  postPatch = ''
    touch OvmfPkg/AmdSev/Grub/grub.efi
    cp -r ${./EnclavidFwPkg} EnclavidFwPkg
    chmod -R u+w EnclavidFwPkg

    # Refuse to build against an edk2 this platform was not written for.
    #
    # The derived files under EnclavidFwPkg are static text. Without this, a
    # bump would silently keep serving logic derived from the previous release
    # — the one direction of failure that looks like success. `sha256sum -c`
    # names the file that moved; EnclavidFwPkg/upstream.sha256 says what to do.
    if ! sha256sum -c --quiet EnclavidFwPkg/upstream.sha256; then
      echo "" >&2
      echo "edk2 moved under this platform. The files above are the ones" >&2
      echo "EnclavidFwPkg is derived from or inherits. Read their diffs," >&2
      echo "re-derive, review, then update EnclavidFwPkg/upstream.sha256." >&2
      exit 1
    fi
  '';

  # Ask for the library report. It is the only place the build says which
  # instance it actually linked, and `postInstall` refuses the image if that is
  # not ours — see the note there.
  buildFlags = [ "-y" "build-report.txt" "-Y" "LIBRARY" ];

  # No `-D` flags. The distro build adds TPM2, CC measurement and three network
  # stacks; a guest that boots one measured kernel over vsock with no NIC uses
  # none of them, and each would be more measured firmware to account for. The
  # DSC's own defaults give the 4 MiB image (`FD_SIZE_IN_KB = 4096`) the
  # measurement tool expects.

  # `installPhase` moves `Build/*/*` to $out, so the flash image lands at
  # $out/FV/OVMF.fd. FV/ also holds MEMFD.fd, an artefact of the second `[FD.]`
  # section — the launch loads OVMF.fd and only OVMF.fd.
  #
  # Before that, refuse the image unless both substitutions actually took.
  #
  # This is not belt and braces. A `QemuLoadImageLib` line written in a less
  # specific scope than the one AmdSevX64.dsc already uses loses to it, and edk2
  # reports nothing: the build succeeds, the image boots, the shim path is back,
  # and the only difference is a line in a report nobody reads. An exit code
  # cannot tell the two builds apart, so the check has to name the instance —
  # and assert the absence of the upstream one, since finding ours somewhere in
  # a report would not prove it is what BdsDxe linked.
  #
  # The two substitutions need two different artefacts, and using the wrong one
  # passes vacuously. Library resolution is a BUILD fact, so it is in the build
  # report. Which driver serves the loader filesystem is a PLACEMENT fact, and
  # the upstream driver is still compiled — the inherited [Components] names it —
  # so it appears in the build report either way. `FV/DXEFV.inf` is the list of
  # what the volume actually received.
  postInstall = ''
    report=$(find . -name build-report.txt | head -1)
    if [ -z "$report" ]; then
      echo "no build report: cannot tell which QemuLoadImageLib was linked" >&2
      exit 1
    fi
    if ! grep -q NoShimQemuLoadImageLib "$report"; then
      echo "NoShimQemuLoadImageLib was not linked — the override did not apply" >&2
      exit 1
    fi
    if grep -q GenericQemuLoadImageLib "$report"; then
      echo "GenericQemuLoadImageLib is still linked — the shim path is present" >&2
      exit 1
    fi
    cp "$report" $out/build-report.txt

    dxefv=$out/FV/DXEFV.inf
    if ! grep -q QemuLoaderFs "$dxefv"; then
      echo "QemuLoaderFs is not in the DXE volume — the loader was not replaced" >&2
      exit 1
    fi
    if grep -q QemuKernelLoaderFsDxe "$dxefv"; then
      echo "QemuKernelLoaderFsDxe is in the DXE volume — the open name set is back" >&2
      exit 1
    fi

    # The firmware must have no way to read a disk. This is the whole of what
    # stops a host attaching a medium with \EFI\BOOT\BOOTX64.EFI on it and
    # having BdsDxe run it: measured on hardware, the untrimmed platform does
    # that whichever way PcdPlatformRecoverySupport is set. Since the control is
    # an absence, nothing about the build fails when it comes back — a module
    # returning to the FDF for an unrelated reason would restore the vector
    # silently. Hence naming it here.
    #
    # Any one of these breaks the chain block-io -> DiskIo -> Partition -> FAT,
    # and the three at the filesystem end are the ones worth leaning on: SdDxe
    # and SdMmcPciHcDxe are still in the volume, so "no block device driver" was
    # never true and enumerating every possible one would be a losing game.
    # Without DiskIo, Partition and Fat, a visible device is still not a
    # filesystem anything can be loaded from.
    #
    # Matched against the FFS directory name, which is the FILE_GUID and the
    # module's BASE_NAME concatenated with nothing between them. Two things that
    # look right and are not: `grep -w` never matches, because the character
    # before the name is a hex digit; and the GUID is upper case, so a
    # lower-case-only class matches nothing either. Both were written, both
    # passed every build, and both were caught only by putting a module back and
    # watching the check fail to fail.
    for m in VirtioBlk DiskIoDxe PartitionDxe Fat; do
      if grep -qE "Ffs/[0-9A-Fa-f-]+$m" "$dxefv"; then
        echo "$m is in the DXE volume — the firmware can read a host-attached" >&2
        echo "filesystem again, which is how \EFI\BOOT\BOOTX64.EFI gets run." >&2
        exit 1
      fi
    done

    ( cd $out/FV && sha256sum OVMF.fd > OVMF.fd.sha256 )
  '';

  dontPatchELF = true;

  passthru.firmware = "OVMF.fd";
}
