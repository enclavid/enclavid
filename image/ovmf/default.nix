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
# — and it carries the SEV secret-page components unconditionally.
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
in
pkgs.edk2.mkDerivation "OvmfPkg/AmdSev/AmdSevX64.dsc" {
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
  # the script take its early exit — and the file must exist regardless, because
  # `Grub.inf` declares it as a binary and its bytes land in the firmware.
  #
  # Empty is the right content, and not a shortcut: it is how the firmware this
  # fleet already boots was produced (Debian's `debian/rules` does the same
  # `touch` for its amdsev target), and the guests are booted with `-kernel` and
  # `kernel-hashes=on`, so the firmware verifies and starts the kernel itself
  # and never hands off to an embedded bootloader.
  postPatch = ''
    touch OvmfPkg/AmdSev/Grub/grub.efi
  '';

  # No `-D` flags. The distro build adds TPM2, CC measurement and three network
  # stacks; a guest that boots one measured kernel over vsock with no NIC uses
  # none of them, and each would be more measured firmware to account for. The
  # DSC's own defaults give the 4 MiB image (`FD_SIZE_IN_KB = 4096`) the
  # measurement tool expects.

  # `installPhase` moves `Build/*/*` to $out, so the flash image lands at
  # $out/FV/OVMF.fd. FV/ also holds MEMFD.fd, an artefact of the second `[FD.]`
  # section — the launch loads OVMF.fd and only OVMF.fd.
  postInstall = ''
    ( cd $out/FV && sha256sum OVMF.fd > OVMF.fd.sha256 )
  '';

  dontPatchELF = true;

  passthru.firmware = "OVMF.fd";
}
