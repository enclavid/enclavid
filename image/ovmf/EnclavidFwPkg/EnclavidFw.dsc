## @file
#  The firmware this fleet launches: AmdSevX64, with the two ways a host can
#  reach code execution under an unchanged launch measurement taken away.
#
#  A platform description, not a patch. `!include` pulls in AmdSevX64.dsc
#  verbatim from the pinned edk2 and the sections below override it; edk2's own
#  tree is untouched, and this package is found through PACKAGES_PATH. What that
#  buys is an upgrade path: bumping edk2 is a bump, not a rebased patch.
#
#  WHAT IT CHANGES, and why each one:
#
#  1. QemuLoadImageLib -> NoShimQemuLoadImageLib. Upstream loads a host-named
#     "shim" blob ahead of the kernel. Reproduced on SNP hardware: the injected
#     blob ran, the measured kernel did not, and the launch digest read back from
#     the PSP was byte-identical. See the library's own file header.
#
#  There is NO PCD here for the second way a host reaches code execution —
#  attaching a disk with \EFI\BOOT\BOOTX64.EFI on it and giving the guest no
#  measured payload, at which point BdsDxe runs what is on the disk. That is
#  deliberate and was measured rather than reasoned:
#
#    untrimmed firmware, PcdPlatformRecoverySupport|FALSE   host's code ran
#    untrimmed firmware, PcdPlatformRecoverySupport|TRUE    host's code ran
#
#  The knob that looks like it governs this does not. BdsEntry.c:1128-1141 takes
#  an `else` when it is FALSE, and the else still reaches for the same path —
#  upstream says so in a comment. PcdBootRestrictToFirmware|FALSE makes no
#  difference either. What stops it is that this platform's FDF carries no way
#  to read a disk, which `image/ovmf/default.nix` asserts rather than assumes.
#
#  WHAT IT DOES NOT CHANGE: the loader filesystem still fetches every blob the
#  host names under fw_cfg's etc/boot/, and QemuKernelVerifyBlob still waves
#  through any name outside kernel/initrd/cmdline. Nothing references those
#  blobs any more, so they are inert — but inert is a property of this
#  reachability argument rather than of the code, which is why the fetch side is
#  worth closing separately.
#
#  Copyright (c) 2026, Enclavid<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  SUPPORTED_ARCHITECTURES        = X64

!include OvmfPkg/AmdSev/AmdSevX64.dsc

# The image contents come from our own copy of the flash description. AmdSevX64
# names its own in the [Defines] the include above brings, so this has to come
# after it, and it has to win.
[Defines]
  FLASH_DEFINITION               = EnclavidFwPkg/EnclavidFw.fdf

# DXE_DRIVER, not plain [LibraryClasses]: this class is linked into BdsDxe, and
# AmdSevX64.dsc resolves it in exactly this scope. A less specific block loses to
# the more specific one already present, builds without complaint, and silently
# leaves the upstream implementation in place — which looks identical from the
# outside and is the whole hole. `image/ovmf/default.nix` greps the build report
# for the instance that was actually linked rather than trusting the exit code.
[LibraryClasses.common.DXE_DRIVER]
  QemuLoadImageLib|EnclavidFwPkg/Library/NoShimQemuLoadImageLib/NoShimQemuLoadImageLib.inf

# Built here so the FDF above can place it; the inherited [Components] still
# names the upstream driver, which is built and then not placed anywhere.
#
# The NULL library is where VerifyBlob comes from. It is not in the driver's
# .inf — upstream attaches it per-component in exactly this shape — so a copy of
# the .inf alone links against nothing and fails on an undefined reference. This
# is the instance that halts the machine on a name it cannot check, which is the
# behaviour the loader's own name set now makes unreachable rather than relies on.
[Components]
  EnclavidFwPkg/Driver/QemuLoaderFs/QemuLoaderFs.inf {
    <LibraryClasses>
      NULL|OvmfPkg/AmdSev/BlobVerifierLibSevHashes/BlobVerifierLibSevHashes.inf
  }

