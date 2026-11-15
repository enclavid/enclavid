# The host QEMU every image is launched under, as an overlay on the image pin:
# nixpkgs' own build, held at the release the Secure TSC series applies to as
# it stands, plus that series.
#
# QEMU is not something a guest trusts — a host can start a guest under any
# QEMU it likes. What QEMU decides is the launch, and the launch is measured: a
# guest started without Secure TSC has `sev_features` other than the ones
# `launch.guestFeatures` names, so its digest is not the one in the ID block and
# the firmware refuses it.
#
# The patches are upstream commits, applied unchanged: AMD's series that gives
# `sev-snp-guest` its `secure-tsc` and `tsc-frequency` properties, in QEMU's
# master since 2026-08-17 and in no release up to 11.1.2.
final: prev: {
  qemu_kvm = prev.qemu_kvm.overrideAttrs (finalAttrs: old: {
    version = "11.1.2";
    src = final.fetchurl {
      url = "https://download.qemu.org/qemu-${finalAttrs.version}.tar.xz";
      sha256 = "731b5681e4bb18be313231579b8efd0296c5b015fa36dc533874b639ba838016";
    };
    patches = old.patches ++ [
      ./0001-target-i386-SEV-Generalize-handling-of-SVM-SEV-FEAT-SNP-ACTIVE.patch
      ./0002-target-i386-SEV-Ensure-SEV-features-are-only-set-through-qemu-cli-or-IGVM.patch
      ./0003-target-i386-SEV-Consolidate-SEV-feature-validation-to-common-init-path.patch
      ./0004-target-i386-SEV-Validate-that-SEV-ES-is-enabled-when-VMSA-features-are-used.patch
      ./0005-target-i386-SEV-Enable-use-of-KVM-SEV-INIT2-for-SEV-ES-guests.patch
      ./0006-target-i386-SEV-Add-support-for-enabling-debug-swap-SEV-feature.patch
      ./0007-target-i386-SEV-Add-support-for-enabling-Secure-TSC-SEV-feature.patch
      ./0008-target-i386-SEV-Add-support-for-setting-TSC-frequency-for-Secure-TSC.patch
      ./0009-target-i386-SEV-Refactor-check-sev-features.patch
    ];
  });
}
