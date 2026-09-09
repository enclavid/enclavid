# Guest firmware

The first thing a SEV-SNP launch hashes, built from source here rather than
taken as a binary, and built as **our own platform** rather than as upstream's.

## Why a platform of our own

A host can add `-shim evil.efi` to the launch — or the same thing spelled
`-fw_cfg name=etc/boot/shim,file=evil.efi`, which needs no special QEMU support.
Upstream's `AmdSevX64` firmware then runs that binary **instead of** the measured
kernel, and the launch digest does not move.

Reproduced on this fleet's hardware, reading the real report out of the guest
rather than recomputing it with `sev-snp-measure`:

| launch | kernel that ran | measurement |
|---|---|---|
| `-kernel storage` | storage | `2fab1605…` |
| `-kernel diskless` | diskless | `4e26fdcc…` |
| `-kernel storage -shim diskless` | **diskless** | `2fab1605…` |

The middle row is why the third matters: the kernel really is part of the
digest, and the shim path substitutes it anyway. A payload booted that way
derives the same `tee_seal_key` and is accepted by peers under the same pin —
demonstrated end to end by sealing a secret in one launch and recovering it in
another that ran different code under the same measurement.

Two edk2 behaviours combine to allow it. `QemuKernelLoaderFsDxe` builds a blob
from **any** fw_cfg file named under `etc/boot/`, taking the name from the host,
and fetches its contents before anything inspects the name. Then
`QemuKernelVerifyBlob` returns `EFI_SUCCESS` for every name outside
`kernel`/`initrd`/`cmdline`, so `BlobVerifierLibSevHashes` — which halts the
machine on a name it cannot check — is never asked. The SEV hash table covers
those three names, so anything else arrives measured by nobody.

Upstream's own docs say `-shim` presupposes a firmware with Secure Boot enabled.
`AmdSevX64` has none: `AuthVariableLibNull` unconditionally, no
`DxeImageVerificationLib`, and no `SECURE_BOOT_ENABLE` anywhere in its include
chain. The mechanism is used without checking its precondition, on the one
platform that cannot satisfy it.

## What the platform changes

`EnclavidFwPkg/EnclavidFw.dsc` `!include`s `OvmfPkg/AmdSev/AmdSevX64.dsc` and
overrides it. edk2 itself is stock and pinned; nothing under `OvmfPkg` is
patched. `EnclavidFw.fdf` is a copy of `AmdSevX64.fdf`, because neither DSC nor
FDF has a directive that removes an entry — leaving a module out means owning
the list.

| | what | effect |
|---|---|---|
| `Library/NoShimQemuLoadImageLib` | the shim device path is gone | nothing names a shim, so there is nothing to load |
| `Driver/QemuLoaderFs` | the name set is a compile-time constant, and the verifier refuses what it cannot check | an unknown name never becomes a blob |
| `PcdPlatformRecoverySupport\|FALSE` | — | a failed launch reaches for one built-in path rather than every registered recovery option |

The first two are separate answers to the same question on purpose. Deleting the
shim device path makes the injected blob unreferenced; closing the name set
makes it non-existent. The first depends on an argument that nothing else
reaches the blob, and that kind of argument is what failed twice here already.

Both `.c` files are **derived from upstream by script**, not rewritten. The diff
against the upstream file is small enough to read, and reading it is the review.

## The trim

95 modules become 52: USB, graphics and the setup-browser chain, ATA/SCSI/NVMe,
PS/2, S3 suspend, and every way the firmware could read a block device — Linux
brings its own virtio-blk driver and its own filesystem.

None of those is on the path from reset to the measured kernel — and one of them
turns out to be the only thing closing a second vector, which is worth stating
because the opposite was assumed first.

**The devices a guest is started with are chosen by the host and are not part of
the measurement.** Attach a disk with a FAT partition holding
`\EFI\BOOT\BOOTX64.EFI`, give the guest no measured payload, and BdsDxe runs
what is on it. Measured on this hardware with a payload that announces itself
(a kernel with `console=ttyS0` compiled in, so "did not run" and "ran silently"
are distinguishable):

| firmware | host's code ran |
|---|---|
| before the trim | **yes** |
| after the trim | no |
| after the trim, `PcdBootRestrictToFirmware\|FALSE` | no |

Both builds already had `PcdPlatformRecoverySupport|FALSE`, so neither PCD is
what stops it — see the note in `EnclavidFw.dsc` for why the one that looks like
it should does not. What stops it is that `VirtioBlk`, `PartitionDxe`,
`DiskIoDxe` and `Fat` are gone: nothing can see the device, read its partition
table, or open a filesystem on it. Structural rather than policy, which is the
only kind of answer that does not rest on an argument about reachability.

Two look removable and are not, both found by trying: `CapsuleRuntimeDxe`
(without it the guest takes `#UD` during BDS and never reaches the kernel) and
`HiiDatabaseDxe`. Neither failure is a build failure, which is why the list was
arrived at by removing a category at a time and booting after each.

## What keeps it honest

Three checks, because each covers a different way this could silently stop
working, and an exit code distinguishes none of them.

- **`EnclavidFwPkg/upstream.sha256`** — the derived files are static text, so a
  bumped edk2 would otherwise leave them serving the previous release's logic,
  including through a security fix. `sha256sum -c` names the file that moved.
- **the build report** — a `QemuLoadImageLib` line written in a less specific
  scope than the one `AmdSevX64.dsc` already uses loses to it, builds without
  complaint, and leaves upstream's implementation in place.
- **`FV/DXEFV.inf`** — which driver serves the loader filesystem is a placement
  fact. Upstream's driver is still compiled, because the inherited
  `[Components]` names it, so the build report shows it either way.

## What this does not do

It adds no Secure Boot and does not sign anything. `initrd` and `cmdline` are
bound to the measurement by `kernel-hashes=on` and by nothing else, which is why
that flag is set from the same expression as the measurement — see
`image/default.nix`.

## When bumping edk2

`upstream.sha256` will fail. Read the diffs of the files it names, re-derive,
review that diff, then update the hashes. Updating the number without reading is
how the review stops happening — the commit that introduced the shim path is
called `GenericQemuLoadImageLib: support booting via shim`, and the platform
description did not change when it landed.
