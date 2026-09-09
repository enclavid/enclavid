# Running the fleet

`README.md` next door says what goes into a measurement. This says what it takes
to actually start these images and get a measurement out of them.

It exists because none of that was written down anywhere a clone could reach.
`docs/` is gitignored, so the working knowledge — the launch line, the firmware
build, the ordering — lived on one machine as a set of shell scripts, and every
session that needed it rediscovered it. What follows was recovered from a
machine where the fleet does boot; where a value is transcribed from something
that ran, it is marked as such, and where it is derived from the expressions in
this directory rather than observed, that is marked too.

## Four things a launch needs that this repository does not contain

| | what | why it is not here |
|---|---|---|
| VMM | QEMU with SEV-SNP support | built from source on the host |

That is the whole of it now. The firmware, the launch parameters and the
measuring tool were on this list and are not any more: `image/ovmf` builds the
AmdSev firmware from the pinned edk2, `image/default.nix` holds the launch
parameters and calls `sev-snp-measure` from the pinned nixpkgs.

QEMU stays outside because it does not enter the digest — it constructs the
VMSA, but what it constructs is a function of the parameters, not of its own
version. It matters to whether the guest boots at all: `sev-snp-guest`,
`kernel-hashes` and `vhost-vsock-pci` all have to be present. Observed: 10.2.4,
built from source.

### Firmware

`nix-build image/ovmf` — our own edk2 platform, built from AmdSevX64 out of the
pinned nixpkgs: one combined flash image, no separate variables file, the loader
replaced and 43 modules left out. `image/ovmf/README.md` says what was taken
away and why, and it is worth reading before touching this — two of the removals
are the only thing stopping a host running its own code under our digest.

The distro binary this replaces was `ovmf-amdsev_2025.11-3ubuntu8`, sha256
`6f5c36dd…438d`. Recorded because every measurement taken before this change was
taken against it, and none of them carry over.

### VMM

Observed: QEMU 10.2.4, built from source. The version matters to a measurement
only through the VMSA it constructs, but it matters to whether the guest boots
at all — `sev-snp-guest`, `kernel-hashes` and `vhost-vsock-pci` all have to be
present.

## Building the images

`nix-build image -A images.<role>` does all of the below and gets the ordering
right. What follows is the individual pieces, for when one of them is what you
are working on.

```sh
nix-build image/kernel -A diskless        # api, both workers
nix-build image/kernel -A storage         # the one role with a disk
nix-build image/app    -A api             # and -A storage, -A compile-worker,
                                          # -A execution-worker; each has a
                                          # `-debug` twin
```

The initramfs is a function rather than an attribute set, because what it wraps
differs per role. The two workers must be given their child binary as a
`sibling`, because a worker resolves it next to its own executable; storage
needs `/data` as a mount point, because its inittab mounts `/dev/vda` there.

```sh
A='(import ./image/app)'

nix-build image/initramfs -o irfs-storage \
  --arg app "$A.storage + \"/storage-cvm\"" \
  --arg inittab ./image/init/inittab/storage \
  --argstr name storage \
  --arg dirs '[ "data" ]'

nix-build image/initramfs -o irfs-execution-worker \
  --arg app "$A.\"execution-worker\" + \"/execution-worker\"" \
  --arg inittab ./image/init/inittab/execution-worker \
  --argstr name execution-worker \
  --arg siblings "{ engine-executor-child = $A.\"execution-worker\" + \"/engine-executor-child\"; }"
```

…and the same shape for `compile-worker` with `engine-compiler-child`.

**Pass the derivation, not a path.** Writing
`--arg app /nix/store/…-enclavid-app-storage/storage-cvm` looks equivalent and
is not: nix copies that file in as a fresh store object with no link to the
derivation that produced it, so it is not an input, and the build fails inside
the sandbox with `install: cannot stat`. Interpolating the derivation
(`$A.storage + "/…"`) produces a string that carries its dependency, which is
also what makes the build graph say what it means.

The kernel and the app are what change most often. Note that a role's binaries
are built by **one cargo invocation per package** — `app/default.nix` explains
why at length, and the short version is that a shared invocation would unify
cargo features across a worker and the child that runs untrusted wasm.

## The launch

Every flag the measurement depends on comes out of the image, and none of them
is written here. That is the point: this file used to transcribe them, and a
transcription is a second copy of something that has to agree with the first.

```sh
I=$(nix-build image -A images.$ROLE --arg idKeys $KEYS --no-out-link)

qemu-system-x86_64 -enable-kvm \
  $(cat $I/qemu-args | tr '\n' ' ') \
  -kernel $I/bzImage -initrd $I/initramfs.cpio.gz -append "$(cat $I/cmdline)" \
  -m $MEM -object memory-backend-memfd,id=ram0,size=$MEM,share=true,prealloc=false \
  -device vhost-vsock-pci,guest-cid=$CID \
  -nographic -no-reboot -display none -serial file:$LOG
```

`qemu-args` holds `-cpu`, `-smp`, `-machine`, `-bios` and the `sev-snp-guest`
object — including the ID block, which is why `idKeys` is not optional. The
second line is what the digest does not cover and an operator has to choose:
memory size, the vsock CID, any drive, where the serial goes.

What each measurement-relevant part is doing:

- **`kernel-hashes=on`** — without it the kernel, the initramfs and the command
  line contribute **nothing** to the launch digest. QEMU's default for this
  property is off, so three of the five inputs `README.md` calls pinned are only
  pinned because this flag is here.
- **`-cpu EPYC-Milan-v2` and `-smp N`** — the VMSA pages are measured, one per
  vCPU, so both the type and the count enter the digest. See the open question
  below.
- **`policy=0x30000`** — bits 16 and 17. Bit 17 is reserved and must be set; bit
  16 is `SMT_ALLOWED`, so this guest agrees to run on a host with SMT enabled.
  Debug (bit 19) and migration-agent (bit 18) are clear, which is what
  `crates/attestation/src/snp.rs` requires of a peer. The policy is a signed
  field of every report, so it is a security constant that currently lives
  nowhere but a command line.
- **`-m`** — memory size is *not* a measurement input. Roles may differ freely;
  observed 2G for storage and 3G for the rest.

`-serial file:` is where a role's log device lands. Under
`cmdline/<role>/production` the application writes to `/dev/ttyS0` with the
kernel console off; under `debug` the kernel console shares the port.

## Order, and how to tell it worked

vsock addresses guest↔host only, so a guest cannot dial another guest. Every
fleet leg is two hops through a host-side relay, which means the relays must
exist before the guest that dials through them is useful.

1. Start the three leaves. Each answers `{"healthy":false}` on its health port
   from the moment it binds, and `{"healthy":true}` once it is listening.
2. Start one relay per leg and the hatch.
3. Start api. It dials all three legs before it binds either serving port, and
   it waits without a bound — so a leg that never comes up shows as an api that
   never becomes ready, not as one that exits.

```sh
host-relay --listen vsock:8001 --to vsock:$STORAGE_CID:8001
host-relay --listen vsock:8002 --to vsock:$COMPILE_CID:8002
host-relay --listen vsock:8003 --to vsock:$EXEC_CID:8003

HATCH_LISTEN_ADDR=8000 HATCH_AUTH=none HATCH_AUTH_PRINCIPAL=guest host-hatch
```

`HATCH_AUTH=none` is the dev posture. Outside `sev-snp` a dev api also needs
`ENCLAVID_TEE_KEY=<64 hex chars>`, because the sealing key is then not derived
from the chip — but it has to be IN the cmdline file, not appended at launch, or
the guest's measurement stops matching what was computed for it.

### The health ports

The host reads these; nothing else does. They are on the measured command line
like every other port, and `README.md`'s port table does not yet list them.

| port | role |
|---|---|
| 8445 | api |
| 8011 | storage |
| 8012 | compile-worker |
| 8013 | execution-worker |

`connect`, read to EOF, send nothing — the port never reads, and a prober that
speaks first can have its own answer reset away. api's answer carries its fleet
peers and the hatch alongside its own bool; a leaf's is the bool alone. Whether
any of that means *ready* is the reader's conclusion, not the guest's claim —
`crates/fleet-transport/src/health.rs` argues the split.

## Building and booting a fleet

    nix-build image -A measurements.storage    # the launch digest, needs no keys
    nix-build image -A images.storage --arg idKeys $KEYS   # + cmdline + qemu-args
    nix-build image -A images.api    --arg idKeys $KEYS    # pinned to the three leaves

`idKeys` is a directory of `id.pem` and `author.pem` (EC P-384). Anything that
writes a launch line needs them, because the line carries an ID block asserting
its own digest; `measurements.*` does not.

`image/default.nix` is where a build starts. It owns the ordering api's
`endorsement.rs` depends on — the three leaves are built and measured, then api
is built from their digests — and it generates the launch flags and the digest
from ONE set of parameters, so the two cannot disagree.

Each image carries a `qemu-args` file with the flags the measurement covers.
Splice it in verbatim and add only what the digest does not describe: memory,
the vsock CID, any drive, where the serial goes.

    I=$(nix-build image -A images.storage-debug --no-out-link)
    qemu-system-x86_64 -enable-kvm $(cat $I/qemu-args | tr '\n' ' ') \
      -m 2G -object memory-backend-memfd,id=ram0,size=2G,share=true,prealloc=false \
      -device vhost-vsock-pci,guest-cid=4 \
      -drive file=storage.img,if=virtio,format=raw \
      -kernel $I/bzImage -initrd $I/initramfs.cpio.gz -append "$(cat $I/cmdline)" \
      -nographic -no-reboot -display none -serial file:/tmp/storage.log

**`-append` must be the cmdline file and nothing else.** The command line is
measured byte for byte. Appending one variable at launch — the bench scripts used
to add `ENCLAVID_TEE_KEY` — produces a guest whose measurement nothing pins, and
the only symptom is api refusing every peer. Under `sev-snp` the seal key comes
from the chip, so that variable is not needed and must not be added.

Production and debug are separate fleets end to end: `api-debug` pins the three
`*-debug` leaves, `api` pins the three production ones. Mixing them is a refused
handshake, correctly.

## What this has been shown to do

On a Milan bench, the four debug images built by the expressions above boot on
the self-built firmware, and api's log says `storage-CVM connected` with no
`not pinned` line — meaning the digest nix computed equals the one the AMD
Secure Processor put in the guest's report. The same run with `ENCLAVID_TEE_KEY`
appended to `-append` refuses, which is what makes the first result mean
something.

## Computing a measurement

```sh
sev-snp-measure --mode snp \
  --vcpus $N --vcpu-type EPYC-Milan-v2 \
  --ovmf   $(nix-build image -A ovmf --no-out-link)/FV/OVMF.fd \
  --kernel $I/bzImage --initrd $I/initramfs.cpio.gz \
  --append "$(cat $I/cmdline)"
```

Shown for reading rather than for running: `measurements.<role>` does exactly
this from the same expression the launch line comes from, which is the only way
the two are known to agree.

Every argument must match the launch exactly, and `--append` especially: the
command line is taken verbatim, so a stray space is a different machine.

`--guest-features` defaults to `0x1` in the tool. If the launch ever enables
anything beyond `SNPActive` — `debug-swap`, say — this has to move with it.

## Open: does the vCPU count have to be pinned?

Measured on a real build, same everything except `--vcpus`:

```text
2  2b94903ec462f659e7770d70d5ec7d2197ea2c59ce657eaf998a4ffd16075c38…
4  557ee63a2b4da379fb6566777c8262c0e8bc9efb9e399fd273f1e6908527d479…
8  0d33f912dc74d68ce75f8cd2d1410cd74def7b0ae4f534cd68c5d69d62dfeddf…
```

So the count is an input, and a fleet that pins measurements freezes it.

There is a way that might not bite, and it is worth settling rather than
remembering. QEMU builds a VMSA for every **possible** vCPU, so `-smp N,maxcpus=M`
should produce a digest that depends on `M` and not on `N` — set `maxcpus` once
with headroom, vary the booted count freely, and pass `M` to `--vcpus`. The
launchers observed here pass a bare `-smp` with no `maxcpus`, so nothing today
uses that, and they disagree with each other: six pass 2 and two pass 4, while
the one recorded `sev-snp-measure` run used 4.

**The experiment that settles it:** boot with `-smp 2,maxcpus=8`, have the guest
mint a report, and compare its measurement against `--vcpus 8` and `--vcpus 2`.
Whichever matches is the rule. Write the answer here.

## Known drift

- The launch parameters above exist only as shell scripts on one machine. Until
  the command line and the `sev-snp-measure` call are generated from one source
  in this repository, "measured with 4, booted with 2" is a mistake nothing
  catches — and it has already happened.
- `initramfs/default.nix` says "the Rust build is not yet expressed in Nix".
  It is: that is what `app/default.nix` does.
- `README.md` lists a gateway among the roles using the diskless kernel. There
  is no gateway — no cmdline, no inittab, no attribute.
- Images built before the disposable-child crates were split carry a
  `session-child` sibling. A worker initramfs holding that name is stale.
