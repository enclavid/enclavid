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
| firmware | `ovmf-amdsev`, a distribution package | not in the pinned nixpkgs; see below |
| VMM | QEMU with SEV-SNP support | built from source on the host |
| the launch parameters | vCPU count and type, guest policy, `kernel-hashes` | had no home in the tree until this file |
| the measuring tool | `sev-snp-measure` | IS in the pinned nixpkgs as `sev-snp-measure`, unused so far |

The first three are the gap. A measurement is a function of all of them, so a
digest computed against a different firmware build, a different vCPU count or a
launch that forgot `kernel-hashes=on` is a digest of a different machine — and
nothing today would notice.

### Firmware

Observed: `ovmf-amdsev_2025.11-3ubuntu8_all.deb`, unpacked, yielding a single
combined flash image. There is no separate variables file and none is measured.

```text
OVMF.amdsev.fd
sha256  6f5c36ddf2eb56052df7adbb0fd32bd7997cc2a706573e33fbd8a4d7918d438d
```

`README.md` says the firmware is verified by "package version + digest". That
line is now true of this file and of nothing else in the tree: until the
firmware becomes a pinned derivation, the digest above is the only thing
standing between a rebuild and a silently different measurement.

### VMM

Observed: QEMU 10.2.4, built from source. The version matters to a measurement
only through the VMSA it constructs, but it matters to whether the guest boots
at all — `sev-snp-guest`, `kernel-hashes` and `vhost-vsock-pci` all have to be
present.

## Building the images

Three derivations, one per measurement input that this repository does own.

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

Transcribed from a launcher that boots the whole fleet:

```sh
qemu-system-x86_64 \
  -enable-kvm -cpu EPYC-Milan-v2 -smp 2 -m $MEM \
  -machine q35,confidential-guest-support=sev0,memory-backend=ram0 \
  -object memory-backend-memfd,id=ram0,size=$MEM,share=true,prealloc=false \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=0x30000 \
  -device vhost-vsock-pci,guest-cid=$CID \
  -bios /path/to/OVMF.amdsev.fd \
  -kernel $BZIMAGE -initrd $INITRAMFS -append "$(cat image/cmdline/$ROLE/$VARIANT)" \
  -nographic -no-reboot -display none -serial file:$LOG
```

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

`HATCH_AUTH=none` is the dev posture. A dev api additionally needs
`ENCLAVID_TEE_KEY=<64 hex chars>` appended to its command line, because outside
`sev-snp` the sealing key is not derived from the chip.

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

## What cannot be booted yet

A `production` fleet does not come up, and the reason is in the crates rather
than in anything here. The three leaves build their RA-TLS acceptor with
`MockAttestor::dev_fleet()` unconditionally — their manifests take
`enclavid-attestation` with `default-features = false, features = ["mock"]`, and
none of the three has a `sev-snp` feature to enable. api built with `sev-snp`
mints a real report, and the mock backend rejects anything whose format is not
its own, before a measurement is ever compared.

So the fleet handshake fails in both directions, and it fails on the format
discriminator rather than on any policy. Two things follow for anyone running
this: `cmdline/<role>/production` is only half a production posture today, and
the `debug` path is the one that works end to end.

It also means the leaves' identity is currently a signing key that is a literal
in this repository, and that they accept anyone holding it. That is fine for a
dev fleet and is why the key is confined to a backend named `mock` — but the
image builds ship that backend, so the confinement does not currently hold where
it matters.

## Computing a measurement

```sh
sev-snp-measure --mode snp \
  --vcpus $N --vcpu-type EPYC-Milan-v2 \
  --ovmf  /path/to/OVMF.amdsev.fd \
  --kernel $BZIMAGE --initrd $INITRAMFS \
  --append "$(cat image/cmdline/$ROLE/$VARIANT)"
```

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
