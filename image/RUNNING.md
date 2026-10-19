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

## What a launch needs that this repository does not contain

Nothing is left on this list. The firmware, the launch parameters, the measuring
tool and the VMM were on it and are not any more: `image/ovmf` builds the AmdSev
firmware from the pinned edk2, `image/default.nix` holds the launch parameters
and calls `sev-snp-measure` from the pinned nixpkgs, and `image/qemu` is the
QEMU the images are launched under.

QEMU does not enter the digest — it constructs the VMSA, but what it constructs
is a function of the parameters, not of its own version. It is pinned all the
same, because whether the guest boots at all depends on it: `sev-snp-guest`,
`kernel-hashes`, `secure-tsc` and `vhost-vsock-pci` all have to be present, and
`secure-tsc` is in no QEMU release up to 11.1.2.

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

`image/qemu`: QEMU 11.1.2 from the pinned nixpkgs' recipe, plus AMD's Secure TSC
series — nine upstream commits, applied unchanged. The version matters to a
measurement only through the VMSA it constructs, but it matters to whether the
guest boots at all — `sev-snp-guest`, `kernel-hashes`, `secure-tsc` and
`vhost-vsock-pci` all have to be present.

The patches go with QEMU 11.2, the first release to carry the series: moving
`image/qemu` to it leaves a version and a hash, and the nine files are deleted.

## Building the images

`nix-build image -A images.<role>` does all of the below and gets the ordering
right. What follows is the individual pieces, for when one of them is what you
are working on.

```sh
nix-build image/kernel -A base              # api, the gateway
nix-build image/kernel -A compile-worker    # diskless + the memory controller
nix-build image/kernel -A execution-worker  # diskless + the memory controller
nix-build image/kernel -A storage           # the one role with a disk
nix-build image/app    -A api             # and -A storage, -A compile-worker,
                                          # -A execution-worker; each has a
                                          # `-debug` twin
```

The initramfs is a function rather than an attribute set, because what it wraps
differs per role. Every role takes the clock keeper and its services — the
`common` ones and its own. The two workers must be given their child binary as
a `sibling`, because a worker resolves it next to its own executable; storage
needs `/data` as a mount point, because its `data` service mounts `/dev/vda`
there.

```sh
A='(import ./image/app)'

nix-build image/initramfs -o irfs-storage \
  --arg app "$A.storage + \"/storage-cvm\"" \
  --arg timesync "$A.timesync + \"/timesync\"" \
  --arg services '[ ./image/init/services/common ./image/init/services/storage ]' \
  --argstr name storage \
  --arg dirs '[ "data" ]'

nix-build image/initramfs -o irfs-execution-worker \
  --arg app "$A.\"execution-worker\" + \"/execution-worker\"" \
  --arg timesync "$A.timesync + \"/timesync\"" \
  --arg services '[ ./image/init/services/common ./image/init/services/execution-worker ]' \
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

## Checking the gateway's attested build

A workspace build on a developer machine is the TCP build with software
attestation. The gateway image carries another, `vsock` with `sev-snp`, and
building an image fails on no warning. So check that build on a Linux machine
with a C toolchain — `ring` compiles C, so it is not cross-built from elsewhere:

```sh
# Every combination the gateway accepts, warnings as errors, tests included.
for f in "" "--features vsock" \
         "--no-default-features --features vsock,sev-snp" \
         "--no-default-features --features vsock,sev-snp,debug"; do
  cargo clippy -p enclavid-gateway $f --all-targets -- -D warnings
done

# The tests that open no socket, on the vsock transport. The `sev-snp` build's
# tests are compiled above and not run: its attestor opens /dev/sev-guest.
cargo test -p enclavid-gateway --features vsock
```

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

api is also told, at launch, the host port each of its legs dials — one fw_cfg
entry for each of its four peers, outside the measurement
(`crates/api/src/fleet/legs.rs`):

```sh
  -fw_cfg name=opt/com.enclavid/storage-port,string=8001 \
  -fw_cfg name=opt/com.enclavid/compile-worker-port,string=8002 \
  -fw_cfg name=opt/com.enclavid/execution-worker-port,string=8003 \
  -fw_cfg name=opt/com.enclavid/hatch-port,string=8004 \
```

An api launched without them says which one is missing and stops.

The hatch is the one role launched with a network interface, carried over a
unix socket to a [passt](https://passt.top) on the host, which opens the
connections the guest opens and takes none in. QEMU dials it until it answers,
and again whenever it goes:

```sh
passt --foreground --socket $SOCK --ipv4-only --no-icmp \
  --tcp-ports none --udp-ports none \
  --address 10.0.2.15 --netmask 24 --gateway 10.0.2.2 \
  --map-host-loopback none --map-guest-addr none --search none \
  --dns-forward 10.0.2.3

# and on the hatch's QEMU line
  -netdev stream,id=nic,server=off,addr.type=unix,addr.path=$SOCK,reconnect-ms=1000 \
  -device virtio-net-pci,netdev=nic \
```

The kernel takes its address from passt's DHCP answer before PID 1 runs
(`ip=dhcp` on its command line). Its resolver is the image's own: 10.0.2.3,
which `--dns-forward` carries on the DNS ports, and nothing else, to the host's
own resolver, the first in its /etc/resolv.conf — or, with
`--dns 10.0.2.3 --dns-host ADDRESS`, to that one. A `--dns` without
`--dns-host` carries them nowhere: given a resolver to hand out, passt reads
none of the host's. The guest's resolver is that one
address whichever network passt is on, so a passt started again elsewhere
needs nothing new of the guest. The hooks it asks are named by its
launch settings below: the host port of each, which a relay on the host
carries to the operator's service. A hook given no port is not asked.

And it is given the certificate AMD issues this chip at its reported TCB — the
VCEK, in DER — which is what lets anyone check a quote it mints
(`crates/api/src/endorsement.rs`). It is public, and api checks it against the
AMD root compiled in and against a report the chip has just made, so the host
choosing it chooses only whether api starts. `snphost show vcek-url` names it;
fetch it once per chip and TCB and keep it:

```sh
  -fw_cfg name=opt/com.enclavid/vcek,file=/var/lib/enclavid/vcek/vcek.der \
```

What each measurement-relevant part is doing:

- **`kernel-hashes=on`** — without it the kernel, the initramfs and the command
  line contribute **nothing** to the launch digest. QEMU's default for this
  property is off, so three of the five inputs `README.md` calls pinned are only
  pinned because this flag is here.
- **`-cpu EPYC-Milan-v2` and `-smp N`** — the VMSA pages are measured, one per
  vCPU, so both the type and the count enter the digest. The count is each
  role's own (`roles.<role>.vcpus` in `default.nix`: api, storage and the
  compile-worker 4, the execution-worker 8, the gateway and the hatch 2). See
  the open question below.
- **`policy=0x30000`** — bits 16 and 17. Bit 17 is reserved and must be set; bit
  16 is `SMT_ALLOWED`, so this guest agrees to run on a host with SMT enabled.
  Debug (bit 19) and migration-agent (bit 18) are clear, which is what
  `crates/attestation/src/snp.rs` requires of a peer. The policy is a signed
  field of every report, so it is a security constant that currently lives
  nowhere but a command line.
- **`-m`** — memory size is *not* a measurement input. Roles may differ freely;
  the defaults below are chosen for 2G for storage, 3G for api, 1G for the
  hatch, 8G for the compile-worker and 10G for the execution-worker. The
  execution-worker sizes
  itself from its memory: it reserves its bundle cache (which the bundles
  streaming into it share), a base, and a share in itself for each child its
  child bound allows, and gives the rest to its round children as one total.
  The kernel holds the children to that total together and each to the round's
  max, killing a child past either. It refuses to boot when the total cannot
  hold one child at its max — at the default settings, when its kernel reports
  below about 5.4G (a 10G launch reports 9000 MiB) — and when the cache cannot
  hold the largest bundle, about 1.6G, since a round runs its bundle from the
  cache. Its boot line reports the memory it read, the total, every setting
  below, and how many rounds fit beside one at its max
  (`crates/engine-executor/src/admission.rs` has the reserves and the
  defaults). The compile-worker refuses to boot when its memory less its base
  reserve cannot hold one compile at its max — at the default settings, when
  its kernel reports below about 4.5G (an 8G launch reports 7514 MiB).

- **Launch settings** — how many, how much, how long. Not measurement inputs:
  every role takes them from one fw_cfg entry, `opt/com.enclavid/settings`,
  as `key=value` pairs ended by `;` or a newline
  (`crates/fleet-transport/src/launch.rs`). `enclavid-boot-cvm` passes one as
  `FW_CFG="settings=max-children=8;round-max-bytes=536870912"`, and the fleet
  module as `enclavid.cvms.<role>.settings`. Each is optional; a value that
  does not parse, a key given twice, or a key the role does not know stops the
  boot. A developer's build without vsock reads each from the environment
  instead, as `ENCLAVID_<ROLE>_<KEY>` (`ENCLAVID_EXECUTION_WORKER_MAX_CHILDREN`).

  | Role | Setting | Default |
  | --- | --- | --- |
  | execution-worker | `max-children` | 12 |
  | | `waiting-per-child` | 1 |
  | | `bundle-cache-bytes` | 4 GiB |
  | | `bundle-cache-entries` | 512 |
  | | `bundle-idle-secs` | 3600, at most 3600 |
  | | `base-reserve-bytes` | 256 MiB |
  | | `round-max-bytes` | 384 MiB |
  | | `round-headroom-bytes` | 128 MiB |
  | | `round-deadline-secs` | 120 |
  | | `round-fuel` | 10 000 000 000 |
  | | `capacity-wait-secs` | 10 |
  | | `bundle-stream-secs` | 120 |
  | | `bundle-stream-idle-secs` | 20 |
  | | `child-max-tasks` | 64 |
  | | `child-exit-wait-secs` | 5 |
  | | `child-connect-secs` | 30 |
  | | `room-poll-ms` | 50 |
  | | `request-buffer` | 4 |
  | | `callback-request-buffer` | 4 |
  | compile-worker | `max-compiles` | 4 |
  | | `deadline-secs` | 100 |
  | | `compile-max-bytes` | 4 GiB |
  | | `compile-headroom-bytes` | 256 MiB |
  | | `base-reserve-bytes` | 512 MiB |
  | | `child-max-tasks` | 64 |
  | | `child-exit-wait-secs` | 5 |
  | | `child-connect-secs` | 30 |
  | | `room-poll-ms` | 50 |
  | | `cwasm-read-bytes` | 1 MiB |
  | | `request-buffer` | 4 |
  | storage | `cache-bytes` | 4 GiB |
  | | `cache-read-bytes` | 1 MiB |
  | | `sweep-secs` | 60 |
  | | `sweep-batch` | 1024 |
  | | `session-request-buffer` | 16 |
  | | `cache-request-buffer` | 8 |
  | | `db-busy-secs` | 5 |
  | api | `session-ttl-secs` | 1 week |
  | | `leg-dial-secs` | 30 |
  | | `leg-retry-max-secs` | 10 |
  | | `pull-deadline-secs` | 60 |
  | | `registry-requests-per-consumer` | 4 |
  | | `authorize-deadline-secs` | 25 |
  | | `kbs-deadline-secs` | 20 |
  | | `callback-request-buffer` | 4 |
  | hatch | `concurrent-manifests` | 128 |
  | | `concurrent-blobs` | 8 |
  | | `authorize-hook-port` | none: no authorization |
  | | `limits-hook-port` | none: no limits |
  | | `hook-deadline-secs` | 10 |
  | | `request-buffer` | 16 |
  | all five | `leg-timeout-secs` | 20 |
  | | `leg-max-ports` | 256 |
  | | `leg-chunk-bytes` | 65536 |
  | | `leg-receive-bytes` | 8388608 |
  | | `accept-retry-ms` | 1000 |

  The `leg-*` settings are each end's own: chmux announces them in its hello
  and the far end fits to them, so the two ends of a leg need not agree.

`-serial file:` is where a role's log device lands. Under
`cmdline/<role>/production` the application writes to `/dev/ttyS0` with the
kernel console off; under `debug` the kernel console shares the port.

## Order, and how to tell it worked

vsock addresses guest↔host only, so a guest cannot dial another guest. Every
fleet leg is two hops through a host-side relay, which means the relays must
exist before the guest that dials through them is useful.

0. Start the relays to the NTS servers, two per server on
   `crates/timesync/servers`. Every guest starts its application only once
   three of them agree on the time, so without these no guest starts its
   application — its console says which servers it cannot reach, and after the
   keeper's ten minutes (`start-timeout`) the guest powers off.
1. Start the four leaves, the hatch with its passt. Each answers
   `{"healthy":false}` on its health port from the moment it binds, and
   `{"healthy":true}` once it is listening.
2. Start one relay per leg, and one per hook the hatch is given a port for.
3. Start api. It dials all four legs before it binds either serving port, and
   it waits without a bound — so a leg that never comes up shows as an api that
   never becomes ready, not as one that exits.

```sh
# one pair per server on crates/timesync/servers: <port> and <port>+1
host-relay --listen vsock:7100 --to tcp:time.cloudflare.com:4460
host-relay --listen vsock:7101 --to udp:time.cloudflare.com:123
# …

host-relay --listen vsock:8001 --from $API_CID --to vsock:$STORAGE_CID:8001
host-relay --listen vsock:8002 --from $API_CID --to vsock:$COMPILE_CID:8002
host-relay --listen vsock:8003 --from $API_CID --to vsock:$EXEC_CID:8003
host-relay --listen vsock:8004 --from $API_CID --to vsock:$HATCH_CID:8004

# with `authorize-hook-port=8005` in the hatch's settings
host-relay --listen vsock:8005 --from $HATCH_CID --to tcp:127.0.0.1:9100
```

A hatch with no hook ports authorizes no one and limits nothing: the dev
posture, every session no one's. Outside `sev-snp` a dev api also needs
`ENCLAVID_TEE_KEY=<64 hex chars>`, because the sealing key is then not derived
from the chip — but it has to be IN the cmdline file, not appended at launch, or
the guest's measurement stops matching what was computed for it.

### The health ports

The host reads these; nothing else does. They are on the measured command line
like every port a guest listens on, and `README.md`'s port table does not yet
list them.

| port | role |
|---|---|
| 8445 | api |
| 8011 | storage |
| 8012 | compile-worker |
| 8013 | execution-worker |
| 8014 | hatch |

`connect`, read to EOF, send nothing — the port never reads, and a prober that
speaks first can have its own answer reset away. api's answer carries its fleet
peers, the hatch among them, alongside its own bool; a leaf's is the bool alone. Whether
any of that means *ready* is the reader's conclusion, not the guest's claim —
`crates/fleet-transport/src/health.rs` argues the split.

## Building and booting a fleet

    nix-build image -A measurements.storage    # the launch digest, needs no keys
    nix-build image -A images.storage --arg idKeys $KEYS   # + cmdline + qemu-args
    nix-build image -A images.api    --arg idKeys $KEYS    # pinned to the four leaves

`idKeys` is a directory of `id.pem` and `author.pem` (EC P-384). Anything that
writes a launch line needs them, because the line carries an ID block asserting
its own digest; `measurements.*` does not.

`image/default.nix` is where a build starts. It owns the ordering api's
`endorsement.rs` depends on — the four leaves are built and measured, then api
is built from their digests — and it generates the launch flags and the digest
from ONE set of parameters, so the two cannot disagree.

Each image carries a `qemu-args` file with the flags the measurement covers.
Splice it in verbatim and add only what the digest does not describe: memory,
the vsock CID, any drive, where the serial goes — and, for api, its legs'
ports as fw_cfg entries; for the hatch, its network interface.

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

Production and debug are separate fleets end to end: `api-debug` pins the four
`*-debug` leaves, `api` pins the four production ones. Mixing them is a refused
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

`--guest-features` defaults to `0x1` in the tool. The launch also enables Secure
TSC, bit 9, so the build passes `0x201`; anything else it ever enables —
`debug-swap`, say — has to move with it.

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
- Images built before the disposable-child crates were split carry a
  `session-child` sibling. A worker initramfs holding that name is stale.
