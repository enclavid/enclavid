# Guest image

Five inputs go into a SEV-SNP launch measurement. All five are pinned here, and
each reproduces byte for byte:

| input | where | verify |
|---|---|---|
| firmware | distribution `ovmf-amdsev` package | package version + digest |
| kernel | `kernel/` | `nix-build image/kernel -A <role> --check` |
| PID 1 | `init/` (binary) + `init/inittab/<role>` | `nix-build image/init --check` |
| initramfs | `initramfs/` | `nix-build image/initramfs --check` |
| cmdline | `cmdline/<role>/<variant>` | the file is the value |

`app/` builds the role binary the initramfs wraps. Roles differ in every input
except the firmware, so each carries its own measurement — that is a property of
the launch, not a packaging choice.

## The command line

Verbatim: whatever `cmdline/<role>/<variant>` contains is what `-append` receives and
what `sev-snp-measure --append` is given. A byte of difference is a different
measurement, so there is no room for a formatting convention here.

`panic=-1 oops=panic` makes the guest fail closed. An oops becomes a panic
rather than continuing in a corrupted state, and a panic ends the machine
instead of leaving it running with a broken kernel. There is no in-place
recovery in this design; a run that cannot continue should stop existing.

`sysctl.kernel.yama.ptrace_scope=3` is the ptrace floor the per-round child
isolation rests on — "no attach", denying every process including one holding
`CAP_SYS_PTRACE`, which matters because everything in this guest is root. The
kernel accepts `sysctl.*` on its command line, so the floor is measured rather
than provisioned.

The `ENCLAVID_*` entries are the application's configuration, and they are
spelled exactly as they are in a shell because they end up in the same place.
The kernel hands init any parameter it does not recognise that contains `=`
as an environment variable, and init execs the application with what it
inherited — so `std::env::var` finds them and the binaries need no notion of
where they came from. Nothing else could fill an environment here: there is
no shell and no service manager, and PID 1 runs `/bin/app` straight from its
inittab.

The channel is measured, which makes it the right place for values that say
what this image *is*: the fixed vsock ports it speaks on, the host CID it
reaches. It is the wrong place for anything that differs per machine, which
would fragment the measurement into one per deployment, and the wrong place
for a secret, which the command line does not keep. The sealing key is
neither configured nor transported: under `sev-snp` the chip derives it,
bound to this image's measurement.

## The ports

vsock addresses guest↔host and nothing else, so a guest cannot name another
guest: it dials CID 2 — the host — and the port is what says who it wants.
The port numbers therefore ARE the routing, and because they ride a measured
command line, changing one changes the measurement.

| port | reached by | carries |
|---|---|---|
| 8000 | api → host | the hatch: authorization, OCI pulls, the KBS relay, VCEK |
| 8001 | api → host | the storage-CVM |
| 8002 | api → host | the compile-worker |
| 8003 | api → host | the execution-worker |
| 8443 | host → api | the consumer-facing surface |
| 8444 | host → api | the applicant-facing surface |

Each outbound port needs something on the host listening there and splicing
onward to the peer guest; the guest neither knows nor can discover which one.

**`production` carries no `console=`.** Everything the kernel prints on a serial
console is plaintext the host can capture, and a panic trace carries pointers
and register values from whatever the guest was doing. Diagnostics are supposed
to leave over RA-TLS, not over a channel the host owns by construction.

The cost is that a failure before RA-TLS is up is silent. That is what `debug`
is for — the same image with a console, and therefore a different measurement,
which no consumer pins. Reaching for it is one file away, and it costs about
190 ms of boot time.

## The storage volume

One role persists, and it is the only one that gets a device. `storage` expects
a single virtio disk carrying an ext4 filesystem, mounted by its inittab at
`/data`, with the session store and the cwasm cache underneath. Whoever
provisions the disk makes the filesystem once; the guest only mounts it, and
mounts it `nosuid,nodev,noexec` because nothing on it is meant to be executed
or to name a device.

The volume needs no encryption of its own. Every byte reaching it was AEAD-sealed
on the api side under a key derived from api's chip and measurement, so this CVM
holds no key and a disk full of its contents is worth what any other ciphertext
is worth. What the volume does NOT defend against is the host rolling the whole
device back to an earlier state — the seal proves what a record says, not that it
is the newest one.

Two things follow from the sealing key being bound to a measurement. Data
survives a restart of the same image. It does not survive a new release of api:
a different measurement derives a different key, and what the previous one wrote
stays unreadable.

`poweroff -f` in the inittab flushes first — busybox skips the `sync()` only for
`-n` — so an ordinary shutdown loses nothing. A guest killed rather than shut
down leaves the journal to replay, which ext4 does on the next mount.
