# Guest image

Five inputs go into a SEV-SNP launch measurement. All five are pinned here, and
each reproduces byte for byte:

| input | where | verify |
|---|---|---|
| firmware | `ovmf/` — our own edk2 platform, see its README | `nix-build image/ovmf --check` |
| kernel | `kernel/` | `nix-build image/kernel -A base\|compile-worker\|execution-worker\|hatch\|storage --check` |
| PID 1 | `init/` (dinit, busybox) + `init/services/` | `nix-build image/init -A dinit -A busybox --check` |
| initramfs | `initramfs/` | `nix-build image/initramfs --check` |
| cmdline | `cmdline/<role>/<variant>` | the file is the value |

`app/` builds the role binary the initramfs wraps. `onnxruntime/` builds the
ONNX Runtime the execution worker's model process links, from source and with
its telemetry compiled out (`nix-build image/onnxruntime -A static --check`).

Two of the five are shared rather than per-role. The firmware is one image for
everyone. The kernel comes in five variants, named for the roles they boot and
built from fragments named for what they turn on or off: `base` for api and the
gateway; `compile-worker`; `execution-worker`; `hatch`, for the one role with a
network interface; and `storage`, for the one role that owns a disk. All but
`storage` are `diskless`. The two workers' variants add the kernel's memory
controller — each supervisor holds its disposable children, a round or a
compile each, to their memory with it, and no other role confines anything
that way, so no other kernel carries it (see `kernel/memcg.config`). The
hatch's adds IPv4, the virtio NIC and the kernel's DHCP client, and nothing
more beneath them (see `kernel/net.config`): every other kernel has no IP stack
at all, so that it reaches no network is a property its measurement shows.
Everything else — PID 1's services, the initramfs that carries the role binary,
and the command line — is the role's own, and that is enough to give each its
own measurement.

## PID 1

dinit (`init/`). It starts each role's services (`init/services/`, the
`common` ones and the role's own) in the order their dependencies give: the
mounts, then the clock keeper, then the application. Nothing restarts — dinit is
built never to — so when any of them ends, what depends on it stops, and once
every service has stopped dinit starts `recovery`, which powers the guest off.
The application finishing, dying, or its clock no longer being kept all end the
same way: a run that cannot continue should stop existing.

No application keeps root's capabilities; each holds only those its role's
`app` file names: none for api, storage and the hatch, one for the gateway,
and four for each worker's supervisor, which it uses to give each disposable
child an identity of its own. api, storage, the hatch and the gateway run as a
user of their own, `app` (1000), handed by `app-files` just what they open —
the log device, the attestation device, the launch settings, storage's volume
— so they own nothing else of root's. The workers' supervisors stay root, under `noroot`
securebits, locked, so that being root brings no capability into an exec: a
process that can give its children identities could be root again whenever
it liked, so a user of its own would bound nothing. The two workers mount
`/proc` `hidepid=invisible` in a `proc` of their own, so neither supervisor
holds a right to mount. The clock keeper narrows
itself to `CAP_SYS_TIME` once it has opened what it needs.

Root without capabilities can still write whatever root owns by its file
mode, and some of that would hand capabilities back: the kernel's settings
(one names a program the kernel runs with every capability), attributes under
/sys (which clocksource the kernel reads, among them), PID 1's service files
and the programs it runs, and its control socket. So before the clock keeper
starts, `lockdown` makes /proc/sys, /sys and the root filesystem read-only and
takes every permission off the control socket; undoing any of it takes
`CAP_SYS_ADMIN` or `CAP_DAC_OVERRIDE`, which nothing after holds. /dev, /tmp
and /run, which stay writable, are `noexec`; and the kernel has no core dumps.

busybox is still in the image, for the four things dinit has no code for:
`mount`, `poweroff`, the `chmod` that opens the two workers' cgroup root to its
owner, and the `chown` that hands the other roles' applications what they open.
It carries those applets and nothing else — no shell above all
(`init/busybox.config`).

## The command line

Verbatim: whatever `cmdline/<role>/<variant>` contains is what `-append` receives and
what `sev-snp-measure --append` is given. A byte of difference is a different
measurement, so there is no room for a formatting convention here.

`panic=-1 oops=panic` makes the guest fail closed. An oops becomes a panic
rather than continuing in a corrupted state, and a panic ends the machine
instead of leaving it running with a broken kernel. There is no in-place
recovery in this design; a run that cannot continue should stop existing.

`--auto-recovery` is PID 1's: the kernel passes on what it does not recognise
and that starts with `--`. With it, dinit meets every service stopped by
starting `recovery` — the guest's poweroff — rather than by asking at the
console what to do, of an operator who is not there.

`no-kvmclock tsc=reliable` put the guest's clock on its TSC, which Secure TSC
(`launch.snpFlags` in `default.nix`) fixes at launch out of the host's reach.
Without the first, the kernel prefers KVM's paravirtual clock, whose readings
the host writes, unless CPUID says the TSC is invariant — and the host writes
CPUID too, and the measurement does not cover it. The second stops the kernel
checking the TSC against the HPET and the ACPI timer, both emulated by the
host; under Secure TSC this kernel already treats the TSC as reliable, so it
says what holds rather than changing it.

Neither keeps the clock on the TSC for good. The kernel still gives the TSC up
after boot when it judges it unstable, and part of what it judges by is the
host's to say — ACPI asking it to re-read the idle states, for one. It would
move to a clocksource the host emulates and can stop, and every timer in the
guest would stop with it, every check of the clock included. So there is
nothing to move to: `hpet=disable` here, the kernel built without the ACPI PM
timer (`kernel/common.config`), and the KVM clock off by `no-kvmclock`; and
`idle=halt` keeps ACPI from re-reading idle states at all. The clock keeper
below refuses to start unless the TSC is the only clocksource the kernel has,
and checks every second after that it still reads it.

The TSC makes elapsed time the guest's own; where the calendar starts is still
the emulated RTC's, which is the host's. Every role's PID 1 therefore starts
`timesync` (`crates/timesync`) before the application: it takes the calendar
from NTS servers — the key exchange ending in the guest, every time packet
authenticated, three servers of different operators agreeing — and dinit starts
the application only once the keeper says the kernel's clock is synchronised.
The application never runs on the host's calendar. The keeper ending ends the
guest, and once it has first set the clock it ends itself on any step of more
than 2 s; and every role runs a guard (`timesync::guard`) that ends it, and so the
guest, once the kernel's own error estimate says the clock has gone about an
hour without being kept.

`sysctl.kernel.yama.ptrace_scope=3` is the ptrace floor the per-round child
isolation rests on — "no attach", denying every process including one holding
`CAP_SYS_PTRACE`, which matters because everything in this guest is root,
except the two workers' disposable children — a round or a compile each —
which run as identities of their own. The kernel accepts `sysctl.*` on its
command line, so the floor is measured rather than provisioned.

`ip=dhcp`, on the hatch's lines alone, has the kernel configure its one
interface before PID 1 runs, from the DHCP answer of the host's end of it.
Nothing in userspace configures the network, so nothing there could change it.
The resolver is not taken from that answer: the image's own /etc/resolv.conf
names 10.0.2.3, the address the far end of a hatch's interface serves names
at, so it is measured with the rest.

`init_on_free=1` is on every line of the roles that hold plaintext — api, the
gateway that terminates client TLS, the hatch that ends TLS to registries and
key brokers, and the two workers. The kernel zeroes each
page as it is freed: a killed child's memory, a released cwasm, a request
buffer api let go of. Without it a freed page keeps what it held until
something reuses it, so whoever reached the guest's kernel would read past
rounds out of free memory and not only the ones in flight. It costs a zeroing
pass on every free. The storage role holds only sealed bytes and goes without.

The two workers' lines also carry `printk.devkmsg=off` and
`sysctl.kernel.dmesg_restrict=1`, and their production lines
`sysctl.vm.oom_dump_tasks=0`. Each worker's kernel kills a child that
outgrows its memory, and reports the kill in its log, naming the process and
what it held. The first two close that log, which is open to any identity
otherwise, so a child could read a sibling's kill: `/dev/kmsg` to every reader,
and — set here rather than by sysctl — for good; `syslog(2)` to every reader
without `CAP_SYSLOG`, which the children's syscall filter refuses as well. The
supervisor refuses to start without either. The third leaves out of a kill's
report the table of every task in the guest, which the kernel otherwise walks
and prints on each kill. The `debug` line keeps the table: there the kernel log
is on the port, which is where a kill is diagnosed.

The `ENCLAVID_*` entries are the application's configuration, and they are
spelled exactly as they are in a shell because they end up in the same place.
The kernel hands init any parameter it does not recognise that contains `=`
as an environment variable, and dinit starts every service with what it
inherited — so `std::env::var` finds them and the binaries need no notion of
where they came from. Nothing else fills an environment here: there is no
shell, and dinit is given no environment file of its own.

The channel is measured, which makes it the right place for values that say
what this image *is*: the fixed vsock ports it listens on, the host CID it
reaches. It is the wrong place for anything that differs per machine, which
would fragment the measurement into one per deployment, and the wrong place
for a secret, which the command line does not keep. The sealing key is
neither configured nor transported: under `sev-snp` the chip derives it,
bound to this image's measurement.

## The ports

vsock addresses guest↔host and nothing else, so a guest cannot name another
guest: it dials CID 2 — the host — and the port is what says who it wants.
The port numbers therefore ARE the routing. The ones on a measured command
line change the measurement when they change.

| port | reached by | carries | where it is set |
|---|---|---|---|
| 8001 | api → host | the storage-CVM | the launch, fw_cfg |
| 8002 | api → host | the compile-worker | the launch, fw_cfg |
| 8003 | api → host | the execution-worker | the launch, fw_cfg |
| 8004 | api → host | the hatch: authorization, OCI pulls, the KBS relay | the launch, fw_cfg |
| 8005 | hatch → host | the operator's authorization hook | the hatch's launch settings |
| 8006 | hatch → host | the operator's limits hook | the hatch's launch settings |
| 8443 | host → api | the consumer-facing surface | command line |
| 8444 | host → api | the applicant-facing surface | command line |

Each outbound port needs something on the host listening there and splicing
onward to the peer guest, or to the hook; the guest neither knows nor can
discover which one.

The ports api dials are not on its command line: the host hands them to api
at launch as fw_cfg entries (`crates/api/src/fleet/legs.rs`), and the numbers
above are only the ones `deploy/` uses. Putting them in the image bound
nothing — the host decides where a port leads whatever api dials; what
decides whether api talks to a peer is the measurement it pins for that leg.
Out of the measurement, they let two releases run side by side on one host,
each api reaching its own peers. The hatch's hooks are the host's own, and a
hook the host gives no port for the hatch does not ask.

**`production` says `console=null`, and the token is load-bearing.** Omitting
`console=` does NOT produce a silent kernel — it produces a kernel that enables
the FIRST console to register. On an ordinary x86 build the VT console absorbs
that; `CONFIG_VT` is off here, so the 8250 registers first, comes up enabled,
and `CON_PRINTBUFFER` replays the whole buffered boot log. Measured: 25110
bytes on the serial port from a command line with no `console=` at all, versus
183 with `console=null`.

Those remaining 183 are OVMF's screen-clearing escapes and one line from the
EFI stub — firmware, before the kernel exists, constant on every boot. No
kernel line survives, which is what matters: a panic trace carries pointers and
register values from whatever the guest was doing, and `panic()` calls
`console_verbose()`, so a log level cannot be trusted to hold it back. Only the
absence of an enabled console can.

What `console=null` governs is the KERNEL. What the APPLICATION's fds 0, 1 and
2 point at is the console too, by its service file: `app` and `timesync` share
dinit's console (`options: shares-console`), and the initramfs carries a
`/dev/console` node of its own for dinit to open before any service has mounted
`/dev`. So the production image is silent — the null console discards — and the
`debug` variant, whose command line puts a real console on the port, shows what
the application writes there.

Silencing the kernel does not silence the role. `ENCLAVID_LOG_DEVICE` names the
same port, and the role opens it itself — see `crates/safe-logger`. That is the
whole difference: the port carries only lines an `info!` site wrote down a reason
for, plus a panic report. Everything else in the process — a `println!` from any
dependency, a panic payload, output from C underneath — keeps going to fds 1
and 2, which discard.

How much a panic report says is per role. Where the measured code is the only
code, a panic names `file:line`, because aiming that choice at a secret means
rewriting the role and so changing the measurement. The execution worker runs
the consumer's policy — adversary-chosen wasm that executes inside the measured
image without altering it — so in its production build a panic says only that
one happened. Its `-debug` build names the location like the rest: that image
is already putting the whole kernel log on this port, and it is a measurement
no consumer pins.

Below that sits a third tier, and it is the one the kernel switch governs.
`debug!` in `crates/safe-logger` writes to stderr, which discards, and needs
no reason because nothing it says leaves the TEE in production. It is also not
compiled at all without the `debug` cargo feature, which is why `app/` ships
`<role>` and `<role>-debug`: were the tier gated only by `console=null`, one
wrong line in `kernel/` or here would put every `debug!` in the tree, session
ids and error chains included, in front of the host at once. Not building them
means that mistake can leak only what dependencies print.

The pair belongs together — a `-debug` app wants the `debug` command line.
Mismatching is confusing and never unsafe: one way writes into a descriptor
that discards, the other says nothing.

The `debug` command line also sets `ENCLAVID_LOG_LEVEL=info`, not the default
of everything. The level gates only what DEPENDENCIES log — every `debug!` in
this tree goes around it — and below `info` they write far more than this port
can carry: the fleet's RPC layer prints every 8 KiB piece of a message at trace,
four characters a byte, and the compiler reports every pass of every function
at debug. Every character on this port is an exit to the host, so at those
levels a round spends minutes writing and misses its own deadlines.

What stays silent is a failure nobody annotated. That is what `debug` is for —
the same image with a kernel console, and therefore a different measurement,
which no consumer pins. Reaching for it is one file away, and it costs about
190 ms of boot time.

## The storage volume

One role persists, and it is the only one that gets a device. `storage` expects
a single virtio disk carrying an ext4 filesystem, mounted by its `data` service
at `/data`, with the session store and the cwasm cache underneath. Whoever
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

`poweroff -f`, which `recovery` runs, flushes first — busybox skips the `sync()`
only for `-n` — so an ordinary shutdown loses nothing. A guest killed rather than shut
down leaves the journal to replay, which ext4 does on the next mount.
