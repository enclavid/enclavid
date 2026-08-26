# Guest image

Five inputs go into a SEV-SNP launch measurement. All five are pinned here, and
each reproduces byte for byte:

| input | where | verify |
|---|---|---|
| firmware | distribution `ovmf-amdsev` package | package version + digest |
| kernel | `kernel/` | `nix-build image/kernel -A <role> --check` |
| PID 1 | `init/` | `nix-build image/init --check` |
| initramfs | `initramfs/` | `nix-build image/initramfs --check` |
| cmdline | `cmdline/` | the file is the value |

`app/` builds the role binary the initramfs wraps. Roles differ in every input
except the firmware, so each carries its own measurement — that is a property of
the launch, not a packaging choice.

## The command line

Verbatim: whatever `cmdline/<variant>` contains is what `-append` receives and
what `sev-snp-measure --append` is given. A byte of difference is a different
measurement, so there is no room for a formatting convention here.

`panic=-1 oops=panic` makes the guest fail closed. An oops becomes a panic
rather than continuing in a corrupted state, and a panic ends the machine
instead of leaving it running with a broken kernel. There is no in-place
recovery in this design; a run that cannot continue should stop existing.

**`production` carries no `console=`.** Everything the kernel prints on a serial
console is plaintext the host can capture, and a panic trace carries pointers
and register values from whatever the guest was doing. Diagnostics are supposed
to leave over RA-TLS, not over a channel the host owns by construction.

The cost is that a failure before RA-TLS is up is silent. That is what `debug`
is for — the same image with a console, and therefore a different measurement,
which no consumer pins. Reaching for it is one file away, and it costs about
190 ms of boot time.
