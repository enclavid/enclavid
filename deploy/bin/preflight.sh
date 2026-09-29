# Whether this host can run the fleet: a processor with SEV-SNP, KVM running
# SNP guests, the vsock device the guests are reached through, a QEMU that boots
# them, memory for all of them, and the public port free for the relay. Each
# check says what it found; any that fails fails the whole.
#
#   enclavid-preflight
failed=0
ok() { echo "ok    $1"; }
fail() {
  echo "FAIL  $1"
  failed=$((failed + 1))
}
note() { echo "note  $1"; }
root=false
[ "$(id -u)" = 0 ] && root=true

if grep -qw sev_snp /proc/cpuinfo; then
  ok "the processor offers SEV-SNP"
else
  fail "the processor offers no SEV-SNP — no sev_snp flag in /proc/cpuinfo; it may be off in the firmware setup"
fi

if [ -e /dev/kvm ]; then ok "/dev/kvm is there"; else fail "no /dev/kvm"; fi

snp=$(cat /sys/module/kvm_amd/parameters/sev_snp 2>/dev/null || true)
case "$snp" in
  Y | 1) ok "KVM runs SNP guests" ;;
  *) fail "KVM does not run SNP guests: kvm_amd is not loaded, loaded with SNP off, or the SEV firmware did not initialise (dmesg says which)" ;;
esac

if [ -e /dev/sev ]; then ok "/dev/sev is there"; else fail "no /dev/sev — the SEV firmware is not available to the host"; fi

# The fleet loads it at every boot; loaded here too, so the first start needs
# no reboot.
if [ ! -e /dev/vhost-vsock ] && $root; then modprobe vhost_vsock 2>/dev/null || true; fi
if [ -e /dev/vhost-vsock ]; then
  ok "/dev/vhost-vsock is there"
else
  fail "no /dev/vhost-vsock — load the vhost_vsock module"
fi

# One for each release the fleet runs, since each boots under its own.
for qemu in "${QEMUS[@]}"; do
  if [ -x "$qemu" ] && "$qemu" -object help 2>/dev/null | grep -q sev-snp-guest; then
    ok "QEMU boots SNP guests ($qemu)"
  else
    fail "$qemu does not boot SNP guests — it is missing, or has no sev-snp-guest object"
  fi
done

# A guest's memory is a count of MiB or GiB with its unit; fleet.nix allows
# nothing else.
mib() {
  case "$1" in
    *G) echo $((${1%G} * 1024)) ;;
    *) echo "${1%M}" ;;
  esac
}
wanted=0
for m in "${MEMORY[@]}"; do wanted=$((wanted + $(mib "$m"))); done
total=$(($(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024))
# What the host itself needs beside the guests.
spare=1024
if [ $((wanted + spare)) -le "$total" ]; then
  ok "memory: the guests take ${wanted} MiB of ${total} MiB"
else
  fail "memory: the guests take ${wanted} MiB, and ${total} MiB less ${spare} for the host is not enough"
fi

case "$LISTEN" in
  tcp:*)
    port=${LISTEN##*:}
    holder=$(ss -Hltnp "sport = :$port" 2>/dev/null || true)
    if [ -z "$holder" ]; then
      ok "port $port is free for the public relay"
    elif grep -q host-relay <<<"$holder"; then
      ok "port $port is held by the fleet's own relay"
    elif $root; then
      fail "port $port is held by another process: $holder"
    else
      note "port $port is held, and only root can see by what"
    fi
    ;;
esac

if [ "$failed" -gt 0 ]; then
  echo "this host cannot run the fleet: $failed check(s) failed"
  exit 1
fi
