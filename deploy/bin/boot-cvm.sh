# Boot one confidential VM exactly as its image says — the image's own QEMU
# arguments and kernel command line, which its launch measurement was computed
# over — plus only what the host decides: memory, the vsock CID, a disk, where
# the serial console goes, and fw_cfg entries for a guest that reads them.
#
#   [FW_CFG="name=value ..."] enclavid-boot-cvm NAME IMAGE CID MEMORY [DISK SIZE]
#
# NAME is this guest's among the host's — a release's api is one of several —
# and names only its console.
name=$1 image=$2 cid=$3 memory=$4

# Each entry becomes the fw_cfg file opt/com.enclavid/NAME, outside the
# measurement. Which role reads which is that role's business: every role takes
# its settings from one, `settings`, and api the ports of its legs from others.
fwcfg=()
read -ra entries <<<"${FW_CFG:-}"
for entry in "${entries[@]}"; do
  fwcfg+=(-fw_cfg "name=opt/com.enclavid/${entry%%=*},string=${entry#*=}")
done

disk=()
if [ $# -ge 6 ]; then
  # Made under another name and put in place only once formatted: a volume
  # that exists is one that mounts, since the guest mounting none serves from
  # memory and says nothing.
  if [ ! -e "$5" ]; then
    rm -f "$5.new"
    truncate -s "$6" "$5.new"
    mkfs.ext4 -q -F "$5.new"
    mv "$5.new" "$5"
  fi
  disk=(-drive "file=$5,if=virtio,format=raw")
fi

# One generation kept: the console of the boot before this one.
log=/var/log/enclavid/$name.serial
[ ! -e "$log" ] || mv -f "$log" "$log.1"

read -ra args <<<"$(tr '\n' ' ' <"$image/qemu-args")"
exec "$QEMU" -enable-kvm "${args[@]}" \
  -m "$memory" -object "memory-backend-memfd,id=ram0,size=$memory,share=true,prealloc=false" \
  -device "vhost-vsock-pci,guest-cid=$cid" "${disk[@]}" "${fwcfg[@]}" \
  -kernel "$image/bzImage" -initrd "$image/initramfs.cpio.gz" -append "$(cat "$image/cmdline")" \
  -display none -monitor none -serial "file:$log" -no-reboot
