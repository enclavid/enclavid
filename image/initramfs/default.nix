# Guest initramfs — reproducible build.
#
# The third and last input QEMU hashes into the measured SEV-SNP launch, after
# the firmware and the kernel. Takes the role's application binary and wraps it
# with PID 1 and what PID 1 runs:
#
#   /init           dinit (image/init)
#   /etc/dinit.d/   PID 1's whole program: the role's services (image/init/services)
#   /bin/busybox    `mount` and `poweroff`, for the services that mount and power off
#   /bin/timesync   the clock keeper, the same in every role (crates/timesync)
#   /bin/app        the role's application — api, storage-cvm, …
#   /bin/<sibling>  binaries the application execs, under the names it uses
#   /dev/console    the console dinit writes to, and
#   /dev/null       what it gives every service as stdin, both before any of
#                   them has mounted /dev — the mount of /dev among them
#
# Usage, with already-built static binaries:
#
#   nix-build image/initramfs --arg app "$(nix-store --add ./target/.../api)" \
#     --arg timesync "$(nix-store --add ./target/.../timesync)" \
#     --arg services '[ ./image/init/services/common ./image/init/services/api ]'
#   cat result/initramfs.cpio.gz.sha256
#
# `app` is a path rather than a derivation on purpose: the Rust build is not yet
# expressed in Nix, and pretending otherwise would hide which half is pinned.
# When it is, this takes the derivation instead and nothing else changes.
{ app
  # The clock keeper, which the application's service depends on.
, timesync
  # Directories of dinit service files, copied into /etc/dinit.d in order, so
  # that a later one can add to — or replace a file of — an earlier.
, services
, name ? "app"
  # Directories the role needs that the pseudo-filesystems do not provide —
  # a mount point for a persistent volume, say. Empty for a diskless role, so
  # its image carries nothing it does not use.
, dirs ? [ ]
  # Binaries the application execs, keyed by the name it looks for. The workers
  # spawn a fresh child per round and resolve it as a SIBLING of their own
  # executable, so the name is what matters and `/bin/app` is not enough on its
  # own. Empty for a role that spawns nothing.
, siblings ? { }
}:
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as image/kernel and image/init.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  init = import ../init;

  # The kernel's own tool for writing initramfs entries, from the source the
  # guest kernel is built from. It is what writes a device node into an archive
  # without the builder making one, which an unprivileged builder cannot.
  genInitCpio = pkgs.runCommandCC "gen_init_cpio" { } ''
    tar -xJf ${(import ../kernel).src} --wildcards --strip-components=2 '*/usr/gen_init_cpio.c'
    $CC -O2 -o $out gen_init_cpio.c
  '';
in
pkgs.runCommand "enclavid-initramfs-${name}"
{
  nativeBuildInputs = [ pkgs.cpio pkgs.gzip ];
} ''
  mkdir -p root/bin root/etc/dinit.d root/proc root/sys root/dev root/tmp root/run
  ${pkgs.lib.concatMapStringsSep "\n  " (d: "mkdir -p root/${d}") dirs}

  # The one user beside root: what api, storage and the gateway run as
  # (services/<role>/app, `run-as = app`). dinit takes a user's group, and that
  # it has no others, from these; given a bare number it would keep its own
  # group, root's.
  printf 'app:x:1000:1000::/:\n' > root/etc/passwd
  printf 'app:x:1000:\n' > root/etc/group

  install -m 0755 ${init.dinit}/bin/dinit  root/init
  install -m 0755 ${init.busybox}/busybox  root/bin/busybox
  ${pkgs.lib.concatMapStringsSep "\n  " (s: "install -m 0644 ${s}/* root/etc/dinit.d/") services}
  install -m 0755 ${timesync}              root/bin/timesync
  install -m 0755 ${app}                   root/bin/app
  ${pkgs.lib.concatStringsSep "\n  " (
    pkgs.lib.mapAttrsToList (n: path: "install -m 0755 ${path} root/bin/${n}") siblings
  )}

  mkdir -p $out

  # Four separate sources of nondeterminism, all of them silent, and one of them
  # was being attributed to a flag that does not address it:
  #   - directory iteration order, hence the sort;
  #   - device and inode numbers, which is what --reproducible zeroes;
  #   - the builder's uid/gid, hence --owner: --reproducible leaves them, and
  #     they were going in as 1000:100;
  #   - per-entry mtime, hence the touch: --reproducible leaves that too, and it
  #     is what actually made two builds of this differ.
  #   - gzip's own header timestamp and filename, hence -n.
  #
  # The archive is the measured artefact, so a field nobody reads still changes
  # the launch digest. A build that does not reproduce cannot be checked by
  # anyone who did not run it, which is most of the point of publishing one.
  find root -exec touch -h -d @0 {} +
  ( cd root
    find . | LC_ALL=C sort \
      | cpio --quiet --create --format=newc --reproducible --owner=0:0 ) > files.cpio

  # The two device nodes, as a second archive after the first: the kernel
  # unpacks archives laid end to end. `-t 0` fixes their mtime, and their order
  # is this list's.
  printf '%s\n' \
    'nod /dev/console 0600 0 0 c 5 1' \
    'nod /dev/null 0666 0 0 c 1 3' > nodes
  ${genInitCpio} -t 0 nodes > nodes.cpio

  cat files.cpio nodes.cpio | gzip -9n > $out/initramfs.cpio.gz
  ( cd $out && sha256sum initramfs.cpio.gz > initramfs.cpio.gz.sha256 )
''
