# Guest initramfs — reproducible build.
#
# The third and last input QEMU hashes into the measured SEV-SNP launch, after
# the firmware and the kernel. Takes the role's application binary and wraps it
# with PID 1:
#
#   /init          busybox
#   /bin/busybox   the same binary, under the name its inittab calls
#   /bin/app       the role's application — api, storage-cvm, …
#   /bin/<sibling>  binaries the application execs, under the names it uses
#   /etc/inittab   PID 1's whole program
#
# Usage, with an already-built static binary:
#
#   nix-build image/initramfs --arg app "$(nix-store --add ./target/.../api)"
#   cat result/initramfs.cpio.gz.sha256
#
# `app` is a path rather than a derivation on purpose: the Rust build is not yet
# expressed in Nix, and pretending otherwise would hide which half is pinned.
# When it is, this takes the derivation instead and nothing else changes.
#
# There is no /dev/console node. The kernel is happy without one — verified by
# booting an image built exactly this way — which is what lets the archive be
# assembled by an unprivileged builder with plain cpio, no mknod and no
# gen_init_cpio.
{ app
, inittab
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
in
pkgs.runCommand "enclavid-initramfs-${name}"
{
  nativeBuildInputs = [ pkgs.cpio pkgs.gzip ];
} ''
  mkdir -p root/bin root/etc root/proc root/sys root/dev root/tmp root/run
  ${pkgs.lib.concatMapStringsSep "\n  " (d: "mkdir -p root/${d}") dirs}

  install -m 0755 ${init}/busybox root/init
  install -m 0755 ${init}/busybox root/bin/busybox
  install -m 0644 ${inittab}      root/etc/inittab
  install -m 0755 ${app}          root/bin/app
  ${pkgs.lib.concatStringsSep "\n  " (
    pkgs.lib.mapAttrsToList (n: path: "install -m 0755 ${path} root/bin/${n}") siblings
  )}

  mkdir -p $out

  # Three separate sources of nondeterminism, all of them silent:
  #   - directory iteration order, hence the sort;
  #   - the builder's uid/gid recorded per entry, hence --reproducible, which
  #     also zeroes the timestamps;
  #   - gzip's own header timestamp and filename, hence -n.
  ( cd root
    find . | LC_ALL=C sort \
      | cpio --quiet --create --format=newc --reproducible \
      | gzip -9n > $out/initramfs.cpio.gz )

  ( cd $out && sha256sum initramfs.cpio.gz > initramfs.cpio.gz.sha256 )
''
