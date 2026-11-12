# libvpx's VP8 decoder, built from source as the archive a static binary links.
#
#   nix-build image/libvpx
#
# The one decoder of an applicant's video in the fleet, linked into
# engine-executor-media and nowhere else. Only what decoding VP8 needs is
# compiled: no VP9, no encoder, no post-processing, no threads, no tools. The
# decoder allocates for whatever size a keyframe says, up to 16383 a side —
# libvpx's own size limit binds VP9 alone — so the coprocess reads each
# keyframe's size first, through the decoder's own reading of it, and decodes
# nothing from the first keyframe whose size is not the video's, which it holds
# to engine-types' bounds.
#
# Out: `include/vpx/*.h`, which the coprocess's C shim compiles against, and
# `lib/libvpx.a`; nothing else.
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;

  version = "1.17.0";
in
pkgs.stdenv.mkDerivation {
  pname = "libvpx-vp8-decoder";
  inherit version;

  src = pkgs.fetchFromGitHub {
    owner = "webmproject";
    repo = "libvpx";
    tag = "v${version}";
    hash = "sha256-1PBeHQSgBf5nT/IDL36VWBqiWLSHz/1XGM41gy49DsY=";
  };

  # nasm for the decoder's x86 SIMD; perl and which for its configure.
  nativeBuildInputs = [
    pkgs.nasm
    pkgs.perl
    pkgs.which
  ];

  # Its own configure, not autoconf's: it refuses `--build` and `--host`, and
  # takes `--prefix` as autoconf's does.
  configurePlatforms = [ ];

  # Its build runs scripts of its own — a Perl one writes the headers that
  # pick each function's SIMD version — through `/usr/bin/env`, which the
  # build sandbox does not have.
  postPatch = ''
    patchShebangs --build build/make
  '';

  # It links with the compiler, and takes `LD` from the environment if it is
  # set — which stdenv sets to `ld`, so it would call `ld` with the compiler's
  # flags.
  preConfigure = ''
    export LD="$CC"
  '';
  configureFlags = [
    "--target=x86_64-linux-gcc"
    "--as=nasm"
    "--enable-static"
    "--disable-shared"
    # Position-independent, for the static-pie binary it is linked into.
    "--enable-pic"
    "--disable-vp9"
    "--disable-vp8-encoder"
    "--enable-vp8-decoder"
    "--disable-postproc"
    "--disable-multithread"
    "--disable-examples"
    "--disable-tools"
    "--disable-docs"
    "--disable-unit-tests"
    "--disable-webm-io"
    "--disable-libyuv"
    "--disable-install-bins"
    "--disable-install-srcs"
  ];

  postInstall = ''
    rm -r $out/lib/pkgconfig
  '';
}
