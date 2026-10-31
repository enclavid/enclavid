# ONNX Runtime, built from source with its telemetry compiled out.
#
#   nix-build image/onnxruntime             # the shared library
#   nix-build image/onnxruntime -A static   # the archives a static binary links
#
# The released Linux binaries carry Microsoft's 1DS telemetry, switched on. On
# the first environment they write a device database under
# ~/.cache/Microsoft/DeveloperTools, read the machine's DMI and os-release, and
# report the model's graph names and hashes to events.data.microsoft.com; the
# one switch that stops it at run time is an environment variable. Built from
# source, the telemetry backend is a CMake option that defaults to OFF. It is
# passed OFF here all the same, and `postInstall` refuses a library that still
# names the endpoint.
#
# Every third-party archive the build takes is the one ORT's `cmake/deps.txt`
# names, fetched here by our hash and laid out as ORT's local mirror. ORT checks
# each against its own SHA1 and applies its own patches to it, as an upstream
# build does — and one of those patches is a bounds check in onnx's shape
# inference, which runs over every graph this library is given. Nothing comes
# from nixpkgs but the toolchain: with `FETCHCONTENT_TRY_FIND_PACKAGE_MODE` at
# NEVER, ORT cannot pick up a system protobuf or onnx, a mix its own build warns
# corrupts the heap rather than failing to link.
#
# Every operator ORT has a CPU kernel for is compiled in, in all three of its
# domains — the standard set, traditional ML (`ai.onnx.ml`) and ORT's own
# (`com.microsoft`): each is a computation over tensors, and none of their
# kernels opens a file or a socket or loads code. What is left out is where a
# model could reach past computation. A session refuses an initializer whose
# data a file holds (external initializers); the caller hands weights in.
# Sparse initializers are not compiled in, since densifying one reads such a
# file by its path too, nor are string tensors: StringNormalizer builds the
# locale its model names, and glibc reads that locale's files by the name. The
# platform is not probed for GPUs and NPUs; the CPU is the only device there is.
let
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
    url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
    sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;

  version = "1.31.1";

  # The archives of `cmake/deps.txt` this configuration builds from, each at the
  # path ORT's mirror lookup turns its URL into: the URL less `https://`. Bumping
  # ORT means re-reading deps.txt; an archive left at the old version fails the
  # build on ORT's SHA1 check rather than building with it.
  deps = {
    "github.com/abseil/abseil-cpp/archive/refs/tags/20250814.0.zip" =
      "sha256-sr3PZoLYy1PfNlvMXWwxiiLlWCHZl4oQ/bYUBMAm2v8=";
    "github.com/google/re2/archive/refs/tags/2024-07-02.zip" =
      "sha256-qDX+Vfvc2OgPOFhKsi0IQGYsZ/L+s2vWeUAtqWQdxx4=";
    "github.com/protocolbuffers/protobuf/releases/download/v33.6/protobuf-33.6.tar.gz" =
      "sha256-FkmNfceWfpsQBjITi6vUuGthWSvuzN1Vb2dTnZwjE1U=";
    "github.com/HowardHinnant/date/archive/refs/tags/v3.0.1.zip" =
      "sha256-9DALlvejBNTvm/bg+j3tchWffy0PYFvd4+AwoNunz58=";
    "github.com/boostorg/mp11/archive/refs/tags/boost-1.82.0.zip" =
      "sha256-gUMb3ETEOaMk4CwH7QZ/j1VkGf2G8ti0hv9WjfaqyJk=";
    "github.com/nlohmann/json/archive/refs/tags/v3.11.3.zip" =
      "sha256-BAIrBdgG61/3MCPCgLaGl9Erk+G3JnoLIqGjnsdXgGk=";
    "github.com/pytorch/cpuinfo/archive/66ee79c038d70dad9f08705b2c9b3e58f6d8f512.zip" =
      "sha256-uTBEJj7gcum+NXe9pS9I1aTdn8uACRUpRxyNK/5ZIZ0=";
    "github.com/microsoft/GSL/archive/refs/tags/v4.2.1.zip" =
      "sha256-ySkdlfX25cVhmQ0GpYmwHYnlU9DzZvDOcj3ReI56YHY=";
    "github.com/dcleblanc/SafeInt/archive/refs/tags/3.0.28.zip" =
      "sha256-P/vZov3/Rdp32j5yaemqUS6kO+1cOM6P2PPRBooDLD8=";
    "github.com/google/flatbuffers/archive/refs/tags/v23.5.26.zip" =
      "sha256-V71YDAdy/RpybDSri/BTJSk7xfnBZQYKiYr6H+7rleE=";
    "github.com/onnx/onnx/archive/refs/tags/v1.22.0.zip" =
      "sha256-jcEYHTNSmhJJ4DEiYSbQaZrJvfxXHuUw7joS9GVvK+M=";
    "github.com/eigen-mirror/eigen/archive/1d8b82b0740839c0de7f1242a3585e3390ff5f33/eigen-1d8b82b0740839c0de7f1242a3585e3390ff5f33.zip" =
      "sha256-amDXY1H5cTJmna7rch1r8UsAgQGIOtLWh6MgHFxGHrA=";
  };

  mirror = pkgs.linkFarm "onnxruntime-${version}-deps" (
    lib.mapAttrsToList (path: hash: {
      name = path;
      path = pkgs.fetchurl {
        url = "https://${path}";
        inherit hash;
      };
    }) deps
  );
in
pkgs.stdenv.mkDerivation {
  pname = "onnxruntime";
  inherit version;

  src = pkgs.fetchFromGitHub {
    owner = "microsoft";
    repo = "onnxruntime";
    tag = "v${version}";
    hash = "sha256-wTnt1/slnU/RSAN3+nrBYR10T4z+wqQ2r0zrIG/GlVk=";
  };

  # Python only as an interpreter: onnx generates its protobuf sources with it.
  nativeBuildInputs = [
    pkgs.cmake
    pkgs.ninja
    pkgs.python3
  ];

  cmakeDir = "../cmake";

  cmakeFlags = [
    # ORT compiles its own targets with warnings as errors, and GCC 15's
    # libstdc++ trips this one inside <format>, in its own headers. Every other
    # warning stays an error.
    (lib.cmakeFeature "CMAKE_CXX_FLAGS" "-Wno-error=maybe-uninitialized")
    (lib.cmakeFeature "onnxruntime_CMAKE_DEPS_MIRROR_DIR" "${mirror}")
    (lib.cmakeFeature "FETCHCONTENT_TRY_FIND_PACKAGE_MODE" "NEVER")
    (lib.cmakeBool "onnxruntime_BUILD_SHARED_LIB" true)
    (lib.cmakeBool "onnxruntime_BUILD_UNIT_TESTS" false)
    (lib.cmakeBool "onnxruntime_USE_TELEMETRY" false)
    (lib.cmakeBool "onnxruntime_DISABLE_DEVICE_DISCOVERY" true)
    (lib.cmakeBool "onnxruntime_DISABLE_EXTERNAL_INITIALIZERS" true)
    (lib.cmakeBool "onnxruntime_DISABLE_SPARSE_TENSORS" true)
    (lib.cmakeBool "onnxruntime_DISABLE_STRING_TYPE" true)
  ];

  # ORT applies its patches only when CMake finds a `patch` program, and builds
  # the unpatched sources without a word when it does not. The onnx patch is the
  # one that matters here, so its bounds check is looked for by name.
  preBuild = ''
    if ! grep -q 'axis < 0 || axis >= input_ndim' _deps/onnx-src/onnx/defs/nn/defs.cc; then
      echo "onnx was not patched: ORT's own patches did not apply" >&2
      exit 1
    fi
  '';

  # Two forms of one build. `out` is the shared library, for a host with a
  # dynamic loader to load it by path. `static` is the archives that library is
  # linked from, laid out as the build left them, which is the layout `ort-sys`
  # links a static binary from: a guest has no dynamic loader, so whatever runs
  # ORT there carries it inside. Nothing compiles against either — `ort-sys`
  # brings its own bindings — so neither keeps headers, CMake or pkg-config
  # files.
  outputs = [
    "out"
    "static"
  ];

  # Both outputs are filled here, and then a library that can still report home
  # is refused. `onnxruntime_USE_TELEMETRY` is the control; this is what notices
  # if a bump moves telemetry behind another option.
  postInstall = ''
    rm -r $out/include $out/lib/cmake $out/lib/pkgconfig
    mkdir -p $static/lib
    find . -name '*.a' -exec cp --parents {} $static/lib \;
    for marker in events.data.microsoft.com DeveloperTools; do
      if grep -rqaF "$marker" $out/lib $static/lib; then
        echo "the library names $marker: telemetry is compiled in" >&2
        exit 1
      fi
    done
  '';
}
