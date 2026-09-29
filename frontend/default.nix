# The applicant's page — reproducible build.
#
# The fourth unpinned input to a measurement, and the newest: until this file
# existed, nothing served the page out of any measurement at all. It is built
# here so that `crates/api` can compile it into its binary, which is what makes
# the bytes a browser runs part of api's launch digest — the same digest that
# covers the handlers the page calls.
#
# That is the property worth having, and it rests on two things:
#
#   1. the output is a deterministic function of the input, so two people
#      building one commit get one digest;
#   2. the input is pinned by content, so nothing can be swapped after the fact.
#
# Under those, code that ships data to a third party cannot reach a browser
# without moving a number that is published and comparable. A compromised build
# tool is caught the same way — by two independent builders disagreeing — which
# is why cross-machine reproducibility is what to spend effort on.
#
#   nix-build frontend            # the built page, as $out
#   nix-build frontend --check    # build again and compare, byte for byte
#
# `pkgs` is an argument so that `image/app` passes its own and the whole image
# shares one nixpkgs pin. The default is the SAME pin, spelled again here, so
# that the command above works on its own — which matters, because filling in
# the hash below is the one thing that has to be done by hand.
#
# `x86_64-linux` rather than the caller's platform, and not as a convenience:
# the fetch collects platform-specific binaries (see `prePnpmInstall`), so it
# has to happen for the system the image is built for.
{ pkgs ? import
    (builtins.fetchTarball {
      # nixos-26.05 @ 2026-08-23 — same pin as the rest of image/.
      url = "https://github.com/NixOS/nixpkgs/archive/a3b98866eecd08edac6e61a3081e69540a35020f.tar.gz";
      sha256 = "0gy7jvdm3yfr2mddcch4yr7l8nw5y21gfls5in05j1f282bcr9mh";
    })
    { system = "x86_64-linux"; }
}:
let
  # The major version by NAME, not `pkgs.pnpm`. A pnpm reads one lockfile
  # format, so this line and `pnpm-lock.yaml`'s `lockfileVersion` are one fact
  # written twice — inheriting the pin's default would let a nixpkgs bump change
  # which lockfile this build demands, silently, in a commit about something
  # else. Named here, a bump fails loudly instead.
  #
  # 11 and not 8, which is what wrote the committed lockfile until now: in this
  # pin, `pnpm_8` and `pnpm_9` both carry seven known vulnerabilities and only
  # 10 and 11 are clean. Since the older format is readable only by the
  # vulnerable pair, the format had to move with them.
  #
  # Moving again is a deliberate act: regenerate the lockfile under the new
  # version (`pnpm install --lockfile-only`), review what re-resolved, commit
  # that, and change this line. Never the other way round — a lockfile the build
  # environment cannot reproduce is a dependency set nobody can check.
  pnpm = pkgs.pnpm_11;
  nodejs = pkgs.nodejs;
in
pkgs.stdenv.mkDerivation (finalAttrs: {
  pname = "enclavid-frontend";
  version = "0.0.0";

  # Filtered for the same reason `image/app` filters the workspace: an
  # unfiltered tree would put the previous build's output, and every package the
  # developer happens to have installed, into this build's input hash.
  src = builtins.path {
    name = "enclavid-frontend-src";
    path = ./.;
    filter = path: type:
      let base = baseNameOf path; in
      !(base == "node_modules" || base == "dist" || base == ".DS_Store");
  };

  # `pnpm` itself as well as the hook: the hook resolves the binary from PATH
  # and the override only tells it which one to expect, so naming one without
  # the other leaves it looking for a pnpm that is not there.
  nativeBuildInputs = [ nodejs pnpm (pkgs.pnpmConfigHook.override { inherit pnpm; }) ];

  pnpmDeps = pkgs.fetchPnpmDeps {
    inherit (finalAttrs) pname version src;
    inherit pnpm;

    # Which layout the fetched store is written in, and therefore what the hash
    # below is a hash OF. Required rather than defaulted, deliberately: a
    # fetcher that silently changed shape would change every hash in the tree at
    # once, and nobody could tell that from a dependency having moved.
    fetcherVersion = 3;

    # THE BUNDLER IS A NATIVE BINARY, and so are two more of these tools:
    #
    #   @rolldown/binding-*      Vite 8's bundler — Vite is no longer Rollup-on-JS
    #   @tailwindcss/oxide-*     Tailwind 4's engine
    #   lightningcss-*           the CSS transformer
    #
    # They arrive prebuilt from npm, one package per platform, and pnpm installs
    # only the one it is running on. Nothing here has to select that, because
    # this fetch and the build below both happen on the system fixed at the top
    # of this file — so the binaries collected are the binaries used.
    #
    # It does mean the hash is a function of that system as well as of the
    # lockfile. Fetching on one platform and building on another would fail
    # loudly, at `vite build`, with no binding for the host — never as a page
    # that quietly came out different.

    # The whole fetched dependency set, by content. This is what lets the fetch
    # reach the network at all — nix allows that only for a derivation whose
    # output is declared in advance — and it is therefore also what stops any of
    # those binaries being swapped afterwards.
    #
    # It cannot be computed without fetching, so it is obtained once and pasted:
    #
    #   nix-build frontend    # on a mismatch, read the `got: sha256-…` line
    #
    # It changes when the lockfile changes, which is the point: a dependency
    # cannot move without moving a line in this file.
    hash = "sha256-1E6fz2yezfeDCBtCsxsk9Em06v4wJhPEXM8UTgvZ92Y=";
  };

  buildPhase = ''
    runHook preBuild
    pnpm build
    runHook postBuild
  '';

  # `$out` IS the built page, with no directory above it, so `crates/api`'s build
  # script can be pointed straight at it.
  installPhase = ''
    runHook preInstall
    cp -r dist $out
    runHook postInstall
  '';

  # What has actually been checked, on 2026-09-16:
  #
  #   * `nix-build --check` passed — nix rebuilt this derivation and found no
  #     difference, so the build is reproducible under the pin;
  #   * no absolute path appears anywhere in the bundle;
  #   * no timestamp or build date appears anywhere in the bundle.
  #
  # What that does NOT establish is agreement between two DIFFERENT machines,
  # which is the form that carries the weight: a backdoor delivered to one
  # builder shows up as two builders disagreeing, and one machine agreeing with
  # itself cannot see that. Running `nix-build --check` somewhere else is the
  # outstanding step.
  meta = {
    description = "The applicant-facing page, built into api's measurement";
  };
})
