#!/usr/bin/env bash
# Build a guest kernel and print its digest.
#
# A thin wrapper: default.nix holds the actual recipe, and is the only place
# versions and digests are pinned. Kept as a script purely so the invocation is
# discoverable — running nix-build directly is equivalent.
#
#   ./build.sh base               api, gateway
#   ./build.sh compile-worker     the compile-worker
#   ./build.sh execution-worker   the execution-worker
#   ./build.sh storage            the storage CVM
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
role=${1:-base}

out=$(nix-build "$here" -A "$role" --no-out-link)

echo "role:    $role"
echo "bzImage: $out/bzImage"
cat "$out/bzImage.sha256"
