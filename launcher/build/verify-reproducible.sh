#!/bin/sh
# launcher/build/verify-reproducible.sh — auditor entry point.
#
# Runs build.sh twice in fresh OUT_DIRs and asserts that every output
# sha256 matches.  If they do not, the build is not deterministic and
# the launcher cannot be considered reproducible.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
WORKDIR=$(mktemp -d -t story-kernel-verify-XXXXXX)
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "verify-reproducible: workdir = $WORKDIR"

OUT_DIR="$WORKDIR/out-a" sh "$HERE/build.sh"
OUT_DIR="$WORKDIR/out-b" sh "$HERE/build.sh"

# Compare manifests and primary artifacts.
diff -u "$WORKDIR/out-a/manifest.json" "$WORKDIR/out-b/manifest.json" || {
    echo "verify-reproducible: FAIL — manifests differ"
    exit 1
}

for f in story-kernel rootfs.verity root-hash.txt code_commitment.txt; do
    A_SHA=$(sha256sum "$WORKDIR/out-a/$f" | awk '{print $1}')
    B_SHA=$(sha256sum "$WORKDIR/out-b/$f" | awk '{print $1}')
    if [ "$A_SHA" != "$B_SHA" ]; then
        echo "verify-reproducible: FAIL — $f differs ($A_SHA vs $B_SHA)"
        exit 1
    fi
done

# rootfs.raw name varies; iterate all .raw files.
for raw in "$WORKDIR/out-a"/*.raw; do
    name=${raw##*/}
    if [ ! -r "$WORKDIR/out-b/$name" ]; then
        echo "verify-reproducible: FAIL — $name missing in second build"
        exit 1
    fi
    A_SHA=$(sha256sum "$raw"                    | awk '{print $1}')
    B_SHA=$(sha256sum "$WORKDIR/out-b/$name"    | awk '{print $1}')
    if [ "$A_SHA" != "$B_SHA" ]; then
        echo "verify-reproducible: FAIL — $name differs"
        exit 1
    fi
done

echo "verify-reproducible: PASS — both builds produced byte-identical artifacts"
