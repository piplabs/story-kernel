#!/bin/sh
# launcher/boot/dm-verity-build.sh — generate dm-verity hash tree and
# root hash for a given rootfs.raw.
#
# Authoritative dm-verity for the booted image is built by mkosi from the
# root + root-verity partitions in mkosi/mkosi.repart/, and its roothash is
# injected into the measured UKI command line. build/build.sh reads that
# roothash — it does NOT call this script.
#
# This script remains a STANDALONE auditor tool: given a published rootfs
# partition image, it re-derives the roothash so an auditor can confirm it
# matches the on-chain platform approval. It must use the same veritysetup
# parameters mkosi uses, or the recomputed roothash will not match.
set -eu

ROOTFS=${1:?dm-verity-build: rootfs path required}
HASHTREE=${2:-${ROOTFS}.verity}
ROOTHASH_OUT=${3:-${ROOTFS}.roothash}

if [ ! -r "$ROOTFS" ]; then
    echo "dm-verity-build: cannot read $ROOTFS" >&2
    exit 1
fi
if ! command -v veritysetup >/dev/null 2>&1; then
    echo "dm-verity-build: veritysetup not found (install cryptsetup-bin)" >&2
    exit 1
fi

echo "dm-verity-build: rootfs   = $ROOTFS"
echo "dm-verity-build: hashtree = $HASHTREE"
echo "dm-verity-build: roothash = $ROOTHASH_OUT"

# Use a deterministic salt and a fixed FEC layout so re-runs against the
# same rootfs.raw produce the same hash tree.  The salt is derived from
# the SHA-256 of the rootfs itself, which keeps it deterministic without
# allowing pre-computation against an arbitrary salt.
SALT=$(sha256sum "$ROOTFS" | awk '{print $1}')

# `veritysetup format` writes:
#   - the hash tree into $HASHTREE
#   - the root hash to stdout (we grep it out)
ROOTHASH=$(veritysetup format \
    --salt="$SALT" \
    --hash=sha256 \
    --data-block-size=4096 \
    --hash-block-size=4096 \
    --uuid=00000000-0000-0000-0000-000000000000 \
    "$ROOTFS" "$HASHTREE" \
    | awk '/^Root hash:/ { print $3 }')

if [ -z "$ROOTHASH" ]; then
    echo "dm-verity-build: failed to parse root hash from veritysetup output" >&2
    exit 1
fi

# Persist for the build pipeline / auditor.
echo "$ROOTHASH" > "$ROOTHASH_OUT"

echo
echo "dm-verity-build: SUCCESS"
echo "  rootfs SHA-256 : $(sha256sum "$ROOTFS" | awk '{print $1}')"
echo "  hashtree SHA-256: $(sha256sum "$HASHTREE" | awk '{print $1}')"
echo "  root hash      : $ROOTHASH"
echo
echo "Add to kernel cmdline:"
echo "  root=/dev/dm-0 \\"
echo "  systemd.verity=yes \\"
echo "  systemd.verity_root_data=<PARTUUID of $ROOTFS partition> \\"
echo "  systemd.verity_root_hash=<PARTUUID of $HASHTREE partition> \\"
echo "  roothash=$ROOTHASH"
