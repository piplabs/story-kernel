#!/bin/sh
# launcher/boot/dm-verity-build.sh — generate dm-verity hash tree and
# root hash for a given rootfs.raw.
#
# Two callers:
#   1. build/build.sh after mkosi produces rootfs.raw — bakes the hash
#      tree into the final image artifact.
#   2. Auditors who want to independently re-derive the root hash from
#      a published rootfs.raw to confirm it matches the on-chain value.
#
# mkosi natively supports verity via SplitArtifacts=roothash, so under
# normal use this script is invoked by build/build.sh as a final
# verification step rather than as the primary generator.  It still
# works standalone for the auditor case.
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
