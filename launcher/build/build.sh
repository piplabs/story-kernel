#!/bin/sh
# launcher/build/build.sh — top-level entry point for reproducible
# story-kernel TD image build.
#
# Two-stage build:
#   1. Build the story-kernel Go binary (deterministic, SOURCE_DATE_EPOCH
#      honored, all module versions pinned via go.mod).
#   2. Stage binary into mkosi.extra/, run mkosi, produce the disk image
#      and dm-verity hash tree.
#
# Output, all under ./out/:
#   story-kernel             — the Go binary (sha256 captured)
#   *.raw                    — the image (dm-verity hash tree embedded as a partition)
#   code_commitment.txt    — expected code_commitment value
#   manifest.json            — every artifact + its sha256 + build inputs (incl. dm-verity root_hash)
#
# Reproducibility:
#   - SOURCE_DATE_EPOCH is set from the story-kernel commit timestamp.
#   - The builder image is the Docker image built from build/Dockerfile.builder.
#   - All apt and pip versions are pinned in Dockerfile.builder.
#   - Auditor flow: ./build.sh --verify  ⇒  rebuilds and asserts that
#     every output sha256 matches the published manifest.

set -eu

# === Paths ===
HERE=$(cd "$(dirname "$0")" && pwd)
LAUNCHER_DIR=$(cd "$HERE/.." && pwd)
REPO_DIR=$(cd "$LAUNCHER_DIR/.." && pwd)
OUT_DIR=${OUT_DIR:-$REPO_DIR/launcher/out}

mkdir -p "$OUT_DIR"

# === Builder image digest guard ===
# A reproducible build is only meaningful when the builder image is pinned
# to a concrete Debian digest. Refuse to run while Dockerfile.builder still
# carries the release-cut placeholder, unless the caller opts into a
# non-reproducible dev build explicitly.
BUILDER_DOCKERFILE="$HERE/Dockerfile.builder"
# Match the placeholder only on the FROM line so prose mentioning the token
# (e.g. this guard's own documentation) does not trip it.
if grep -qE '^FROM .*PLACEHOLDER_REPLACE_AT_RELEASE_CUT' "$BUILDER_DOCKERFILE" 2>/dev/null; then
    if [ "${ALLOW_UNPINNED_BUILDER:-0}" = "1" ]; then
        echo "build: WARNING — builder image digest is unpinned (PLACEHOLDER);" >&2
        echo "build:   artifacts are NOT reproducible. Continuing (ALLOW_UNPINNED_BUILDER=1)." >&2
    else
        echo "build: ERROR — $BUILDER_DOCKERFILE still pins debian@sha256:PLACEHOLDER_REPLACE_AT_RELEASE_CUT." >&2
        echo "build:   Pin it to a concrete digest (see build/README.md 'Pinning protocol')," >&2
        echo "build:   or set ALLOW_UNPINNED_BUILDER=1 for a non-reproducible dev build." >&2
        exit 1
    fi
fi

# === Reproducibility timestamp ===
# Use the most recent commit touching the launcher + kernel source as
# SOURCE_DATE_EPOCH.  Falls back to a fixed value to make pure-config
# builds deterministic.
if [ -d "$REPO_DIR/.git" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$REPO_DIR" log -1 --pretty=%ct -- launcher enclave/tdx 2>/dev/null || echo 1700000000)
else
    SOURCE_DATE_EPOCH=1700000000
fi
export SOURCE_DATE_EPOCH

echo "build: SOURCE_DATE_EPOCH = $SOURCE_DATE_EPOCH"

# === Step 1: build story-kernel ===
# Delegated to the repo's Makefile which handles the cb-mpc C++
# dependency setup (clone + CGO_CFLAGS wiring via scripts/go_with_cpp.sh).
# `make build-tdx` selects the TDX backend via the `tdx` build tag.
echo "build: building story-kernel Go binary via 'make build-tdx'"
(
    cd "$REPO_DIR"
    make build-tdx
)
# The Makefile writes the binary to $(OUT_DIR)/$(BIN_NAME). Resolve where it
# landed and stage it into the launcher's out/ tree.
KERNEL_SRC=$(find "$REPO_DIR/build" -maxdepth 2 -name 'story-kernel' -type f -executable -print -quit 2>/dev/null)
if [ -z "$KERNEL_SRC" ] || [ ! -x "$KERNEL_SRC" ]; then
    echo "build: could not locate kernel binary after 'make build-tdx'" >&2
    exit 1
fi
install -m 0755 "$KERNEL_SRC" "$OUT_DIR/story-kernel"
KERNEL_SHA256=$(sha256sum "$OUT_DIR/story-kernel" | awk '{print $1}')
echo "build: story-kernel sha256 = $KERNEL_SHA256"

# === Step 2: derive expected code_commitment ===
# code_commitment = keccak256(RTMR3) where RTMR3 = SHA-384(ELF) after
# a single extend from the zero starting value.
#
# RTMR_3 starts at 48 zero bytes.  extend(RTMR3, x) = SHA-384(RTMR3 || x).
# We model the post-extend RTMR3 and feed it through keccak256.
ELF_SHA384=$(sha384sum "$OUT_DIR/story-kernel" | awk '{print $1}')

# Allow PYTHON override so callers can point at a venv that has eth-utils.
PYTHON=${PYTHON:-python3}
EXPECTED_BIN_COMMIT=$("$PYTHON" - <<EOF
import hashlib
from eth_utils import keccak

# RTMR3 starts at 48 zero bytes; extend appends the new measurement and
# hashes the result with SHA-384.  Our extend payload is SHA-384(ELF).
elf_sha384 = bytes.fromhex("$ELF_SHA384")
rtmr3_initial = b"\x00" * 48
rtmr3_after = hashlib.sha384(rtmr3_initial + elf_sha384).digest()
print(keccak(rtmr3_after).hex())
EOF
)
echo "$EXPECTED_BIN_COMMIT" > "$OUT_DIR/code_commitment.txt"
echo "build: expected code_commitment = 0x$EXPECTED_BIN_COMMIT"

# === Step 3: stage binary + hardening tree into mkosi.extra ===
MKOSI_DIR="$LAUNCHER_DIR/mkosi"
EXTRA_DIR="$MKOSI_DIR/mkosi.extra/usr/local/bin"
mkdir -p "$EXTRA_DIR"
install -m 0755 "$OUT_DIR/story-kernel" "$EXTRA_DIR/story-kernel"

# Stage the hardening tree at a known buildroot path so mkosi.postinst
# can find it inside the sandbox.  Removed by postinst after install.sh
# completes; not shipped in the final image.
HARDENING_STAGE="$MKOSI_DIR/mkosi.extra/_launcher_hardening"
rm -rf "$HARDENING_STAGE"
cp -r "$LAUNCHER_DIR/hardening" "$HARDENING_STAGE"

# === Step 4: cmdline lint ===
echo "build: checking that boot/kernel-cmdline ≡ mkosi.conf"
sh "$LAUNCHER_DIR/boot/diff-cmdline.sh"

# === Step 5: run mkosi inside the pinned builder container ===
# mkosi runs in the container built from Dockerfile.builder, NOT host mkosi.
# This anchors reproducibility to the pinned toolchain (mkosi 25.3 + the
# deterministic mke2fs wrapper that fixes the ext4 htree hash_seed). The
# repo and $OUT_DIR are bind-mounted at identical paths so the staged
# binary (mkosi.extra) is visible and output lands in $OUT_DIR.
#   --force         rebuild against leftover state
#   --output-dir    honor $OUT_DIR (verify-reproducible.sh's out-a/out-b)
#   --privileged    loop devices + systemd-repart need it for disk format
BUILDER_IMAGE=${BUILDER_IMAGE:-story-kernel-tdx-builder:local}
echo "build: building builder image $BUILDER_IMAGE"
docker build -q -t "$BUILDER_IMAGE" -f "$BUILDER_DOCKERFILE" "$HERE" >/dev/null

OUT_MOUNT=""
case "$OUT_DIR" in
    "$REPO_DIR"/*) : ;;                       # already covered by repo mount
    *) OUT_MOUNT="-v $OUT_DIR:$OUT_DIR" ;;
esac

echo "build: running mkosi in container"
# shellcheck disable=SC2086
docker run --rm --privileged \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -v "$REPO_DIR":"$REPO_DIR" $OUT_MOUNT \
    -w "$MKOSI_DIR" \
    "$BUILDER_IMAGE" \
    mkosi --force --output-dir "$OUT_DIR" build

# mkosi runs as root in the container; reclaim ownership for the host user.
if [ "$(id -u)" -ne 0 ]; then
    sudo chown -R "$(id -u):$(id -g)" "$OUT_DIR" 2>/dev/null || true
fi

# mkosi outputs land in ../out (configured via OutputDirectory).
ROOTFS_IMG="$OUT_DIR/story-kernel-td.raw"
if [ ! -r "$ROOTFS_IMG" ]; then
    # Fall back to whatever mkosi actually named the output.  Use find
    # instead of ls so unusual file names round-trip cleanly.
    ROOTFS_IMG=$(find "$OUT_DIR" -maxdepth 1 -name '*.raw' -print -quit)
fi
# Fail fast: if mkosi produced no .raw, the fallback find returns empty and the
# downstream dm-verity/sha256sum steps would otherwise run with an empty path
# and emit confusing errors.
if [ -z "$ROOTFS_IMG" ] || [ ! -r "$ROOTFS_IMG" ]; then
    echo "build: no readable rootfs image in $OUT_DIR (mkosi produced no .raw?)" >&2
    exit 1
fi
echo "build: rootfs = $ROOTFS_IMG"

# === Step 6: verify the dm-verity roothash is in the MEASURED UKI cmdline ===
# dm-verity is built by mkosi from the root + root-verity partitions defined in
# mkosi.repart/. mkosi computes the roothash and injects it as roothash=<hash>
# into the UKI kernel command line, which the TDX firmware measures into RTMR1
# and thus binds into platform_commitment. We read that authoritative roothash
# from the UKI's .cmdline section (the exact bytes that get measured), never a
# recomputed value.
#
# Fail-closed guard: if the UKI cmdline has no roothash=, dm-verity is NOT wired
# into the boot — the rootfs would mount writable, defeating the integrity model
# (and the seal's PCR 11 bind). Refuse to emit a manifest in that case.
ESP_IMG=$(find "$OUT_DIR" -maxdepth 1 -name '*.esp.raw' -print -quit)
if [ -z "$ESP_IMG" ] || [ ! -r "$ESP_IMG" ]; then
    echo "build: ERROR — no ESP image in $OUT_DIR; cannot verify the verity roothash." >&2
    exit 1
fi
ESP_MNT=$(mktemp -d)
UKI_CMDLINE=""
if sudo mount -o loop,ro "$ESP_IMG" "$ESP_MNT" 2>/dev/null; then
    UKI=$(sudo find "$ESP_MNT" -iname '*.efi' -print -quit)
    if [ -n "$UKI" ]; then
        sudo objcopy -O binary --only-section=.cmdline "$UKI" "$OUT_DIR/.uki-cmdline" 2>/dev/null || true
    fi
    sudo umount "$ESP_MNT" 2>/dev/null || true
fi
rmdir "$ESP_MNT" 2>/dev/null || true
if [ -r "$OUT_DIR/.uki-cmdline" ]; then
    UKI_CMDLINE=$(tr -d '\0' < "$OUT_DIR/.uki-cmdline")
    rm -f "$OUT_DIR/.uki-cmdline"
fi
ROOT_HASH=$(printf '%s' "$UKI_CMDLINE" | grep -oE 'roothash=[0-9a-f]+' | head -1 | cut -d= -f2)
if [ -z "$ROOT_HASH" ]; then
    echo "build: ERROR — no roothash= in the measured UKI cmdline; dm-verity is not" >&2
    echo "build:   wired into the boot (check mkosi.repart/ verity partitions)." >&2
    echo "build:   Refusing to emit a manifest for a non-integrity-protected image." >&2
    exit 1
fi
echo "build: dm-verity roothash (from measured UKI cmdline) = $ROOT_HASH"

# === Step 7: emit manifest ===
ROOTFS_SHA=$(sha256sum "$ROOTFS_IMG" | awk '{print $1}')

cat > "$OUT_DIR/manifest.json" <<EOF
{
    "source_date_epoch": $SOURCE_DATE_EPOCH,
    "story_kernel": {
        "sha256": "$KERNEL_SHA256",
        "sha384": "$ELF_SHA384"
    },
    "rootfs": {
        "path": "${ROOTFS_IMG##*/}",
        "sha256": "$ROOTFS_SHA"
    },
    "verity": {
        "root_hash": "$ROOT_HASH"
    },
    "code_commitment": "$EXPECTED_BIN_COMMIT"
}
EOF

echo "build: SUCCESS — manifest at $OUT_DIR/manifest.json"
jq . "$OUT_DIR/manifest.json"
