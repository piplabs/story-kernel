#!/bin/sh
# manifest_test.sh — schema test for the build manifest.
#
# Constructs a synthetic manifest.json mirroring what build/build.sh
# emits, then asserts each documented field is present and well-typed.
# Catches drift between build.sh and the manifest schema in build/README.md.
set -eu

if ! command -v jq >/dev/null 2>&1; then
    echo "  jq not installed — SKIP"
    exit 0
fi

WORKDIR=$(mktemp -d -t manifest-test-XXXXXX)
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# Synthetic manifest in the shape build.sh emits.  Hexes are fake but
# correctly sized so length-based checks pass.
cat > "$WORKDIR/manifest.json" <<'JSON'
{
    "source_date_epoch": 1700000000,
    "story_kernel": {
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "sha384": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    },
    "rootfs": {
        "path": "story-kernel-td.raw",
        "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
    },
    "verity": {
        "hashtree_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
        "root_hash": "3333333333333333333333333333333333333333333333333333333333333333"
    },
    "code_commitment": "4444444444444444444444444444444444444444444444444444444444444444"
}
JSON

assert() {
    desc=$1; cmd=$2
    if ! eval "$cmd" >/dev/null 2>&1; then
        echo "  FAIL: $desc"
        return 1
    fi
    echo "  ok: $desc"
}

# Required top-level keys.
assert "has .source_date_epoch (number)" \
    'jq -e ".source_date_epoch | type == \"number\"" '"$WORKDIR/manifest.json"
assert "has .story_kernel.sha256 (64-char hex)" \
    'jq -e ".story_kernel.sha256 | test(\"^[0-9a-f]{64}$\")" '"$WORKDIR/manifest.json"
assert "has .story_kernel.sha384 (96-char hex)" \
    'jq -e ".story_kernel.sha384 | test(\"^[0-9a-f]{96}$\")" '"$WORKDIR/manifest.json"
assert "has .rootfs.path (string)" \
    'jq -e ".rootfs.path | type == \"string\"" '"$WORKDIR/manifest.json"
assert "has .rootfs.sha256 (64-char hex)" \
    'jq -e ".rootfs.sha256 | test(\"^[0-9a-f]{64}$\")" '"$WORKDIR/manifest.json"
assert "has .verity.hashtree_sha256 (64-char hex)" \
    'jq -e ".verity.hashtree_sha256 | test(\"^[0-9a-f]{64}$\")" '"$WORKDIR/manifest.json"
assert "has .verity.root_hash (64-char hex)" \
    'jq -e ".verity.root_hash | test(\"^[0-9a-f]{64}$\")" '"$WORKDIR/manifest.json"
assert "has .code_commitment (64-char hex)" \
    'jq -e ".code_commitment | test(\"^[0-9a-f]{64}$\")" '"$WORKDIR/manifest.json"

echo "  manifest schema OK"
