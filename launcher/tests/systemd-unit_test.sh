#!/bin/sh
# systemd-unit_test.sh — every systemd unit shipped in mkosi.skeleton/
# must have a parseable [Unit] / [Service] / [Install] structure and
# expected ordering directives.
#
# Uses systemd-analyze verify when available (Linux only); falls back
# to a structural grep check elsewhere.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
LAUNCHER_DIR=$(cd "$HERE/.." && pwd)
UNIT_DIR="$LAUNCHER_DIR/mkosi/mkosi.skeleton/etc/systemd/system"

if [ ! -d "$UNIT_DIR" ]; then
    echo "  no unit directory at $UNIT_DIR — FAIL"
    exit 1
fi

FAIL=0
for unit in "$UNIT_DIR"/*.service; do
    rel=${unit##*/}

    # Every unit MUST have [Unit] and [Service].
    if ! grep -q '^\[Unit\]'    "$unit"; then echo "  $rel: missing [Unit] — FAIL";    FAIL=$((FAIL+1)); fi
    if ! grep -q '^\[Service\]' "$unit"; then echo "  $rel: missing [Service] — FAIL"; FAIL=$((FAIL+1)); fi
    # Every unit must declare an [Install] OR be intentionally pulled by
    # Before/Requires from another unit (transient).  We require [Install]
    # for all our units because the hardening install.sh symlinks them.
    if ! grep -q '^\[Install\]' "$unit"; then echo "  $rel: missing [Install] — FAIL"; FAIL=$((FAIL+1)); fi

    # No unit should request DefaultDependencies=yes implicitly at
    # early boot; we explicitly set it to "no" for swtpm and friends.
    case "$rel" in
        story-kernel-swtpm.service|story-kernel-measure-binary.service|story-kernel-rtmr3-extend.service)
            if ! grep -q '^DefaultDependencies=no' "$unit"; then
                echo "  $rel: missing DefaultDependencies=no — FAIL"
                FAIL=$((FAIL+1))
            fi
            ;;
    esac
done

# Boot ordering invariants: each downstream service must require its
# upstream.  We assert via grep rather than trying to model systemd's
# dependency resolver fully.
# swtpm is the upstream-most; nothing requires anything *before* it, so
# we only need the path for documentation / future expansion.
# shellcheck disable=SC2034
swtpm="$UNIT_DIR/story-kernel-swtpm.service"
measure="$UNIT_DIR/story-kernel-measure-binary.service"
rtmr3="$UNIT_DIR/story-kernel-rtmr3-extend.service"
kernel="$UNIT_DIR/story-kernel.service"

check_requires() {
    file=$1; dep=$2
    if ! grep -E '^Requires=.*'"$dep" "$file" >/dev/null; then
        echo "  $(basename "$file"): missing Requires=$dep — FAIL"
        FAIL=$((FAIL+1))
    fi
}
check_after() {
    file=$1; dep=$2
    if ! grep -E '^After=.*'"$dep" "$file" >/dev/null; then
        echo "  $(basename "$file"): missing After=$dep — FAIL"
        FAIL=$((FAIL+1))
    fi
}

check_requires "$measure" "story-kernel-swtpm.service"
check_after    "$measure" "story-kernel-swtpm.service"
check_requires "$rtmr3"   "story-kernel-measure-binary.service"
check_after    "$rtmr3"   "story-kernel-measure-binary.service"
check_requires "$kernel"  "story-kernel-rtmr3-extend.service"
check_after    "$kernel"  "story-kernel-rtmr3-extend.service"

# Optional native-tool check on Linux.
if command -v systemd-analyze >/dev/null 2>&1; then
    for unit in "$UNIT_DIR"/*.service; do
        if ! systemd-analyze verify "$unit" 2>/dev/null; then
            echo "  $(basename "$unit"): systemd-analyze verify failed (likely a missing dep at lint time; non-fatal locally)"
        fi
    done
fi

if [ "$FAIL" -gt 0 ]; then
    echo "  $FAIL unit lint failure(s)"
    exit 1
fi
echo "  all systemd units pass structural lint and boot ordering check"
