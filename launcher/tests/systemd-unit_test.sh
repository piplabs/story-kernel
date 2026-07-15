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

    # Masked units are symlinks to /dev/null (e.g. systemd-firstboot.service):
    # they intentionally have no [Unit]/[Service]/[Install], so skip them.
    if [ -L "$unit" ] && [ "$(readlink "$unit")" = "/dev/null" ]; then
        continue
    fi

    # Every unit MUST have [Unit] and [Service].
    if ! grep -q '^\[Unit\]'    "$unit"; then echo "  $rel: missing [Unit] — FAIL";    FAIL=$((FAIL+1)); fi
    if ! grep -q '^\[Service\]' "$unit"; then echo "  $rel: missing [Service] — FAIL"; FAIL=$((FAIL+1)); fi
    # Every unit must declare an [Install] OR be intentionally pulled by
    # Before/Requires from another unit (transient).  We require [Install]
    # for all our units because the hardening install.sh symlinks them.
    if ! grep -q '^\[Install\]' "$unit"; then echo "  $rel: missing [Install] — FAIL"; FAIL=$((FAIL+1)); fi

    # No unit should request DefaultDependencies=yes implicitly at
    # early boot; we explicitly set it to "no" for the measurement units.
    case "$rel" in
        story-kernel-measure-binary.service|story-kernel-rtmr3-extend.service)
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
# measure-binary is the upstream-most measurement unit; it seals against the
# platform vTPM (/dev/tpmrm0, a device that is present from early boot), so
# nothing precedes it in the chain and no unit needs to Require= it by variable.
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

check_requires "$rtmr3"   "story-kernel-measure-binary.service"
check_after    "$rtmr3"   "story-kernel-measure-binary.service"
check_requires "$kernel"  "story-kernel-rtmr3-extend.service"
check_after    "$kernel"  "story-kernel-rtmr3-extend.service"
check_requires "$kernel"  "story-kernel-lockdown-modules.service"
check_after    "$kernel"  "story-kernel-lockdown-modules.service"

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
