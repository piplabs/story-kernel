#!/bin/sh
# verify-platform.sh — extract MRTD/RTMR0..2 from a fresh TDX quote and
# compute the platform commitment that TDXValidationHook.approvedPlatforms
# expects.
#
# Use cases:
#   1. Image builder: after baking a reproducible TD image, boot it once,
#      run this script, capture the platform_commitment hex, then submit
#      that value to governance via TDXValidationHook.approvePlatform().
#   2. Auditor: independently rebuild the standard image, boot, and
#      confirm the same platform_commitment falls out.
#   3. Operator: after booting the published image, confirm the
#      platform_commitment matches the on-chain whitelist before trusting
#      the node for production work.
#
# Requires:
#   - configfs-tsm (Linux kernel >= 6.7) at /sys/kernel/config/tsm/report/
#   - python3 with eth-utils + pycryptodome backend, e.g. via venv:
#       sudo apt install -y python3-venv
#       python3 -m venv ~/eth-venv
#       ~/eth-venv/bin/pip install eth-utils "eth-hash[pycryptodome]"
#     then either prepend $HOME/eth-venv/bin to PATH, or pass
#     PYTHON=$HOME/eth-venv/bin/python3 when invoking this script.
#   - sudo (to access configfs-tsm); not needed if the user has
#     write access to /sys/kernel/config/tsm/report/
set -eu

REPORT_PATH=${TDX_REPORT_PATH:-/sys/kernel/config/tsm/report}
SUDO=${SUDO:-sudo}
PYTHON=${PYTHON:-python3}

if [ ! -d "$REPORT_PATH" ]; then
    echo "verify-platform: configfs-tsm not available at $REPORT_PATH" >&2
    echo "  Linux >= 6.7 is required; on older kernels the legacy /dev/tdx_guest" >&2
    echo "  ioctl path is intentionally not supported." >&2
    exit 1
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "verify-platform: $PYTHON not found (override with PYTHON=...)" >&2
    exit 1
fi
if ! "$PYTHON" -c 'import eth_utils; eth_utils.keccak(b"")' >/dev/null 2>&1; then
    echo "verify-platform: $PYTHON cannot keccak256 — install eth-utils + pycryptodome:" >&2
    echo "  pip install eth-utils \"eth-hash[pycryptodome]\"" >&2
    echo "  (eth-utils alone has no default backend; the empty-string keccak probe just failed)" >&2
    exit 1
fi

TMPQUOTE=$(mktemp)
cleanup() {
    rm -f "$TMPQUOTE"
    $SUDO rmdir "$REPORT_PATH/req" 2>/dev/null || true
}
trap cleanup EXIT

# Request a fresh quote with zero report_data (we only care about the
# measurement fields here; the binding to a registration payload happens
# at register-tx time, not for platform-commitment extraction).
$SUDO rmdir "$REPORT_PATH/req" 2>/dev/null || true
$SUDO mkdir "$REPORT_PATH/req"
$SUDO dd if=/dev/zero of="$REPORT_PATH/req/inblob" bs=64 count=1 2>/dev/null
# Read the WHOLE quote (no count= cap): a full PCK-chain quote can exceed any
# fixed cap, and a short read would silently yield truncated/empty measurement
# fields. Redirect (not dd of=) works around AppArmor on GCP Ubuntu.
$SUDO dd if="$REPORT_PATH/req/outblob" bs=64k 2>/dev/null > "$TMPQUOTE"

# Absolute offsets into the V4/V5 quote (header 48 + body) — same as
# contracts/src/protocol/TDXValidationHook.sol OFFSET_* constants.
MRTD_OFF=184
RTMR0_OFF=376
RTMR1_OFF=424
RTMR2_OFF=472
MEAS_LEN=48

mrtd=$(xxd  -p -s "$MRTD_OFF"  -l "$MEAS_LEN" "$TMPQUOTE" | tr -d '\n')
rtmr0=$(xxd -p -s "$RTMR0_OFF" -l "$MEAS_LEN" "$TMPQUOTE" | tr -d '\n')
rtmr1=$(xxd -p -s "$RTMR1_OFF" -l "$MEAS_LEN" "$TMPQUOTE" | tr -d '\n')
rtmr2=$(xxd -p -s "$RTMR2_OFF" -l "$MEAS_LEN" "$TMPQUOTE" | tr -d '\n')

# Fail closed on a short/empty read: each measurement must be exactly 48 bytes
# (96 hex chars). Without this, a truncated quote would print a confident but
# wrong platform_commitment with exit 0.
for pair in "MRTD:$mrtd" "RTMR0:$rtmr0" "RTMR1:$rtmr1" "RTMR2:$rtmr2"; do
    name=${pair%%:*}
    val=${pair#*:}
    if [ "${#val}" -ne 96 ]; then
        echo "verify-platform: $name is ${#val} hex chars, expected 96 — quote read too short?" >&2
        exit 1
    fi
done

# Pass the concatenation as argv, not interpolated into the Python source.
platform=$("$PYTHON" -c '
import sys
from eth_utils import keccak
print(keccak(bytes.fromhex(sys.argv[1])).hex())
' "${mrtd}${rtmr0}${rtmr1}${rtmr2}")

cat <<EOF
=== TDX measurement fields (V4/V5 quote, absolute offsets) ===
MRTD  = 0x$mrtd
RTMR0 = 0x$rtmr0
RTMR1 = 0x$rtmr1
RTMR2 = 0x$rtmr2

=== Platform commitment ===
keccak256(MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2) = 0x$platform

Submit this hex to TDXValidationHook.approvePlatform(0x$platform, '<label>')
for the standard image to be accepted on-chain.

If you are an auditor reproducing the build, compare the four 48-byte
measurements above against the published reference. A mismatch means
your build is not byte-identical to the one governance approved — your
image will be rejected by approvedPlatforms[] at register time.
EOF
