#!/bin/sh
# launcher/attestation/verify-rtmr3.sh — post-boot operator check that
# RTMR3 reflects the story-kernel ELF we expect.  This is the
# *verification* counterpart to mkosi.skeleton's extend-rtmr3.sh.
#
# Use cases:
#   - Operator: after boot, confirm RTMR3 ≡ approved code_commitment.
#   - Auditor: independently re-derive code_commitment from a fresh
#     TDX quote and compare against the on-chain whitelist value.
#
# Reads the same configfs-tsm interface that extend-rtmr3.sh writes,
# extracts RTMR3 from the resulting quote, and derives:
#
#   code_commitment = keccak256(RTMR3)
#
# which is exactly the value TDXValidationHook.approvedBinary[] keys on.
set -eu

REPORT_PATH=${TDX_REPORT_PATH:-/sys/kernel/config/tsm/report}
SUDO=${SUDO:-sudo}
PYTHON=${PYTHON:-python3}

if [ ! -d "$REPORT_PATH" ]; then
    echo "verify-rtmr3: configfs-tsm not available at $REPORT_PATH" >&2
    exit 1
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "verify-rtmr3: $PYTHON not found" >&2
    exit 1
fi

if ! "$PYTHON" -c 'import eth_utils; eth_utils.keccak(b"")' >/dev/null 2>&1; then
    echo "verify-rtmr3: $PYTHON cannot keccak256 — install eth-utils + pycryptodome:" >&2
    echo "  pip install eth-utils \"eth-hash[pycryptodome]\"" >&2
    exit 1
fi

TMPQUOTE=$(mktemp)
cleanup() {
    rm -f "$TMPQUOTE"
    $SUDO rmdir "$REPORT_PATH/req-verify" 2>/dev/null || true
}
trap cleanup EXIT

# Request a fresh quote.  The extend operations have already happened
# during boot; we only need the resulting RTMR values, so report_data
# is zero.
$SUDO rmdir "$REPORT_PATH/req-verify" 2>/dev/null || true
$SUDO mkdir "$REPORT_PATH/req-verify"
$SUDO dd if=/dev/zero of="$REPORT_PATH/req-verify/inblob" bs=64 count=1 2>/dev/null

# Use shell redirect (not `dd of=$TMPQUOTE`) so the write happens as the
# invoking user, not root.  Otherwise AppArmor on some distros (notably
# GCP Ubuntu 24.04) denies sudo dd writing to a user-owned tempfile.
# Read the whole quote (no count cap): RTMR3 sits at a fixed early offset, but
# a quote that carries the full PCK certificate chain can be larger than any
# fixed cap, so we never want a partial read here.
$SUDO dd if="$REPORT_PATH/req-verify/outblob" bs=64k 2>/dev/null > "$TMPQUOTE"

# RTMR3 is at offset 520 in the V4/V5 TDX quote (header 48 + body offset 472
# = 520 for the 4th RTMR).  Mirrors TDXValidationHook.sol OFFSET_RTMR3.
RTMR3_OFF=520
MEAS_LEN=48

rtmr3=$(xxd -p -s "$RTMR3_OFF" -l "$MEAS_LEN" "$TMPQUOTE" | tr -d '\n')

# Fail closed on a short or failed read.  A truncated/empty quote leaves $rtmr3
# empty (set -eu does not abort on an empty command substitution), and we would
# otherwise print keccak256("") as a confident-looking but wrong binary
# commitment with exit 0 — which an operator could mistakenly trust.
if [ "${#rtmr3}" -ne $((MEAS_LEN * 2)) ]; then
	echo "verify-rtmr3: read back ${#rtmr3} hex chars for RTMR3, expected $((MEAS_LEN * 2)); quote truncated or malformed" >&2
	exit 1
fi

# Pass the hex via argv, not by interpolating it into the Python source, so the
# shell value is never parsed as code.  (The length guard above already pins it
# to 96 hex chars; this keeps the pattern robust regardless.)
binary=$("$PYTHON" -c '
import sys
from eth_utils import keccak
buf = bytes.fromhex(sys.argv[1])
print(keccak(buf).hex())
' "$rtmr3")

cat <<EOF
=== TDX RTMR3 (binary measurement register) ===
RTMR3 = 0x$rtmr3

=== Binary commitment ===
keccak256(RTMR3) = 0x$binary

This is the value TDXValidationHook.approvedBinary[] keys on for the
story-kernel ELF currently running inside this TD.

Compare with the published reference for the released build:
    contracts/script/tdx/approved-binaries.json
A mismatch means either:
  - the running binary is not the one governance approved
  - the boot chain did not execute extend-rtmr3.sh successfully
Either way, register-tx will fail at the on-chain validation hook.
EOF
