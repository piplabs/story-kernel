#!/bin/sh
# extend-rtmr3.sh — extend RTMR3 with SHA-384 of the story-kernel ELF.
#
# RTMR3 is the only RTMR we self-extend; RTMR0..RTMR2 come from the
# boot chain and are reflected in platform_commitment.  RTMR3 by
# convention holds the application's own measurement and binds
# code_commitment = keccak256(RTMR3).
#
# Uses the Linux tdx_guest misc-driver sysfs interface (kernel
# >= 6.11 with CONFIG_INTEL_TDX_GUEST=y).  Writing 48 bytes to
#
#   /sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384
#
# triggers a TDG.MR.RTMR.EXTEND(rtmr=3, data) TDCALL inside the TD,
# which the TDX module materializes as RTMR3 <- SHA-384(RTMR3 || data).
#
# Note: the older configfs-tsm interface (/sys/kernel/config/tsm/report/)
# is for *generating* attestation quotes, not for extending RTMRs.
set -eu

BINARY=${1:?extend-rtmr3: binary path required}

if [ ! -r "$BINARY" ]; then
    echo "extend-rtmr3: cannot read $BINARY" >&2
    exit 1
fi

# SHA-384 because the TDX RTMRs are SHA-384 throughout.
DIGEST_HEX=$(sha384sum "$BINARY" | awk '{print $1}')
if [ -z "$DIGEST_HEX" ] || [ ${#DIGEST_HEX} -ne 96 ]; then
    echo "extend-rtmr3: invalid SHA-384 digest for $BINARY" >&2
    exit 1
fi

echo "extend-rtmr3: RTMR3 <- SHA-384($BINARY) = $DIGEST_HEX"

RTMR3_PATH=/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384
if [ ! -w "$RTMR3_PATH" ]; then
    echo "extend-rtmr3: $RTMR3_PATH not writable (need CAP_SYS_ADMIN and Linux >= 6.11)" >&2
    exit 1
fi

# Convert the 96-char hex string to 48 binary bytes and write them
# in a single write() to trigger the TDCALL.  xxd is included via
# mkosi.conf for this purpose.
printf '%s' "$DIGEST_HEX" | xxd -r -p > "$RTMR3_PATH"

echo "extend-rtmr3: RTMR3 extended successfully"
