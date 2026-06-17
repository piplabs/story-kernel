#!/bin/sh
# measure-binary.sh — extend a PCR (default 12) with the SHA-256 of the
# given binary.  Mirrors launcher/attestation/measure-binary.sh but
# is tailored to the early-boot environment inside the TD image:
#
#   - No bash, only POSIX sh (busybox/dash compatible).
#   - Uses tpm2_* tools talking to the in-TD swtpm via TPM2TOOLS_TCTI
#     which is exported by the calling systemd unit.
#   - Exits non-zero on any error so the systemd unit fails closed.
set -eu

BINARY=${1:?measure-binary: binary path required}
PCR=${2:-12}

if [ ! -r "$BINARY" ]; then
    echo "measure-binary: cannot read $BINARY" >&2
    exit 1
fi

# Compute SHA-256 of the binary in hex.  sha256sum from coreutils is
# pinned via mkosi.conf; we do not rely on PATH lookups beyond that.
DIGEST=$(sha256sum "$BINARY" | awk '{print $1}')
if [ -z "$DIGEST" ] || [ ${#DIGEST} -ne 64 ]; then
    echo "measure-binary: invalid SHA-256 digest for $BINARY" >&2
    exit 1
fi

echo "measure-binary: PCR $PCR <- SHA-256($BINARY) = $DIGEST"

# tpm2_pcrextend takes <pcr>:<alg>=<hex>.  We extend only the sha256
# bank; if the image ever needs sha384 too the extend call duplicates
# accordingly.
tpm2_pcrextend "${PCR}:sha256=${DIGEST}"

# Read back the post-extend value so the journal records what we just
# committed.  Operator tooling (verify-pcr12.sh) compares this value.
tpm2_pcrread "sha256:${PCR}" -o /tmp/pcr-after.bin
echo "measure-binary: PCR $PCR after extend = $(xxd -p /tmp/pcr-after.bin | tr -d '\n')"
rm -f /tmp/pcr-after.bin
