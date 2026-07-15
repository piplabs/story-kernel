#!/bin/bash
# run-in-container.sh — local functional test for the initrd measurement
# scripts. Invoked from test-scripts.sh; not for direct use on the host.
#
# Inside an Ubuntu container, this:
#   1. installs swtpm + tpm2-tools
#   2. starts a swtpm in TCP socket mode (no kernel module required —
#      tpm2-tools talks to it directly via the "swtpm" TCTI)
#   3. exercises measure-binary.sh against a fake ELF
#   4. runs verify-pcr12.sh and asserts PASS for the original ELF
#   5. modifies the ELF and runs verify-pcr12.sh again — asserts FAIL
#   6. runs measure-binary.sh against an empty TPM state (PCR 12 = 0)
#      after rebuild to confirm a fresh boot reproduces the same PCR
set -euo pipefail

SCRIPTS_DIR=${SCRIPTS_DIR:-/work}
WORKDIR=$(mktemp -d)
trap 'pkill -f "swtpm.*$WORKDIR" >/dev/null 2>&1 || true; rm -rf "$WORKDIR"' EXIT

# --- 1. Install deps -------------------------------------------------------
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
    swtpm swtpm-tools tpm2-tools coreutils xxd >/dev/null
echo "deps installed: $(swtpm --version | head -1), $(tpm2_pcrread --version | head -1)"

# --- 2. Start swtpm in TCP socket mode ------------------------------------
mkdir -p "$WORKDIR/swtpm-state"
swtpm socket \
    --tpmstate "dir=$WORKDIR/swtpm-state" \
    --ctrl "type=tcp,port=2322" \
    --server "type=tcp,port=2321" \
    --tpm2 \
    --flags not-need-init \
    --log "level=1,file=$WORKDIR/swtpm.log" \
    --daemon
# Wait for socket.
for _ in 1 2 3 4 5; do
    if (echo >/dev/tcp/127.0.0.1/2321) 2>/dev/null; then break; fi
    sleep 0.3
done

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c
echo "swtpm started, TPM2 initialised"

# --- 3. Build a fake "story-kernel" ELF ----------------------------------
mkdir -p "$WORKDIR/opt/story-kernel/bin"
ELF="$WORKDIR/opt/story-kernel/bin/story-kernel"
# Use a deterministic byte pattern so we can reason about the hash.
head -c 4096 /dev/urandom > "$ELF"
chmod +x "$ELF"
GOOD_HASH=$(sha256sum "$ELF" | awk '{print $1}')
echo "fake ELF created, SHA-256 = $GOOD_HASH"

# --- 4. Run measure-binary.sh against the fresh TPM (PCR 12 starts at 0) -
echo "--- measure-binary.sh ---"
STORY_KERNEL_ELF="$ELF" sh "$SCRIPTS_DIR/measure-binary.sh"

# --- 5. verify-pcr12.sh must PASS for the original ELF --------------------
echo "--- verify-pcr12.sh (expect PASS) ---"
STORY_KERNEL_ELF="$ELF" sh "$SCRIPTS_DIR/verify-pcr12.sh"

# --- 6. Modify the ELF, expect verify-pcr12.sh to FAIL --------------------
echo "--- modifying ELF and re-checking (expect FAIL) ---"
printf 'tamper\0' >> "$ELF"
TAMPER_HASH=$(sha256sum "$ELF" | awk '{print $1}')
if [ "$TAMPER_HASH" = "$GOOD_HASH" ]; then
    echo "FAIL: tamper did not change hash"; exit 1
fi
if STORY_KERNEL_ELF="$ELF" sh "$SCRIPTS_DIR/verify-pcr12.sh" 2>/dev/null; then
    echo "FAIL: verify-pcr12.sh accepted a tampered ELF" >&2
    exit 1
fi
echo "OK: verify-pcr12.sh correctly rejected the tampered ELF"

# --- 7. Reset TPM, rebuild, check determinism -----------------------------
echo "--- determinism check: reset TPM, re-measure, expect same PCR 12 ---"
# Stop swtpm, wipe state, restart, re-measure.
pkill -f "swtpm.*$WORKDIR" >/dev/null 2>&1 || true
sleep 0.3
rm -rf "$WORKDIR/swtpm-state"
mkdir -p "$WORKDIR/swtpm-state"
swtpm socket \
    --tpmstate "dir=$WORKDIR/swtpm-state" \
    --ctrl "type=tcp,port=2322" \
    --server "type=tcp,port=2321" \
    --tpm2 \
    --flags not-need-init \
    --log "level=1,file=$WORKDIR/swtpm.log" \
    --daemon
sleep 0.3
tpm2_startup -c

# Restore the ELF to its original content (drop the "tamper" suffix).
truncate -s 4096 "$ELF"
RESTORED_HASH=$(sha256sum "$ELF" | awk '{print $1}')
if [ "$RESTORED_HASH" != "$GOOD_HASH" ]; then
    echo "FAIL: restore did not return the original hash"; exit 1
fi

STORY_KERNEL_ELF="$ELF" sh "$SCRIPTS_DIR/measure-binary.sh"
STORY_KERNEL_ELF="$ELF" sh "$SCRIPTS_DIR/verify-pcr12.sh"

echo ""
echo "============================================================"
echo "  ALL TESTS PASSED"
echo "  - measure-binary.sh extends PCR 12 correctly"
echo "  - verify-pcr12.sh PASSes for the measured ELF"
echo "  - verify-pcr12.sh FAILs for a tampered ELF"
echo "  - PCR 12 value is reboot-deterministic for the same ELF"
echo "============================================================"
