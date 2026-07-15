#!/bin/sh
# measure-binary.sh — extend PCR 12 with SHA-256(story-kernel ELF).
#
# This is the extension that makes the seal policy in
# enclave/tdx/providers.go meaningful — without it PCR 12 stays zero, the
# kernel's startup self-check rejects it, and sealing fails closed. It must
# run BEFORE story-kernel so the ELF cannot be swapped after measurement; the
# rootfs is dm-verity read-only, which is what keeps this measurer honest.
#
# In the launcher image the runtime copy runs as the
# story-kernel-measure-binary.service systemd unit (after the verity rootfs is
# mounted, before story-kernel.service), extending PCR 12 on the platform vTPM
# (/dev/tpmrm0 — on GCP confidential VMs the firmware-backed vTPM). This
# attestation/ copy is the auditable reference.
#
# Env overrides (optional):
#   STORY_KERNEL_ELF   path to the ELF (default: /usr/local/bin/story-kernel)
#   TPM2TOOLS_TCTI     tpm2-tools transport (default: tpm2-tools auto-detect)
#
# Exits non-zero on any failure. The initrd must treat a non-zero exit as
# fatal so a missing or unreadable ELF, or a non-responsive vTPM, drops the
# boot before story-kernel can run with a malformed identity chain.
set -eu

ELF_PATH="${STORY_KERNEL_ELF:-/usr/local/bin/story-kernel}"

if [ ! -f "$ELF_PATH" ]; then
    echo "measure-binary: ELF not found at $ELF_PATH" >&2
    exit 1
fi

# Confirm a TPM device or TCTI override is reachable. /dev/tpmrm0 is the
# resource-managed kernel device, /dev/tpm0 is the raw fallback. If the
# operator overrode TPM2TOOLS_TCTI (e.g., for tests), skip the device check.
if [ -z "${TPM2TOOLS_TCTI:-}" ]; then
    if [ ! -c /dev/tpmrm0 ] && [ ! -c /dev/tpm0 ]; then
        echo "measure-binary: no TPM device at /dev/tpmrm0 or /dev/tpm0 (platform vTPM required)" >&2
        exit 1
    fi
fi

# SHA-256 of the on-disk ELF. We deliberately read the file directly
# (rather than /proc/self/exe of any process) because the measurer is the
# initrd, not story-kernel — the goal is to pin "the ELF that will be
# exec'd next", before any chance to swap.
hash=$(sha256sum "$ELF_PATH" | awk '{print $1}')

# Sanity: SHA-256 is 64 hex chars (32 bytes). Anything else means
# coreutils sha256sum is misbehaving.
if [ "${#hash}" -ne 64 ]; then
    echo "measure-binary: unexpected SHA-256 hex length ${#hash} (want 64)" >&2
    exit 1
fi

echo "measure-binary: extending PCR 12 with SHA-256($ELF_PATH) = $hash"
tpm2_pcrextend "12:sha256=$hash"

# Echo the post-extend PCR 12 value for the boot log. Useful for the
# verify-pcr12.sh sanity check at startup and for operators debugging
# "why does the kernel say PCR 12 is wrong?" — they can compare this
# logged value against the kernel's self-check error message.
#
# Use the -o raw-output mode rather than parsing the text output, because
# tpm2-tools' text format ("    12: 0xHEX") varies across releases.
PCR_BIN=$(mktemp)
trap 'rm -f "$PCR_BIN"' EXIT
tpm2_pcrread sha256:12 -o "$PCR_BIN" >/dev/null
post=$(xxd -p "$PCR_BIN" | tr -d '\n')
echo "measure-binary: PCR 12 post-extend = $post"
