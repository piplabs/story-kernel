#!/bin/sh
# verify-pcr12.sh — assert PCR 12 == SHA-256(0x00*32 || SHA-256(story-kernel ELF)).
#
# Run after boot, before treating sealed material as trustworthy. This is
# defense-in-depth — the kernel's own runSelfCheck rejects all-zero PCRs
# and (in strict mode) refuses to start on a digest mismatch, but operators
# may want an independent confirmation that the running kernel ELF on disk
# is what initrd actually measured into PCR 12.
#
# Logic:
#   - PCR 12 starts at 0x00..00 (32 bytes) at TD boot.
#   - initrd calls tpm2_pcrextend 12:sha256=<elf_hash>, which executes
#     PCR12_new = SHA-256(PCR12_old || elf_hash) = SHA-256(0x00*32 || elf_hash).
#   - Compute the expected post-extend value here and compare with the
#     running PCR 12.
#
# Env overrides (optional):
#   STORY_KERNEL_ELF   path to the ELF (default: /usr/local/bin/story-kernel)
#   TPM2TOOLS_TCTI     tpm2-tools transport (default: auto-detect)
set -eu

ELF_PATH="${STORY_KERNEL_ELF:-/usr/local/bin/story-kernel}"

if [ ! -f "$ELF_PATH" ]; then
    echo "verify-pcr12: ELF not found at $ELF_PATH" >&2
    exit 1
fi

elf_hash=$(sha256sum "$ELF_PATH" | awk '{print $1}')

# Expected PCR 12 = SHA-256( 32 zero bytes || sha256(ELF) ).
# We build the 64-byte preimage with printf+xxd, then sha256sum it.
expected=$(
    {
        printf '%0.s\0' $(seq 1 32)
        printf '%s' "$elf_hash" | xxd -r -p
    } | sha256sum | awk '{print $1}'
)

# Read PCR 12 from the running vTPM via the binary -o mode (text output
# format of tpm2_pcrread varies across releases, so we avoid parsing it).
PCR_BIN=$(mktemp)
trap 'rm -f "$PCR_BIN"' EXIT
tpm2_pcrread sha256:12 -o "$PCR_BIN" >/dev/null
actual=$(xxd -p "$PCR_BIN" | tr -d '\n')

if [ "$actual" = "$expected" ]; then
    echo "verify-pcr12: PASS"
    echo "  ELF       = $ELF_PATH"
    echo "  SHA-256   = $elf_hash"
    echo "  PCR 12    = $actual"
    exit 0
fi

cat >&2 <<EOF
verify-pcr12: FAIL — PCR 12 does not bind to the on-disk ELF.

  ELF        = $ELF_PATH
  ELF SHA-256 = $elf_hash
  expected   = $expected
  actual     = $actual

Likely causes:
  - initrd's measure-binary.sh did not run (or ran against a different file)
  - PCR 12 was extended more than once (post value is SHA256(prev || h),
    not SHA256(0 || h))
  - vTPM was reset / state lost between initrd and this check
  - story-kernel ELF on disk was modified after measure-binary ran

Do NOT trust sealed material until this passes.
EOF
exit 1
