# attestation/

RTMR3 self-extend flow. Before story-kernel runs any DKG work, RTMR3
is extended with the SHA-384 of its ELF, binding its identity to the
TDX attestation chain.

## Status

Implemented. The boot-time extender lives in
`../mkosi/mkosi.skeleton/usr/local/lib/story-kernel/extend-rtmr3.sh`
and is driven by `story-kernel-rtmr3-extend.service`.  This directory
holds the *verification* tooling.

## Commitments

The boot chain (firmware, bootloader, kernel, cmdline) extends
RTMR0..RTMR2, which form the **platform_commitment**:

```
platform_commitment = keccak256(MRTD || RTMR0 || RTMR1 || RTMR2)
```

RTMR3 is extended once at startup with the kernel ELF SHA-384, giving the
**code_commitment**:

```
code_commitment = keccak256(RTMR3)
```

This lets governance approve a platform (firmware vintage, boot chain)
independently from a specific story-kernel binary.

## Contents

This directory holds the operator/auditor **verification** tooling. The
boot-time *extenders* run inside the image: `extend-rtmr3.sh` (RTMR3) and
`measure-binary.sh` (PCR 12) are copied verbatim into the rootfs from
`mkosi.skeleton/`. The `measure-binary.sh` here is a standalone reference
that the `test/` harness exercises.

| File | Purpose |
|---|---|
| `verify-rtmr3.sh` | Post-boot check: extracts RTMR3 from a fresh quote → `code_commitment = keccak256(RTMR3)` |
| `verify-platform.sh` | Extracts MRTD/RTMR0..2 → `platform_commitment = keccak256(MRTD‖RTMR0‖RTMR1‖RTMR2)` |
| `verify-pcr12.sh` | Asserts vTPM PCR 12 == `SHA-256(0x00*32 ‖ SHA-256(ELF))` — the sealing bind |
| `measure-binary.sh` | PCR 12 extend helper (reference copy; the in-image one runs at boot) |
| `test/` | Docker harness: runs measure-binary.sh + verify-pcr12.sh against swtpm, asserts tamper detection |
| `README.md` | This file |

## Reference

`contracts/src/protocol/TDXValidationHook.sol` consumes both
commitments via the `approvedPlatform[platform_commitment]` and
`approvedBinary[code_commitment]` mappings.
