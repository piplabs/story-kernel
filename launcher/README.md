# story-kernel-launcher

Reproducible, hardened Trust Domain (TD) image build pipeline and runtime
environment for story-kernel validators. Everything required to deliver,
verify, and operate a production-grade TDX node lives under this directory.

## What it provides

- **Reproducible image build** via `mkosi` — same source produces a
  byte-identical rootfs (and deterministic `code_commitment`) across
  machines and time
- **Keyless reproducible kernel** — the custom TDX kernel is built with
  `CONFIG_MODULE_SIG=n` (`kernel/`), so anyone can rebuild it byte-identically
  with **no private signing key** and independently verify `platform_commitment`
- **Boot-bound sealing** — key shares are sealed on the GCP confidential-VM
  vTPM (`/dev/tpmrm0`) under `PolicyPCR(PCR 7, 11, 12)`, tying them to the exact
  Secure-Boot policy, dm-verity rootfs, and story-kernel ELF; they unseal only in
  that measured boot (see `docs/operator-guide.md` → Measured-boot chain and sealing)
- **`dm-verity` rootfs** — block-level integrity for the booted image;
  any tampering after boot crashes the kernel
- **OS hardening** — no SSH, root locked, all getty masked, ptrace
  disabled, `/dev/mem` unavailable, no shell after handoff
- **RTMR3 self-extend** — story-kernel binary identity is baked into
  the TDX attestation chain before any DKG work begins
- **External config injection** — the light-client config (which chain to
  follow) is fetched at boot from cloud instance metadata into tmpfs, not
  baked into the rootfs, so `code_commitment`/`platform_commitment` stay
  stable across chains and resets (see `docs/operator-guide.md` → Node config)
- **Platform & code commitment extraction tooling** — operators and
  auditors derive both on-chain governance values from a real quote
  (`attestation/verify-platform.sh`, `attestation/verify-rtmr3.sh`)

## Threat model

The launcher defends threats (A) host memory read, (B) root-in-TD code
tampering, (B') validator share extraction, (C) fork-chain light-client
spoofing, and (D) Sybil committee joins. The full matrix — one row per
threat, one column per component — is in
[`docs/threat-model.md`](docs/threat-model.md).

This launcher is **not** a confidentiality replacement. The cryptographic
protocol (DKG + threshold decryption) provides confidentiality. The
launcher exists so the protocol's assumptions about validator code
integrity actually hold in deployed environments.

## Layout

| Subdirectory | Purpose |
|---|---|
| `kernel/` | Keyless reproducible custom TDX kernel: pinned `.config` + `build-kernel.sh` |
| `mkosi/` | Reproducible image build configuration |
| `initrd/` | Custom initrd: early-load modules + dm-verity rootfs setup |
| `boot/` | Boot artifacts: kernel cmdline, dm-verity setup |
| `attestation/` | RTMR3 self-extend flow at boot |
| `hardening/` | OS hardening policies (sysctl, modprobe blacklist) |
| `build/` | Reproducible build pipeline (containerized) |
| `docs/` | Operator + auditor + threat-model documentation |

## Related code outside launcher/

- `enclave/tdx/` — TDX backend Go code (attestation, sealing client)
- `enclave/tdx/README.md` — TDX backend overview

## Building

```sh
# Build the reproducible TD image (containerized, deterministic)
./build/build.sh

# Verify a rebuild is byte-identical to a published reference
./build/verify-reproducible.sh
```

After a TD boots the image, extract the on-chain governance values from a
fresh quote with `attestation/verify-platform.sh` (platform_commitment) and
`attestation/verify-rtmr3.sh` (code_commitment). End-to-end deploy steps —
download, verify, launch, register, upgrade, halt-recovery — are in
[`docs/operator-guide.md`](docs/operator-guide.md).

## Why this is its own component

story-kernel is the Go binary that performs DKG work. The launcher is the
*substrate* around it — image, boot, attestation, sealing, hardening — that
makes the binary's security guarantees real. Keeping them in the same repo
but in distinct trees lets the binary and its substrate be versioned and
audited together while staying organizationally separate.
