# Architecture

How the launcher's pieces fit together and why each piece exists.
The motivating threat list lives in `threat-model.md`; this document
covers structure.

## Component overview

```
                ┌────────────────────────────────────────────────┐
                │                  build/                        │
                │  build.sh  →  Go build  →  mkosi  →  verity    │
                │     │                                          │
                │     └──→  manifest.json (sha256 of every art)  │
                └─────────────────────┬──────────────────────────┘
                                      │  produces
                ┌─────────────────────▼──────────────────────────┐
                │                  out/                          │
                │   story-kernel  *.raw  rootfs.verity           │
                │   root-hash.txt  code_commitment.txt         │
                └─────────────────────┬──────────────────────────┘
                                      │  deployed to TDX host
                ┌─────────────────────▼──────────────────────────┐
                │                 TDX TD                         │
                │  ┌──────────────────────────────────────────┐  │
                │  │  TDX firmware  (MRTD, RTMR0..2)          │  │
                │  └──┬───────────────────────────────────────┘  │
                │     │  loads                                   │
                │  ┌──▼──────────┐    ┌─────────────────────┐    │
                │  │  initrd     │ →  │  rootfs (verity-ro) │    │
                │  └─────────────┘    │  ┌───────────────┐  │    │
                │                     │  │ swtpm (in-TD) │  │    │
                │                     │  └──────┬────────┘  │    │
                │                     │         │ PCR 12    │    │
                │                     │  ┌──────▼────────┐  │    │
                │                     │  │ measure-bin   │  │    │
                │                     │  └──────┬────────┘  │    │
                │                     │         │ RTMR3     │    │
                │                     │  ┌──────▼────────┐  │    │
                │                     │  │ rtmr3-extend  │  │    │
                │                     │  └──────┬────────┘  │    │
                │                     │  ┌──────▼────────┐  │    │
                │                     │  │ story-kernel  │  │    │
                │                     │  └───────────────┘  │    │
                │                     └─────────────────────┘    │
                └────────────────────────────────────────────────┘
                                      │  attests
                                      ▼
                         ┌─────────────────────────┐
                         │   TDXValidationHook     │
                         │   approvedPlatform[]    │
                         │   approvedBinary[]      │
                         └─────────────────────────┘
```

## Boot ordering (the chain that must NEVER be reordered)

```
1. TDX firmware            →  measures MRTD, extends RTMR0
2. Bootloader              →  extends RTMR1 (kernel + cmdline)
3. Kernel                  →  loads dm-verity, mounts verified rootfs
4. systemd starts
5. swtpm service           →  in-TD vTPM (NON-GCP only; neutralized on GCP,
                              which exposes a built-in CVM vTPM at /dev/tpm0)
6. measure-binary service  →  PCR 12 ← SHA-256(story-kernel ELF)
7. rtmr3-extend service    →  RTMR3 ← SHA-384(story-kernel ELF)
8. story-kernel service    →  ExecStartPre: fetch light-client config from
                              instance metadata into tmpfs (§4 gcp-tdx-deployment)
                           →  start: attest, register, join committee
```

Steps 5–7 are enforced by systemd `Requires=`/`Before=` ordering.
Step 8 cannot start until step 7 has completed successfully (fail-closed). The
config fetched in step 8 selects which chain to follow; it is operator-supplied
and is **not** measured into any RTMR/PCR (it does not affect the commitments or
the seal policy — see `threat-model.md` (C)).

## Component responsibilities

| Subdirectory | What it owns | What it does NOT own |
|---|---|---|
| `mkosi/` | The image build configuration; systemd units; in-image helper scripts | The boot loader (mkosi delegates), the dm-verity layer (boot/) |
| `initrd/` | What ends up in initramfs (dracut config, early-load modules) | Anything after switch_root |
| `boot/` | Kernel cmdline source-of-truth; dm-verity hash tree construction | The bootloader binary itself (mkosi packages systemd-boot) |
| `attestation/` | Verifier-side RTMR3 tooling; the contract between the launcher and on-chain `approvedBinary[]` | The extender script (lives in mkosi.skeleton because it runs in the image) |
| `hardening/` | sysctl, modprobe blacklist, system users, service enables | Anything that has to live elsewhere (e.g. systemd units live in mkosi.skeleton) |
| `build/` | Reproducibility, Dockerfile pinning, manifest emission | The Go build itself (that's in `cmd/story-kernel`) |
| `docs/` | Operator + auditor + reviewer documentation | Source-of-truth identifiers (those live where the artifacts are: `manifest.json`, `kernel-cmdline`, etc.) |

## Two artifacts the launcher emits for governance

| Artifact | Formula | Where governance approves it |
|---|---|---|
| `platform_commitment` | `keccak256(MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2)` | `TDXValidationHook.approvePlatform()` |
| `code_commitment`   | `keccak256(RTMR3 after one extend with SHA-384(ELF))` | `TDXValidationHook.approveBinary()` |

`platform_commitment` covers everything OUTSIDE the launcher's
control (firmware, bootloader, kernel, cmdline). `code_commitment`
covers the ELF that the launcher's build pipeline produced. They are
*independent*: a firmware upgrade rotates platform but not binary; a
story-kernel release rotates binary but not platform.

## File-by-file dependency graph

```
build/build.sh
  ├── boot/diff-cmdline.sh           (lint)
  ├── boot/dm-verity-build.sh        (hash tree)
  ├── mkosi/mkosi.conf
  │     ├── mkosi/mkosi.skeleton/*   (verbatim copy)
  │     └── mkosi/mkosi.postinst
  │           └── hardening/install.sh
  │                 ├── hardening/sysctl.conf
  │                 ├── hardening/modprobe-blacklist.conf
  │                 └── hardening/users.conf
  └── (Go build of story-kernel)

attestation/verify-rtmr3.sh          (standalone, run on booted TD)
build/verify-reproducible.sh         (standalone, double-build diff)
```

The launcher has no other inter-component dependencies.
