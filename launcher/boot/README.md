# boot/

Boot artifacts: kernel command line and dm-verity setup. Whatever the
hypervisor hands the TD at boot ends up reflected in RTMR0..RTMR2 and
becomes part of `platform_commitment`. Anything here changes the
on-chain identity of the image.

## Contents

| File | Purpose |
|---|---|
| `kernel-cmdline` | Canonical cmdline string (commented, one flag per line) |
| `dm-verity-build.sh` | Build hash tree + root hash for rootfs.raw |
| `diff-cmdline.sh` | Lint: assert boot/kernel-cmdline ≡ mkosi/mkosi.conf |
| `README.md` | This file |

## Why both `kernel-cmdline` and `mkosi.conf`?

mkosi consumes `KernelCommandLine=` directly from its own config. The
companion `kernel-cmdline` file in this directory is a
human-auditable, line-by-line, commented version of the same string.
`diff-cmdline.sh` enforces that they agree.

This split lets governance review the cmdline as a *document* without
having to read mkosi syntax, while still keeping a single source of
truth that the build actually uses.

## Notes

- The cmdline is part of the measured boot chain. Any operator
  changing the cmdline (e.g. adding `init=/bin/bash`) produces a
  different RTMR1 and is rejected by `approvedPlatforms[]` on chain.
- The dm-verity root hash is embedded into the cmdline at build time
  by `build/build.sh`; the lines marked "filled in by build pipeline"
  in `kernel-cmdline` are placeholders.
