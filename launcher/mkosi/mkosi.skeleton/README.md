# mkosi.skeleton/

Files copied verbatim into the rootfs by mkosi.  Treat this tree as the
*content* of the final image: every byte under here ends up on disk
with the modes and ownership the build pipeline expects.

## What's here

| Path | Purpose |
|---|---|
| `etc/systemd/system/story-kernel-swtpm.service` | In-TD swtpm |
| `etc/systemd/system/story-kernel-measure-binary.service` | PCR 12 extend |
| `etc/systemd/system/story-kernel-rtmr3-extend.service` | RTMR3 self-extend |
| `etc/systemd/system/story-kernel.service` | The DKG kernel itself |
| `etc/tmpfiles.d/story-kernel.conf` | Runtime dirs (the only rw paths) |
| `usr/local/lib/story-kernel/measure-binary.sh` | PCR 12 helper |
| `usr/local/lib/story-kernel/extend-rtmr3.sh` | RTMR3 helper |

The four services form the boot ordering chain:

```
swtpm  ──►  measure-binary (PCR 12)  ──►  rtmr3-extend (RTMR3)  ──►  story-kernel
```

Any failure earlier in the chain halts the later units via systemd
`Requires=` — fail-closed by design.

## What's NOT here

- The `story-kernel` ELF itself.  It is dropped into `mkosi.extra/`
  by `build/build.sh` just before mkosi runs, so the rootfs build sees
  it but the source tree does not carry binaries.
- User accounts.  The `story-kernel` system user is created by
  `mkosi.postinst` so it can be sourced from `hardening/users.conf`.
- Verity hash tree.  mkosi generates that as `SplitArtifacts=roothash`
  output; consumed by `boot/kernel-cmdline` at boot time.
