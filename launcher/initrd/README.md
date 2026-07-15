# initrd/

Configuration that shapes the initramfs.  We rely on `dracut` (driven
from `mkosi`) to assemble the initrd; the files here tell dracut what
to embed and tell the running kernel what to load early.

## Boot flow

```
TD firmware
   │  measures into RTMR0..RTMR2 (platform_commitment)
   ▼
bootloader  (systemd-boot via mkosi)
   │  loads kernel + initrd
   ▼
kernel
   │  loads dm_mod, dm_verity from initrd
   ▼
initrd  (dracut)
   │  sets up dm-verity rootfs
   │  switch_root
   ▼
systemd on the verity-protected rootfs
   │  story-kernel-measure-binary.service ← PCR 12 = SHA256(story-kernel ELF) on the GCP CVM vTPM
   │  story-kernel-rtmr3-extend.service   ← RTMR3 = binary identity
   │  story-kernel.service                ← DKG node runs
```

## Files in this directory

| File | Purpose |
|---|---|
| `modules-load.conf` | Modules loaded by `systemd-modules-load` post-boot |
| `dracut-include.conf` | Dracut config: what to embed in the initrd |

## Why the measurement happens after switch_root, not in initrd

`dm-verity` guarantees the rootfs is byte-identical to the published
image once mounted — any tampering causes a kernel panic at block-read
time.  That means there is no attack window between switch_root and
systemd running the measurement service: a modified `/usr/local/bin/story-kernel`
cannot be staged because writing to the rootfs is impossible.
