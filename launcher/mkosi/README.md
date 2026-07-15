# mkosi/

Reproducible TD image build configuration. Driven by `mkosi`
(https://github.com/systemd/mkosi). The same `mkosi.conf` + source tree
must produce a byte-identical rootfs across builders and time.

## Layout

```
mkosi/
├── mkosi.conf            # Top-level mkosi configuration
├── mkosi.skeleton/       # Files baked verbatim into the image
│   ├── etc/
│   │   ├── systemd/system/          # units: measure-binary, rtmr3-extend, story-kernel
│   │   ├── systemd/network/         # 20-wired.network (GVNIC DHCP)
│   │   ├── tmpfiles.d/              # runtime dirs (the only rw paths)
│   │   └── udev/rules.d/            # TPM device access for the story-kernel user
│   └── usr/local/lib/story-kernel/  # in-image helpers (measure-binary.sh, extend-rtmr3.sh)
├── mkosi.packages/       # the custom keyless kernel .deb (see ../kernel/)
├── mkosi.extra/          # build/build.sh drops the story-kernel ELF here
└── mkosi.postinst        # Post-install hardening hook
```

## Determinism requirements

- `SOURCE_DATE_EPOCH` pinned across the entire build
- All package versions pinned (no floating `latest`)
- File mtimes normalized
- No randomness in build (e.g. no generated keys baked in)
- Output: `rootfs.raw` with stable SHA-256 across rebuilds
