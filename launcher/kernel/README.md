# Custom TDX kernel (keyless, reproducible)

The launcher boots a custom **Linux 6.18.35** kernel
(`linux-image-6.18.35-storytdx`) instead of a stock distro kernel because TDX
attestation needs measurement interfaces that exist only in **kernel ≥ 6.16**:

- `CONFIG_TSM_MEASUREMENTS` — the `tdx_guest/measurements/rtmr3:sha384` sysfs used
  to self-extend the story-kernel binary identity into RTMR3 (`code_commitment`).
- `CONFIG_TSM_REPORTS` + `CONFIG_INTEL_TDX_GUEST` — the configfs-tsm quote provider.

Debian's stock 6.12 kernel has none of these, so attestation is impossible on it.

## Keyless = anyone can reproduce it

`config-6.18.35-storytdx` sets **`CONFIG_MODULE_SIG=n`** (and disables
`CONFIG_SECURITY_LOCKDOWN_LSM`, which would otherwise `select MODULE_SIG`). With
no module-signing key:

- the build needs **no private key** — anyone can rebuild byte-identically from
  this config and independently derive/verify the on-chain `platform_commitment`;
- the only previously non-deterministic input (the auto-generated, randomly-serialed
  module-signing X.509 cert embedded in `vmlinuz`) is gone, so the kernel is
  bit-for-bit reproducible given the fixed `KBUILD_BUILD_*` / `SOURCE_DATE_EPOCH`.

Dropping module signing costs no security here: it is unenforced
(`MODULE_SIG_FORCE` unset), modules live on a `dm-verity` read-only rootfs, and the
node's integrity is enforced by measured boot + the on-chain `code_commitment` /
`platform_commitment` whitelist — not by module signatures. See
[`../docs/threat-model.md`](../docs/threat-model.md).

## Build

```sh
./build-kernel.sh            # emits linux-image-6.18.35-storytdx_*_amd64.deb
```

`build-kernel.sh` starts from `config-6.18.35-storytdx`, re-asserts the
keyless/no-lockdown invariants, resolves new symbols with `make olddefconfig
</dev/null` (never prompts → no CI hang), builds with the deterministic identity,
and **asserts the produced `.deb`'s `/boot/config` actually has `MODULE_SIG=n`**
before accepting it. Stage the output into `../mkosi/mkosi.packages/`.
