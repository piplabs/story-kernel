# GCP TDX deployment — reproducible kernel, boot, and measured-boot chain

This document covers running the launcher image on **Google Cloud confidential
VMs (Intel TDX)** with a **reproducible custom kernel**, the fixes that make the
image boot and bring the story-kernel DKG node up, and the design decision
forced by GCP's confidential-VM vTPM.

It complements `build/README.md` (reproducible image build) and
`docs/operator-guide.md` (operations). Everything here was validated on
`c3-standard-4` TDX VMs in `europe-west4-a`.

---

## 1. Reproducible, KEYLESS custom TDX kernel

The launcher needs a custom **Linux 6.18.35** kernel
(`linux-image-6.18.35-storytdx`) for the TDX measurement interfaces — only
present in **kernel ≥ 6.16**: `CONFIG_INTEL_TDX_GUEST`, `CONFIG_TSM_MEASUREMENTS`
(the `tdx_guest/measurements/rtmr3:sha384` sysfs for RTMR3 self-extend),
`CONFIG_TSM_REPORTS` (configfs-tsm quote provider). Debian's stock 6.12 kernel
has none, so attestation is impossible on it. The pinned config + build live in
[`../kernel/`](../kernel) (`config-6.18.35-storytdx`, `build-kernel.sh`); the
`.deb` is staged into `mkosi/mkosi.packages/` and installed by mkosi.

For `platform_commitment` to be deterministic the kernel must be **bit-for-bit
reproducible**, and we want it reproducible **by anyone with no private key** so
operators/auditors can independently rederive the commitment. We achieve both by
building **keyless** (`CONFIG_MODULE_SIG=n`):

```sh
# from launcher/kernel/ — see build-kernel.sh
cp config-6.18.35-storytdx .config
scripts/config --set-str LOCALVERSION "-storytdx"
scripts/config -d SECURITY_LOCKDOWN_LSM -d SECURITY_LOCKDOWN_LSM_EARLY \
               -d MODULE_SIG -d MODULE_SIG_ALL -d MODULE_SIG_FORCE
make olddefconfig </dev/null            # auto-defaults NEW symbols, never prompts
export KBUILD_BUILD_TIMESTAMP=<fixed> KBUILD_BUILD_USER=story \
       KBUILD_BUILD_HOST=storytdx KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=<fixed>
rm -f .version
make -j"$(nproc)" KBUILD_BUILD_VERSION=1 && make bindeb-pkg -j"$(nproc)" KBUILD_BUILD_VERSION=1
```

**Why keyless and what made it non-trivial.** With the build identity fixed
(`KBUILD_BUILD_*`, `SOURCE_DATE_EPOCH`, pinned `#N`) two builds still differed by
~1 KB: only `vmlinuz`, in `.note.gnu.build-id` and a ~1.3 KB blob in
`.init.data`. That blob is the **embedded module-signing X.509 certificate**,
which `certs/Makefile` regenerates every build with a *random serial* +
build-time `notBefore` (openssl ignores `SOURCE_DATE_EPOCH`) → non-deterministic.
Rather than pin a private signing key (which would make us the sole producer of
the approved image), we **disable module signing entirely** — the cert is then
never generated/embedded, so the kernel is deterministic with **no key at all**.

This is safe: module signing is **unenforced** here (`MODULE_SIG_FORCE` unset),
modules sit on a `dm-verity` read-only rootfs, and node integrity is enforced by
measured boot + the on-chain `code_commitment`/`platform_commitment` whitelist —
not by module signatures (see `threat-model.md`).

Two traps that make `MODULE_SIG=n` actually stick:

> **lockdown re-enables it.** `security/lockdown/Kconfig` has
> `select MODULE_SIG if MODULES`, so `CONFIG_SECURITY_LOCKDOWN_LSM` forces module
> signing back on. You must disable `SECURITY_LOCKDOWN_LSM` (+ `_EARLY`) too.
> Lockdown is dormant in our config anyway (`LOCK_DOWN_KERNEL_FORCE_NONE`, not in
> the boot cmdline), so this costs nothing.

> **resolve config non-interactively, and verify the OUTPUT.** Use
> `make olddefconfig </dev/null` (not `oldconfig` / `yes ""`) so the deb-pkg
> config step never blocks CI on stdin. Then **assert the produced `.deb`'s
> `/boot/config` has `CONFIG_MODULE_SIG=n`** — the pre-build `.config` is not
> authoritative; `build-kernel.sh` does this assertion and fails closed.

Also pin `CONFIG_LOCALVERSION="-storytdx"` so the package is named
`linux-image-6.18.35-storytdx` (mkosi installs the kernel **by name**).

---

## 2. Booting on GCP TDX

Three things block boot on GCP TDX out of the box:

1. **`Makefile` build-tdx `-extldflags=-Wl,-w`** — GNU ld 2.38 rejects `-w`.
   Removed.
2. **Stock `linux-image-amd64`** lacks the TDX measurement interfaces. Replaced
   with the custom `linux-image-6.18.35-storytdx`.
3. **Hardening cmdline flags crash at KASLR** on GCP TDX. The booting cmdline is
   the minimal set in `boot/kernel-cmdline` (console + `random.trust_cpu=on`),
   kept in lock-step with `mkosi.conf` `KernelCommandLine` (the `diff-cmdline.sh`
   lint enforces this). The aggressive hardening flags
   (`lockdown`, `vsyscall=none`, `slab_nomerge`, …) must stay off until each is
   bisected against GCP TDX boot.

VM flags: `--confidential-compute-type=TDX --maintenance-policy=TERMINATE
--no-shielded-secure-boot` (self-signed UKI), `--guest-os-features=
UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC`.

---

## 3. Measured-boot chain and the vTPM decision

Boot order: `swtpm` (see below) → `measure-binary` (PCR 12 ← SHA-256(ELF)) →
`rtmr3-extend` (RTMR3 ← SHA-384(ELF) via `tdx_guest` sysfs) → `story-kernel`.

### 3.1 In-TD swtpm vs GCP confidential-VM vTPM (design decision)

The in-TD swtpm design (`story-kernel-swtpm.service`, `swtpm --vtpm-proxy`) is
**structurally incompatible with GCP confidential VMs**:

- GCP CVMs always expose a `tpm_tis` vTPM at `/dev/tpm0` (`CONFIG_TCG_TIS=y`,
  built-in — cannot be blacklisted), even without `--shielded-vtpm`.
- `swtpm --vtpm-proxy` therefore lands its proxy on `/dev/tpm1`.
- But `enclave/tdx/seal.go` hard-codes `/dev/tpmrm0` → `/dev/tpm0`.

So story-kernel would always seal against the GCP vTPM, never the in-TD swtpm —
the swtpm is vestigial on GCP. **Decision:** drop the swtpm dependency from
`measure-binary` and neutralize `story-kernel-swtpm.service`; the measurement
chain and seal use the GCP vTPM (`/dev/tpmrm0`). The in-TD swtpm path requires
bare-metal TDX or a CVM without an integrated vTPM (where the swtpm proxy can
own `/dev/tpm0`).

### 3.2 Service fixes (so the chain runs unattended)

- **`/usr/lib/modules-load.d`** ships `tpm_vtpm_proxy` (was never wired into the
  image) and `tdx-guest` + `tsm` (configfs-tsm quote provider;
  `CONFIG_TSM_REPORTS=m`, `CONFIG_TDX_GUEST_DRIVER=m`).
- **`story-kernel-swtpm.service`** (kept for non-GCP targets): assert
  `/dev/vtpmx` (the module's control device, not the on-demand `/dev/vtpm-proxy`);
  drop the invalid `--server` option (chardev mode rejects it); add
  `CAP_SYS_ADMIN` (vtpmx ioctl).
- **`story-kernel-measure-binary.service`** runs as `User=story-kernel` with
  `DeviceAllow=char-tpm rw` — the TPM devices are `story-kernel:0600` via the
  `70-story-kernel-tpm.rules` udev rule, so even root was denied without this.
- **`systemd-firstboot.service` masked** + a stable `/etc/machine-id` shipped.
  On a serial console firstboot prints "Please configure your system! — Press
  any key" and **blocks `multi-user.target`**, so `story-kernel.service` never
  starts.
- **`story-kernel.service` `ExecStart`** uses `story-kernel start` (the bare
  binary printed usage and exited).

---

## 4. Node config — external injection via instance metadata

`story-kernel start` loads a light-client config (`chain_id`, `rpc_addr`,
`primary_addr`, `witness_addrs` (≥2), `trusted_height`, `trusted_hash`). The
private keys are **not** in this config — they are generated and TPM-sealed at
runtime; the config only tells the node which chain to follow.

The config is **injected from the cloud instance metadata, not baked into the
rootfs.** `story-kernel.service` `ExecStartPre` fetches it at boot:

```sh
curl -sf -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/attributes/story-kernel-config" \
  -o /tmp/skcfg && cp /tmp/skcfg /run/story-kernel/home/config
# falls back to `story-kernel init` if no metadata is present
```

`/run/story-kernel/home` is tmpfs (wiped each boot); `curl` is in the image
(`mkosi.conf` `Packages=`) and the network comes up via DHCP
(`20-wired.network`, matches `gve`/`ens*`/`eth*`).

**Why external, not baked.** Baking `trusted_height`/`trusted_hash` into the
read-only rootfs makes the rootfs (hence `RTMR1`/`RTMR2`, hence
`platform_commitment`) bound to one chain instance — every chain reset or
re-point would change `platform_commitment` and force a re-whitelist + image
rebuild. External injection keeps `code_commitment` **and**
`platform_commitment` stable across deploys: whitelist/approve once, then point
a validator at any chain by setting `--metadata-from-file=story-kernel-config=…`
at VM-create time. This does **not** weaken the trust model — the trusted block
is operator-chosen either way, the config never enters the seal policy (PCR
7/11/12 only) or the quote, and a forged config cannot extract the sealed key or
forge a registration on the real chain (the quote's `report_data` binds the
followed chain's `startBlockHeight`/`startBlockHash`, which the consensus client
re-checks against real-chain state). See `threat-model.md` (C).

**TDX quote provider — RESOLVED.** Initially `tdx: no TDX device available
(configfs-tsm): no vendor` because `CONFIG_TSM_REPORTS=m` was not loaded. Fixed
by rebuilding the kernel with `CONFIG_TSM_REPORTS=y`, `CONFIG_TDX_GUEST_DRIVER=y`,
`CONFIG_CONFIGFS_FS=y` built-in, plus relaxing the story-kernel.service sandbox
(`ProtectKernelTunables=no`, `CapabilityBoundingSet`/`AmbientCapabilities=
CAP_DAC_OVERRIDE`) so it can create configfs-tsm report entries. story-kernel
then logs `tdx: using vendor adapter "direct"` — TDX attestation is functional.

---

## 5. Validated end-to-end (4-of-4 DKG)

The full path was validated on `c3-standard-4` TDX VMs in `europe-west4-a`
against a Story devnet built from the canonical `dkg/dev` consensus + contracts:
four launcher VMs booted, each ran `story-kernel start` with metadata-injected
config, produced a real TDX quote, and were driven by their consensus client
through **registration → dealing → finalization → global public key** with
`stage = ACTIVE`. On-chain `verifyAndAttestOnChain(quote) == true`, and
`TDXValidationHook` accepted all four.

Observed properties, matching the design:

- **Reproducible** — the build emits a deterministic `code_commitment`
  (`keccak256(RTMR3)` = the story-kernel ELF identity).
- **Same machine type + firmware vintage ⇒ one `platform_commitment`** — all
  four same-image VMs shared a single `platform_commitment`, so it is approved
  once. Note a *new image* (different kernel/rootfs) changes `RTMR1`/`RTMR2` and
  therefore rotates `platform_commitment` (see `architecture.md`).
- **The raw quote passes on-chain DCAP remote attestation** — `code_commitment`
  whitelisted via `approveBinary`, `platform_commitment` via `approvePlatform`,
  with the DCAP collateral (FMSPC TCB, TD_QE identity, TCB-evaluation data, PCK
  + Root CRLs) present.

The on-chain `DKG.sol` register pins `dkgPubKey.length == 32` (ed25519) and
`enclaveCommKey.length == 64` (uncompressed secp256k1 minus the `0x04` prefix);
the kernel emits exactly those lengths.

This was re-validated with the **keyless kernel** (`CONFIG_MODULE_SIG=n`, §1): it
boots on GCP TDX (serial shows no lockdown LSM and no embedded module-signing
cert), produces a quote that passes `verifyAndAttestOnChain`, and completed a
fresh-chain **4-of-4 DKG to `stage = ACTIVE` / global public key**. The keyless
kernel is a different binary from any signed build, so it has its own
`platform_commitment` (firmware/kernel-measured), while `code_commitment` is
unchanged (it is the story-kernel Go ELF, independent of the Linux kernel).
