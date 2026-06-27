# Operator guide (GCP TDX)

> **Supported platform: GCP confidential VMs (Intel TDX) only.** Other
> configfs-tsm clouds (bare-metal / IBM / …) are planned but not yet validated
> for the launcher image.

End-to-end steps to build, deploy, and operate a launcher validator on GCP:
build the reproducible image → import it as a GCP image → launch a confidential
TDX VM → verify on first boot → run story-kernel → routine ops. The internals
(keyless kernel, measured-boot/sealing chain) are in [Reference](#reference--how-the-image-works-on-gcp)
at the end.

## Prerequisites

- A GCP project with **confidential-VM TDX** quota (e.g. `c3-standard-4` in a
  TDX-capable region/zone) and rights to create images + instances.
- A Linux host with Docker to **build** the image (TDX hardware is only needed to
  *boot* the result, not to build it).
- The chain you will follow: its RPC endpoint, **≥ 2** witness endpoints, and a
  recent trusted block (`trusted_height` + `trusted_hash`) for the light client.

## 1. Build the image

The image is reproducible and builds on any Linux host with Docker:

```sh
./launcher/build/build.sh
```

This builds the story-kernel Go binary, stages the **keyless custom kernel**
(`launcher/kernel/`, see [Reference](#keyless-reproducible-kernel)) into
`mkosi/mkosi.packages/`, runs mkosi in a pinned builder container, builds the
dm-verity tree, and writes `launcher/out/` — the TD `.raw` image,
`rootfs.verity`, `root-hash.txt`, and `manifest.json` (sha256/sha384 of every
artifact + the derived `code_commitment`).

Optionally confirm determinism (rebuild + diff every artifact, and rebuild the
kernel twice for byte-identical):

```sh
./launcher/build/verify-reproducible.sh
```

## 2. Import the image into GCP

GCP boots a raw disk image. Tar the `.raw` as `disk.raw`, upload, and create the
image with the TDX guest-OS features:

```sh
cd launcher/out
ln -sf story-kernel-td_*.raw disk.raw
tar --format=oldgnu -Sczhf /tmp/launcher.tar.gz disk.raw      # -h: follow the symlink
gcloud storage cp /tmp/launcher.tar.gz gs://<your-bucket>/launcher.tar.gz
gcloud compute images create story-kernel-tdx \
    --source-uri gs://<your-bucket>/launcher.tar.gz \
    --guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC
```

## 3. Launch the TD on GCP

The node's light-client config is **injected via instance metadata**
(`story-kernel-config`), not baked into the image — this keeps `code_commitment`
and `platform_commitment` stable across chains and resets (see
[Reference](#node-config--external-injection)). Private keys are **not** in this
config; they are generated and TPM-sealed at runtime.

```sh
# config.toml: which chain the node follows (NO keys)
cat > config.toml <<'TOML'
log-level = "info"
[grpc]
listen_addr = ":50051"
[light_client]
chain_id      = "<chain-id>"
rpc_addr      = "http://<chain-rpc>:26657"
primary_addr  = "http://<chain-rpc>:26657"
witness_addrs = ["http://<witness-1>:26657", "http://<witness-2>:26657"]  # >= 2
trusted_height = <height>
trusted_hash   = "<hash>"
TOML

gcloud compute instances create story-kernel-validator-N \
    --machine-type=c3-standard-4 \
    --confidential-compute-type=TDX \
    --maintenance-policy=TERMINATE \
    --no-shielded-secure-boot \
    --image=story-kernel-tdx \
    --metadata-from-file=story-kernel-config=config.toml \
    --zone=<zone>
```

`--no-shielded-secure-boot` is required (the image ships a self-signed UKI).
`story-kernel.service` fetches `story-kernel-config` from the metadata server at
boot into tmpfs (`/run/story-kernel/home/config`). To re-point an existing
validator at a different chain, update the metadata and recreate the VM — no
image rebuild and no re-whitelist (the commitments are unchanged).

## 4. Verify on first boot

There is no SSH into the running TD (blocked by hardening). Use the GCP serial
console to confirm the boot:

```sh
gcloud compute instances get-serial-port-output story-kernel-validator-N \
    --zone=<zone> --port=1
```

Expect the custom kernel (`Linux version 6.18.35-storytdx`), the RTMR3 extend,
the configfs-tsm quote provider (`tdx: using vendor adapter "direct"`), and the
gRPC service listening on `:50051`. The operator/auditor verify scripts derive
the on-chain governance values from a fresh quote (run them from a launcher
checkout with access to the quote):

```sh
launcher/attestation/verify-platform.sh   # platform_commitment
launcher/attestation/verify-rtmr3.sh      # code_commitment
```

Both must match your build's `manifest.json` and the on-chain
`TDXValidationHook.approvedPlatform[]` / `approvedBinary[]` entries.

## 5. Run story-kernel

story-kernel runs as a gRPC service: `story-kernel start` is auto-started by
`story-kernel.service` and exposes `KernelService` on `:50051`. There is nothing
to launch by hand once the TD boots — it comes up as part of the image.

The kernel does not act on its own; your **story consensus client** drives it.
When the validator joins a DKG round it calls the kernel over gRPC
(`GenerateAndSealKey` returns the DKG / communication public keys plus a TDX
quote), then submits the on-chain registration transaction itself;
`TDXValidationHook` verifies that quote against `approvedPlatform[]` /
`approvedBinary[]`. So you just point your validator at the kernel's gRPC endpoint
(`<vm-ip>:50051`) and let it drive registration and DKG participation.

If the consensus client's registration is rejected by the hook:

| Symptom | Cause |
|---|---|
| `approvedPlatform[X] = 0` | Your `platform_commitment` is not whitelisted (firmware drift or a non-approved machine type/vintage). |
| `approvedBinary[Y] = 0` | Your `code_commitment` is not whitelisted — rebuild from source and re-derive it. |
| `quote signature invalid` | Quote was not generated inside a real TDX TD. |

## Routine operations

### Recovering from a halt

systemd restarts story-kernel (`Restart=on-failure`, 5 s backoff). If it fails
repeatedly: check `journalctl -u story-kernel.service -e`. A common cause is
`story-kernel-rtmr3-extend.service` failing (configfs-tsm did not produce a valid
extend) — reboot the TD; first-boot ordering issues usually resolve on reboot.

### Upgrading

No in-place upgrade — dm-verity prevents replacing the binary, by design. You
upgrade by bringing up TDs on the new image/binary and migrating the key material
to them with a DKG **resharing** round:

1. New image published with a new `code_commitment`; governance approves it via
   `TDXValidationHook.approveBinary()`.
2. Bring up new TDs running the new image + binary and register them.
3. Run an upgrade **resharing** round: the existing global key is reshared from
   the old committee to the new (new-binary) one, so the global public key is
   preserved while the key shares move to the upgraded TDs.
4. Retire the old TDs once resharing completes.

### Rotating storage

The data partition (`/var/lib/story-kernel`) is the only writable mount and
survives reboots. To wipe and re-sync: stop the TD, delete the data volume,
recreate it, restart.

---

# Reference — how the image works on GCP

## Keyless reproducible kernel

The launcher boots a custom **Linux 6.18.35** kernel
(`linux-image-6.18.35-storytdx`), required because TDX attestation needs
measurement interfaces present only in kernel ≥ 6.16: `CONFIG_TSM_MEASUREMENTS`
(the `tdx_guest/measurements/rtmr3:sha384` sysfs for RTMR3 self-extend →
`code_commitment`) and `CONFIG_TSM_REPORTS` + `CONFIG_INTEL_TDX_GUEST` (the
configfs-tsm quote provider). The pinned config and build script are in
[`../kernel/`](../kernel).

It is built **keyless** (`CONFIG_MODULE_SIG=n`): no module-signing certificate is
embedded, so the build needs no private key and is bit-for-bit reproducible —
anyone can rebuild it and independently rederive `platform_commitment`. This is
safe because module signing is not the integrity control: modules sit on a
`dm-verity` read-only rootfs and integrity is enforced by measured boot + the
on-chain `code_commitment`/`platform_commitment` whitelist (see `threat-model.md`).
`build-kernel.sh` also disables `SECURITY_LOCKDOWN_LSM` (which would otherwise
`select MODULE_SIG`), pins `CONFIG_LOCALVERSION="-storytdx"` and the build
identity, and asserts the produced `.deb` is genuinely keyless.

## Boot configuration

The VM is created with `--confidential-compute-type=TDX
--maintenance-policy=TERMINATE --no-shielded-secure-boot` and
`--guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC`. The kernel command line
is the minimal set in `boot/kernel-cmdline` (`console=ttyS0`,
`random.trust_cpu=on`, plus the dm-verity root params), kept in lock-step with
`mkosi.conf` `KernelCommandLine` (enforced by `boot/diff-cmdline.sh`). The cmdline
is measured into `RTMR1`, so it is part of `platform_commitment`. Networking
comes up via DHCP on the GVNIC NIC (`20-wired.network`).

## Measured-boot chain and sealing

Boot order (systemd `Requires=`/`Before=`, fail-closed):

```
TDX firmware → RTMR0..RTMR2          (platform_commitment)
bootloader (systemd-boot/UKI) → kernel + initrd
kernel → dm-verity verified rootfs → systemd
  → measure-binary  : PCR 12 ← SHA-256(story-kernel ELF)
  → rtmr3-extend    : RTMR3   ← SHA-384(story-kernel ELF) via tdx_guest sysfs
  → story-kernel    : fetch config from metadata, then attest + run
```

Sealing and the PCR 12 measurement use the **GCP confidential-VM vTPM**
(`/dev/tpmrm0`); the key share is sealed under `PolicyPCR(PCR 7, 11, 12)` (Secure
Boot policy, UKI/dm-verity rootfs, story-kernel ELF), so it unseals only in that
exact measured boot. The TDX modules (`tdx-guest`, `tsm`) are loaded via
`modules-load.d`, and `systemd-firstboot` is masked with a stable
`/etc/machine-id` so boot reaches `multi-user.target` unattended.

## Node config — external injection

`story-kernel start` loads the light-client config (`chain_id`, `rpc_addr`,
`primary_addr`, `witness_addrs` ≥2, `trusted_height`, `trusted_hash`) from
instance metadata at boot (`story-kernel.service` `ExecStartPre` fetches
`story-kernel-config` into tmpfs). Keeping it out of the rootfs keeps both
commitments stable across chains/resets, and does not weaken the trust model: the
config never enters the seal policy (PCR 7/11/12) or the quote, and a forged
config cannot extract the sealed key or forge a registration on the real chain —
the quote's `report_data` binds the followed chain's
`startBlockHeight`/`startBlockHash`, which the consensus client re-checks against
real-chain state (see `threat-model.md` (C)).
