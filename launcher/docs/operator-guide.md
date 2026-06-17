# Operator guide

Steps a validator operator follows to put the launcher-built image
into production. Assumes you already have a TDX-capable host with
configfs-tsm available (Linux ≥ 6.7).

## Prerequisites

- TDX-capable host on an approved cloud / vintage
  (see `enclave/tdx/README.md` for the current support matrix)
- Outbound HTTPS to fetch the published image manifest
- The published reference manifest URL provided by governance

## Step 1: build the image

There is no published image distribution yet, so build it yourself. The
build is reproducible and does **not** require TDX hardware — any Linux
host with Docker is enough (TDX is only needed to *boot* the result):

```sh
# Emits launcher/out/: the TD .raw image, rootfs.verity, root-hash.txt,
# and manifest.json (sha256/sha384 of every artifact + the derived
# code_commitment).
./launcher/build/build.sh
```

`build.sh` builds the story-kernel binary, runs mkosi in a pinned builder
container, builds the dm-verity tree, and writes `manifest.json`.

## Step 2: (optional) confirm the build is reproducible

For independent assurance the build is deterministic, rebuild and diff
every artifact byte-for-byte:

```sh
./launcher/build/verify-reproducible.sh
```

## Step 3: launch the TD

> **The initial release supports GCP only.** Other configfs-tsm clouds
> (bare-metal / IBM / etc.) are planned but not yet validated for the
> launcher image — use GCP confidential VMs (Intel TDX) for now.

On GCP confidential compute with TDX:

```sh
gcloud compute instances create story-kernel-validator-N \
    --machine-type=c3-standard-4 \
    --confidential-compute-type=TDX \
    --image-project=<your-image-project> \
    --image=<imported-story-kernel-image> \
    --metadata=story-kernel-data-dir=/var/lib/story-kernel \
    --create-disk=name=story-kernel-data,size=100GB \
    --zone=<zone>
```

## Step 4: verify on first boot

Once the TD is up, SSH into the *operator console* — note that SSH
into the running TD itself is blocked by hardening. The "console"
here is whatever your cloud provides for confidential-compute
diagnostics.

The verify scripts are operator/auditor tooling, not baked into the
image — run them from a launcher checkout on the operator console:

```sh
# Extract platform_commitment from a fresh quote
sudo launcher/attestation/verify-platform.sh

# Extract code_commitment from RTMR3
sudo launcher/attestation/verify-rtmr3.sh
```

Both values must match the ones in your build's `manifest.json` and
the corresponding entries in `TDXValidationHook.approvedPlatform[]`
and `approvedBinary[]` on-chain.

## Step 5: register as a validator

story-kernel does **not** register itself — it runs as a gRPC service
(`story-kernel start`, auto-started by `story-kernel.service`) exposing
`KernelService`. Registration is driven by your **story consensus client**
(the validator node): when it joins DKG it calls the kernel over gRPC
(e.g. `GenerateAndSealKey`, which returns the DKG / communication public
keys plus a TDX quote), then submits the on-chain registration transaction
itself. That quote is what `TDXValidationHook` verifies against
`approvedPlatform[]` / `approvedBinary[]`.

So there is no `story-kernel` registration subcommand: point your validator
at the kernel's gRPC endpoint and let it drive DKG participation.

If the hook rejects the registration, the most common causes:

| Symptom | Cause |
|---|---|
| `approvedPlatform[X] = 0` | Your platform_commitment is not on the whitelist. Either firmware drifted or you are on a non-approved cloud vintage. |
| `approvedBinary[Y] = 0` | Your binary is not the whitelisted one. Rebuild from source and re-derive `code_commitment`. |
| `quote signature invalid` | Quote was generated outside a real TDX TD. Real TDX hardware is required. |

## Routine operations

### Recovering from a halt

If story-kernel exits, systemd will restart it (`Restart=on-failure`)
with a 5-second backoff. If the unit fails repeatedly:

1. Check the journal: `journalctl -u story-kernel.service -e`
2. Common cause: the `story-kernel-rtmr3-extend.service` failed,
   which means configfs-tsm did not produce a valid extend. Reboot
   the TD; first-boot ordering issues sometimes resolve on reboot.

### Upgrading

You do not upgrade by SSHing in and replacing the binary — that is
exactly what dm-verity prevents. Upgrades follow the path:

1. New image published with new `code_commitment`.
2. Governance approves new `code_commitment` via
   `TDXValidationHook.approveBinary()`.
3. You replace the entire TD with one running the new image.
4. Re-register if required by the new release notes.

There is no in-place upgrade. This is intentional.

### Rotating storage

The data partition (`/var/lib/story-kernel`) is the only writable
mount. It survives reboots. If you need to wipe and re-sync from
genesis: stop the TD, delete the data volume, recreate it, restart.
