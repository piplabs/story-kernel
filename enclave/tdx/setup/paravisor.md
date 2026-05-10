# Paravisor-mediated Setup

Paravisor adapter setup for TDX hosts whose guest interface is mediated by a
paravisor (the upstream Linux TDX guest driver returns ENXIO; quote
acquisition goes through a vTPM HCL envelope + an IMDS-style QGS endpoint).

The current production deployment of this shape is **OpenHCL paravisor on
Hyper-V**, used by **Azure Confidential VM TDX**. The kernel-side adapter
(`enclave/tdx/platform/paravisor/`) is not Azure-specific — any future
paravisor with the same wire-level shape (HCL envelope at NV `0x01400001` +
IMDS QGS endpoint) reuses the same code path. This document focuses on the
Azure CVM TDX setup because that is the only environment where the
paravisor path is currently exercised.

## Why a separate path

On a paravisor-mediated guest, `V4.report_data` is **not** guest-controlled.
The paravisor locks `V4.report_data[:32]` to `SHA256(VariableData)`, where
`VariableData` is a JSON envelope the paravisor builds at boot containing
the AK pub. The kernel cannot place its 32-byte registration commitment
into `V4.report_data` directly. Instead it:

1. Reads the HCL envelope from NV index `0x01400001` (vTPM).
2. Submits the inner TDREPORT to the IMDS QGS endpoint
   `http://169.254.169.254/acc/tdquote` to receive a V4 quote.
3. Locally runs `TPM2_Quote(AK, qualifyingData = registrationCommitment)`
   to bind the registration commitment via `TPMS_ATTEST.qualifyingData`.
4. Wraps everything (V4 + tpm_attest + sig + AK pub + VariableData) into a
   Path-B "STBN" bundle.

The on-chain `TDXValidationHook` decodes the bundle, DCAP-verifies the V4,
RSASSA-verifies the TPM2 signature, and checks
`TPMS_ATTEST.qualifyingData == expectedDataCommitment`.

## Prerequisites

- Azure subscription with quota for TDX-capable Confidential VM SKUs (DCesv5
  / DCedsv5 family, region-dependent — West Europe and East US 2 are good
  defaults at time of writing).
- Quota approval for confidential computing may require a support ticket for
  newer subscriptions; check the Azure portal for *Confidential computing*
  in your subscription's *Usage + quotas*.
- A vTPM is mandatory for Confidential VMs; this is enabled by default for
  the supported SKUs.

## Step 1 — Provision the VM

Via Azure Portal:

1. **Create a virtual machine** → *Confidential virtual machines* under
   *Security type*.
2. **Region**: a TDX-capable region (West Europe, East US 2, etc.).
3. **Size**: select a TDX SKU. Recommended:
   - `Standard_DC4es_v5` (4 vCPU, 16 GB) for testing
   - `Standard_DC8es_v5` (8 vCPU, 32 GB) for validators
4. **Image**: *Ubuntu Server 24.04 LTS* (Confidential VM image).
5. **Confidential computing**: leave default (Intel TDX, vTPM enabled,
   secure boot enabled).
6. **Networking**: open SSH (22). gRPC port (50051) is for kernel ↔ story
   communication and should stay localhost-only.
7. Provision and SSH in.

Or via CLI:

```bash
az vm create \
  --resource-group <rg> \
  --name <name> \
  --location westeurope \
  --image Canonical:ubuntu-24_04-lts-cvm:server:latest \
  --size Standard_DC4es_v5 \
  --security-type ConfidentialVM \
  --enable-secure-boot true \
  --enable-vtpm true \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --admin-username ubuntu \
  --ssh-key-values @~/.ssh/id_ed25519.pub
```

## Step 2 — Verify the paravisor path

After SSH in:

```bash
# Confirm Hyper-V isolation type 3 (TDX paravisor)
sudo dmesg | grep -iE "hyper-v|isolation"
# Expect: lines mentioning "Hyper-V Host Build" and a TDX/isolation indicator.

# Confirm vTPM is reachable
ls -la /dev/tpmrm0
# Expect: character device 0600 root tss (or similar, may vary)

# Confirm the HCL envelope exists at NV 0x01400001
# Install tpm2-tools if missing:
sudo apt update && sudo apt install -y tpm2-tools

# Read the first 32 bytes of NV 0x01400001 — should start with HCLA magic (LE 0x414c4348 = "HCLA" reversed).
sudo tpm2_nvread 0x01400001 -s 32 | xxd | head -1
# Expect: "48 43 4c 41 ..." (the magic) followed by the HCL envelope header.

# Confirm the IMDS QGS endpoint is reachable
curl -sS -o /dev/null -w "%{http_code}\n" -X HEAD \
  -H "Metadata: true" \
  http://169.254.169.254/acc/tdquote
# Any 4xx (e.g., 405 Method Not Allowed for HEAD) confirms reachability.

# Confirm direct path is unavailable (expected on paravisor)
ls /sys/kernel/config/tsm/report/ 2>&1
# Expect: "No such file or directory" — or if present, the kernel-side adapter
# probe will return ENXIO. Either way the paravisor adapter is selected.
```

If the above all check out, the paravisor adapter will succeed at runtime.

## Step 3 — Install build deps

Same as the direct-mode setup:

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev curl wget jq python3 \
    git ca-certificates gnupg lsb-release tpm2-tools

# Go 1.24
GO_VER=1.24.0
wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz"
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.profile"
export PATH=$PATH:/usr/local/go/bin
go version  # should show 1.24.0
```

## Step 4 — Clone and build

```bash
git clone https://github.com/piplabs/story-kernel.git
cd story-kernel
git checkout main  # or the release tag
make build-tdx
ls -la build/story-kernel
```

## Step 5 — Provision the data directory

```bash
sudo mkdir -p /opt/story-kernel
sudo chown $USER:$USER /opt/story-kernel

cp config/config.toml.example /opt/story-kernel/config.toml
# Edit: set chain_id, rpc_addr, trusted_height, trusted_hash
```

## Step 6 — Run

```bash
./build/story-kernel start --home /opt/story-kernel
```

Expected startup logs:

```
INFO Starting story-kernel commit=<sha> version=<v>
INFO tdx: using vendor adapter "paravisor"     ← direct probe failed (ENXIO), paravisor probe succeeded
WARN TDX backend in bootstrap mode — no provider has a populated ExpectedDigest.
       Current PCR digests by provider:
         default-tpm-pcrs-7-11 (PCRs 7,11): 0x<64-hex-chars>
       Populate the matching entry in supportedProviders[].ExpectedDigest
       and rebuild before production deployment.
INFO sealdb: opened sealed LevelDB: /opt/story-kernel/light_client/light_client.db
INFO gRPC server is started: :50051
```

The bootstrap-mode WARN is expected on first boot. Capture the digest, paste
into `enclave/tdx/providers.go`, rebuild, redeploy. From then on the
backend enforces strict matching. See the *supportedProviders flow* section
in [../README.md](../README.md).

To force-select the paravisor adapter (e.g., to fail fast if the paravisor
probe regresses): `STORY_TDX_VENDOR=paravisor ./build/story-kernel start
...`. To deliberately reject `STORY_TDX_BUNDLE_MODE=raw_v4`: this raw_v4
mode is **not** supported under paravisor because `V4.report_data` is
locked, and the adapter returns `ErrParavisorBundleModeRawV4` if the env
var is set.

## Step 7 — On-chain registration

Code commitment for paravisor-mode TDX is the same as direct mode:
`keccak256(MRTD || RTMR0 || RTMR1 || RTMR2 || RTMR3)`. The paravisor's
HCL envelope binds the AK to the TD measurement, but on-chain we still
identify the kernel by its TD measurement, not by AK identity.

The on-chain validation difference is in *how* the user_data is bound:

- **Direct mode**: `V4.report_data[0:32] == expectedDataCommitment`.
- **Paravisor mode (Path-B bundle)**: `TPMS_ATTEST.qualifyingData ==
  expectedDataCommitment`, after the on-chain `TDXValidationHook` has
  RSASSA-verified the TPM2 signature with the AK pub from the bundle.

Submit the code commitment via `whitelistEnclaveType(bytes32(2),
{codeCommitment, TDXValidationHookProxy}, true)` (operator action, see
story contracts repo).

## Step 8 — (Optional) Setup as systemd service

```bash
sudo tee /etc/systemd/system/story-kernel.service > /dev/null <<EOF
[Unit]
Description=Story DKG TEE Service (TDX paravisor)
After=network.target

[Service]
User=$USER
WorkingDirectory=$HOME/story-kernel
ExecStart=$HOME/story-kernel/build/story-kernel start --home /opt/story-kernel
Restart=always
RestartSec=5
StandardOutput=append:/var/log/story-kernel.log
StandardError=append:/var/log/story-kernel.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now story-kernel
journalctl -fu story-kernel
```

## Common pitfalls observed during devnet bring-up

The following issues came up during the `weu-dkg-tdx-test` Azure CVM TDX
deployment and are worth checking up-front on a new host:

| Symptom | Root cause | Mitigation |
|---|---|---|
| `tpm2_nvread 0x01400001` returns "object not found" | Older Azure CVM image without HCL envelope provisioning | Use a recent Ubuntu 24.04 LTS Confidential VM image; confirm the image SKU includes paravisor support. |
| `IMDS HEAD failed: connection refused` | IMDS endpoint disabled or blocked | IMDS is enabled by default on Azure VMs. Check `iptables -L` for any rule blocking 169.254.169.254. The `Metadata: true` header is mandatory. |
| Kernel falls back to `direct` adapter and fails | A non-CVM SKU was selected (no paravisor) | Confirm the VM was created with `Security type = Confidential virtual machines` and a `DC*es_v5` size. `DCsv5` (without `es`) is *not* TDX. |
| Quote round-trip succeeds but on-chain hook reverts `AK binding (paravisor) mismatch` | The bundle's `runtime_data` was tampered or the paravisor's `VariableData` shape is unexpected | The kernel selfcheck (`enclave/tdx/selfcheck.go`) verifies `SHA256(VariableData) == V4.report_data[:32]` before submitting the bundle. If selfcheck passes locally but on-chain rejects, file an issue with the captured bundle bytes. |
| Round 1 finalize fails with `dkg: distributed key not certified` | Vote extensions disabled in CL genesis | This is a chain-side genesis configuration issue, not TDX-specific — set `vote_extensions_enable_height = 1` in the CL genesis. |
