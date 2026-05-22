# Direct (configfs-tsm) Setup

Direct adapter setup for TDX hosts that expose the upstream Linux guest
interface. Applies to:

- **Bare-metal** TDX hosts
- **GCP** Confidential VMs (TDX shape)
- **IBM Cloud** TDX VMs
- **Oracle Cloud Infrastructure** TDX shapes
- **AWS** TDX (when supported)

In all of the above, `V4.report_data` is guest-controlled — same semantics as
SGX `report_data`. The kernel's user_data (32-byte registration commitment)
is bound directly into `V4.report_data[0:32]` with `[32:64]` padded zero; the
on-chain `TDXValidationHook` reads `V4.report_data[0:32]` directly.

## Prerequisites

| Requirement | Verify |
|---|---|
| Linux kernel ≥ 6.7 | `uname -r` |
| configfs-tsm enabled | `ls /sys/kernel/config/tsm/report/` should exist |
| TDX guest module loaded | `dmesg \| grep -i "tdx"` should show TDX initialization |
| vTPM accessible | `ls /dev/tpmrm0` (preferred) or `ls /dev/tpm0` |
| FMSPC obtainable | needed for on-chain DCAP collateral upload (see story contracts repo) |

If `/sys/kernel/config/tsm/report/` returns ENOENT or `IsSupported()` fails,
the host is not TDX-capable through the direct path; either the kernel is
too old, or the TDX guest module is not loaded. Paravisor-mediated TDX
guests (e.g., Azure Confidential VM TDX with OpenHCL) are intentionally
out of scope — story-kernel only supports the upstream configfs-tsm path.

## Step 1 — Provision the host

The provisioning step varies per cloud. Common requirements:

- TDX-capable instance type (verify with cloud documentation)
- Kernel image with TDX guest support compiled in (Ubuntu 24.04 LTS is the
  reference image and ships a 6.8+ kernel)
- vTPM enabled in the instance configuration

### Cloud-specific notes

- **GCP**: select a Confidential VM shape that supports Intel TDX (e.g.,
  `c3-standard` with confidential computing enabled, region-dependent).
  Image: Ubuntu 24.04 LTS for Confidential VM.
- **IBM Cloud**: TDX-capable profiles in the secure execution catalog.
- **Bare-metal**: requires Intel SPR/EMR-class CPU with TDX firmware enabled
  and a kernel built with `CONFIG_INTEL_TDX_GUEST=y` and
  `CONFIG_TSM_REPORTS=y`.

## Step 2 — Verify the direct path

After SSH into the instance:

```bash
# Confirm TDX module loaded
dmesg | grep -i "tdx" | head -5
# Expect output like: "tdx: Guest detected"

# Confirm configfs-tsm interface present
ls /sys/kernel/config/tsm/report/
# Expect: directory exists (may be empty until a quote is requested)

# Confirm vTPM
ls -la /dev/tpmrm0 /dev/tpm0
```

## Step 3 — Install build deps

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

The TDX kernel binary lives at `./build/story-kernel`. There is no Gramine
manifest step — TDX runs as a normal Linux process inside the TD.

## Step 5 — Provision the data directory

```bash
sudo mkdir -p /opt/story-kernel
sudo chown $USER:$USER /opt/story-kernel

# Copy starter config
cp config/config.toml.example /opt/story-kernel/config.toml
# Edit /opt/story-kernel/config.toml: set chain_id, rpc_addr, trusted_height, trusted_hash
```

## Step 6 — Run

```bash
./build/story-kernel start --home /opt/story-kernel
```

Expected startup logs:

```
INFO Starting story-kernel commit=<sha> version=<v>
INFO tdx: using vendor adapter "direct"        ← direct adapter probed first and won
INFO sealdb: opened sealed LevelDB: /opt/story-kernel/light_client/light_client.db
INFO Initializing light client with trusted block: height=<h>, hash=<H>
INFO gRPC server is started: :50051
```

If you see `tdx: no vendor adapter probe succeeded`, configfs-tsm is missing
— re-check Step 2.

You can force the adapter explicitly with `STORY_TDX_VENDOR=direct
./build/story-kernel start ...` to fail fast if direct probe doesn't
succeed.

## Step 7 — On-chain registration

Code commitment for supported direct-mode TDX is `keccak256(RTMR2)`. The
Story-side `TDXValidationHook` independently derives the same binary
commitment from the registration quote and checks the platform half
`keccak256(MRTD || RTMR0 || RTMR1)` against its `approvePlatform` whitelist.
Submit the binary commitment to the DKG contract via
`whitelistEnclaveType(bytes32(2), {codeCommitment, TDXValidationHookProxy},
true)` (operator action, see story contracts repo), then approve each platform
commitment on the hook.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `tdx: no vendor adapter probe succeeded` | configfs-tsm missing | Verify kernel ≥ 6.7 with `CONFIG_INTEL_TDX_GUEST=y` and `CONFIG_TSM_REPORTS=y`. Check `dmesg \| grep tdx`. |
| `tdx: GetRawQuote: ...` at quote time | Quote service unreachable | Some hosts route quote generation via a host-side service (e.g., AESM-equivalent). Confirm host configuration with the cloud provider. |
| `failed to extend PCR <n>` | vTPM PCRs not writable | Confirm vTPM passthrough; check `/dev/tpmrm0` permissions and that the tpm2 kernel module is loaded. |
| Sealing/unsealing failures across reboots | PCR state diverges | The default `supportedProviders` in `enclave/tdx/providers.go` measures PCRs 7 and 11. If your stack uses different PCRs (e.g., a custom Secure Boot policy), edit the slice and rebuild — see the *supportedProviders flow* section in [../README.md](../README.md). |
