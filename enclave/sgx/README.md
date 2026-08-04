# SGX Backend

Intel SGX backend for Story Kernel, run under the Gramine LibOS. This document
covers setup, build, and run for SGX validators. For the TEE backend overview
see [enclave/README.md](../README.md).

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                 Gramine SGX Enclave                    │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐    │
│  │   DKG    │  │  Seal/   │  │   Light Client     │    │
│  │ Service  │  │  Unseal  │  │   (sealed DB)      │    │
│  └──────────┘  └──────────┘  └────────────────────┘    │
└────────────────────────────────────────────────────────┘
                          │
                      gRPC API
```

`enclave/sgx/` provides:

- `quote.go` — DCAP V3 quote generation via `/dev/attestation/quote`
- `seal.go` — Gramine sealing via the `SGX_KEYREQUEST` family
- `sealdb.go` — sealed LevelDB used by the light client + DKG state

## Hardware Requirements

- Intel CPU with SGX support enabled in BIOS
- DCAP-capable platform (PCK certificate provisioning available via PCCS)

## Software Requirements

All validators **must** use the exact same versions below to produce identical
`mr_enclave` (code commitment) values. The Gramine manifest content —
including resolved library paths — is measured into the enclave identity. Any
version difference can produce a different code commitment.

| Component | Required Version | Why pinned |
|-----------|-----------------|------------|
| **Ubuntu** | 24.04 LTS | Library paths (`/lib/x86_64-linux-gnu/`) are Ubuntu-specific and baked into MRENCLAVE |
| **Go** | 1.24.0 | Different Go versions (including patch) produce different binaries → different MRENCLAVE |
| **Gramine** | 1.9 | `gramine.libos` and `gramine.runtimedir()` resolve to version-specific paths → different MRENCLAVE |

> **Why Ubuntu only?** The manifest contains Ubuntu's multiarch library paths
> (`/lib/x86_64-linux-gnu/`). RHEL-based distros use `/lib64/` instead. Since
> the manifest is measured into MRENCLAVE, all validators must use the same
> OS to share a single code commitment.

## Installation

### 1. Install Build Dependencies

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev
```

### 2. Install Intel SGX SDK and DCAP

```bash
# Add Intel SGX repository
sudo mkdir -p /etc/apt/keyrings
wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt update

# Install SGX libraries
sudo apt install -y libsgx-dcap-default-qpl libsgx-enclave-common libsgx-quote-ex
```

### 3. Configure PCCS (Provisioning Certificate Caching Service)

DCAP quote generation needs Intel PCK collateral. Point `libsgx-dcap-default-qpl`
at a PCCS by editing `/etc/sgx_default_qcnl.conf`:

```json
{
  "pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/",
  "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/"
}
```

> **Choosing an endpoint.** The example above targets Intel's public PCS
> directly, which works on any DCAP-capable host. Operators with their own
> infrastructure should run a self-hosted PCCS (`libsgx-dcap-pccs`) for
> better availability and rate-limit isolation. Operators running Azure
> Confidential Compute VMs may prefer Azure's PCCS proxy
> (`https://global.acccache.azure.net/sgx/certification/v4/`); other
> environments should not rely on it.

### 4. Install Gramine 1.9

> **Version matters.** All validators must install the same Gramine version
> via the same method (apt). Do not build from source — it produces different
> library paths.

```bash
sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ noble main" | sudo tee /etc/apt/sources.list.d/gramine.list

sudo apt update
sudo apt install -y gramine=1.9
```

Verify the installation:

```bash
gramine-manifest --version   # should show 1.9
```

### 5. Clone and Build

```bash
git clone https://github.com/piplabs/story-kernel.git
cd story-kernel
make build-sgx
```

Test/lint targets: `make test` / `make lint` run under the SGX backend;
`make test-noop` / `make lint-noop` exercise the package-level shim and
fail-closed paths without TEE hardware.

## Running with Gramine SGX

### 1. Generate the Gramine Manifest

```bash
make gramine-manifest
```

### 2. Sign the Enclave

```bash
make gramine-sign
```

### 3. View Enclave Information

```bash
make gramine-enclave-info
```

This will display the `mr_enclave` (code commitment) value needed for
on-chain whitelisting via `DKG.whitelistEnclaveType(bytes32(1), {codeCommitment, validationHookAddr}, true)`.

### 4. Initialize Configuration

```bash
gramine-sgx story-kernel init --home /opt/story-kernel
```

This creates a configuration directory at `/opt/story-kernel/` with a
`config.toml` file.

> **Note:** The `init` command must be run separately because the production
> manifest hardcodes `argv` to `["story-kernel", "start", "--home",
> "/opt/story-kernel"]`. After initialization, the service starts
> automatically with the correct data directory.

### 5. Configure the Client & TLS

Client configuration (`[grpc]`, `[light_client]`) and the optional TLS/mTLS
setup are backend-agnostic — see **[Configuration](../../README.md#configuration)**
in the top-level README.

> **SGX-specific:** any TLS certificate paths must also be added to the Gramine
> manifest's `allowed_files` so they are readable from inside the enclave.

### 6. Start the Service

```bash
gramine-sgx story-kernel
```

The manifest's `loader.argv` is hardcoded to `["story-kernel", "start",
"--home", "/opt/story-kernel"]`, so no additional arguments are needed.

### 7. (Optional) Setup as Systemd Service

```bash
sudo tee /etc/systemd/system/story-kernel.service > /dev/null <<EOF
[Unit]
Description=Story DKG TEE Service
After=network.target

[Service]
User=$USER
WorkingDirectory=$HOME/story-kernel
ExecStart=/bin/bash -lc "gramine-sgx story-kernel 2>&1 | systemd-cat -t story-kernel"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable story-kernel.service
sudo systemctl start story-kernel.service

# View logs
journalctl -fu story-kernel
```

## Security Considerations (SGX-specific)

- **Code Commitment**: The `mr_enclave` value uniquely identifies the enclave
  code. Any modification to the binary or the Gramine manifest changes this
  value.
- **Sealed Storage**: Private keys are sealed using SGX sealing keys and can
  only be unsealed by the same enclave on the same platform.
- **Remote Attestation**: The service generates DCAP quotes that can be
  verified by remote parties via the on-chain `SGXValidationHook`.
- **SGX Debug Mode**: The manifest sets `sgx.debug = false` for production.
  Debug mode disables enclave memory protection and must never be enabled in
  production.
- **File Access**: The Gramine manifest restricts enclave file access to
  `/opt/story-kernel/` only. `/etc/ssl/certs/` is in `allowed_files` (not
  `trusted_files`) because CA certificate bundles differ across machines and
  would break MRENCLAVE reproducibility.
- **Fixed Data Path**: The data directory is `/opt/story-kernel/` (not
  `~/.story-kernel/`) to ensure all validators produce the same MRENCLAVE
  regardless of OS user. See the root README's *Data Directory* section.
- **MRENCLAVE Reproducibility**: The entire Gramine manifest — every byte —
  is measured into the code commitment. All values that could vary (log
  level, binary name) are hardcoded in the manifest. See *Software
  Requirements* above for the exact versions required.
