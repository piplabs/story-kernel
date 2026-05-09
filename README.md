# Story Kernel

[![Website](https://img.shields.io/badge/story.foundation-4B3263?style=flat&logo=google-chrome&logoColor=white)](https://www.story.foundation)
[![X](https://img.shields.io/badge/@StoryProtocol-000000?style=flat&logo=x&logoColor=white)](https://x.com/StoryProtocol)
[![codecov](https://codecov.io/gh/piplabs/story-kernel/branch/main/graph/badge.svg)](https://codecov.io/gh/piplabs/story-kernel)

> ⚠️ **WARNING**: This software has not been audited and is not production-ready. Use at your own risk.

Story Kernel is a Trusted Execution Environment (TEE) client for Story Protocol's Distributed Key Generation (DKG)
system. It runs inside Intel SGX enclaves to provide secure key generation, management, and threshold decryption
operations.

## Features

- **Distributed Key Generation (DKG)**: Implements Pedersen DKG protocol for secure distributed key generation
- **SGX Remote Attestation**: Generates and verifies SGX quotes for trust establishment
- **Sealed Storage**: Keys are encrypted and sealed to the enclave's identity
- **TDH2 Partial Decryption**: Supports threshold decryption using the TDH2 scheme
- **Light Client Verification**: Verifies on-chain state using CometBFT light client

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Story Kernel                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │               Gramine SGX Enclave                │  │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────┐  │  │
│  │  │   DKG    │  │  Seal/   │  │     Light      │  │  │
│  │  │ Service  │  │  Unseal  │  │     Client     │  │  │
│  │  └──────────┘  └──────────┘  └────────────────┘  │  │
│  └──────────────────────────────────────────────────┘  │
│                          │                             │
│                      gRPC API                          │
└──────────────────────────┼─────────────────────────────┘
                           │
                    Story Network
```

## Prerequisites

### Hardware Requirements

- Intel CPU with SGX support enabled in BIOS

### Software Requirements

All validators **must** use the exact same versions below to produce identical `mr_enclave`
(code commitment) values. The Gramine manifest content — including resolved library paths — is
measured into the enclave identity. Any version difference can produce a different code commitment.

| Component | Required Version | Why pinned |
|-----------|-----------------|------------|
| **Ubuntu** | 24.04 LTS | Library paths (`/lib/x86_64-linux-gnu/`) are Ubuntu-specific and baked into MRENCLAVE |
| **Go** | 1.24.0 | Different Go versions (including patch) produce different binaries → different MRENCLAVE |
| **Gramine** | 1.9 | `gramine.libos` and `gramine.runtimedir()` resolve to version-specific paths → different MRENCLAVE |

> **Why Ubuntu only?** The manifest contains Ubuntu's multiarch library paths
> (`/lib/x86_64-linux-gnu/`). RHEL-based distros use `/lib64/` instead. Since
> the manifest is measured into MRENCLAVE, all validators must use the same OS
> to share a single code commitment.

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

Edit `/etc/sgx_default_qcnl.conf` to set the PCCS endpoint:

```json
{
  "pccs_url": "https://global.acccache.azure.net/sgx/certification/v4/",
  "collateral_service": "https://global.acccache.azure.net/sgx/certification/v4/"
}
```

### 4. Install Gramine 1.9

> **Version matters.** All validators must install the same Gramine version via
> the same method (apt). Do not build from source — it produces different library
> paths.

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

# Build for production SGX/Gramine (use this on validator machines)
make build-sgx
```

Available build targets:

| Target          | TEE backend | When to use                                                              |
|-----------------|-------------|--------------------------------------------------------------------------|
| `make build`    | noop        | Local development. Every TEE operation fail-closes — DO NOT run on devnet or mainnet. |
| `make build-sgx`| sgx         | Production SGX/Gramine build. Replaces the former `make build-with-cpp`. |
| `make build-tdx`| tdx         | Production Intel TDX build. See "TDX Build & Runtime" below for runtime requirements. |

Test and lint targets follow the same split: `make test` / `make lint`
run under the SGX backend, `make test-noop` / `make lint-noop` exercise
the package-level shim and noop fail-closed paths without TEE hardware,
and `make test-tdx` / `make lint-tdx` exercise the TDX backend with the
TPM2 simulator and a mock quote provider — also no hardware required for
unit tests.

## TDX Build & Runtime

Intel TDX is supported as an alternative TEE backend behind the `tdx` Go
build tag. Selection between SGX and TDX is a build-time decision (one tag
per binary); a single binary cannot run on both platforms. The TDX backend
lives in its own Go sub-package at `enclave/tdx/`; the SGX backend lives at
`enclave/sgx/`. The `cmd/tee_*.go` blank imports under build tags are the
only build-time selectors.

### Runtime requirements

| Component | Requirement | Why |
|---|---|---|
| Linux kernel | **>= 6.7** required | configfs-tsm interface (`/sys/kernel/config/tsm/report/`) is the only supported attestation path. Older kernels without configfs-tsm support are not supported by this backend. |
| TDX device | `/sys/kernel/config/tsm/report/` (configfs-tsm) | Only configfs-tsm is supported. The legacy `/dev/tdx_guest` ioctl path is **not** used as a fallback in the current implementation (`LinuxConfigFsQuoteProvider` does not delegate to it). |
| vTPM | Reachable at `/dev/tpmrm0` (preferred) or `/dev/tpm0` | Sealing is bound to the vTPM PolicyOR over PCRs. |
| Persistent TPM handle | **0x81000001 reserved** | Storage-root key is evicted to this conventional SRK handle. Operators must not assign this handle to other applications. |

### vTPM-in-TCB requirement

The TDX backend's sealing security depends on the vTPM being inside the TD's
Trusted Computing Base. Two acceptable deployment models:

1. **Paravisor with in-TD vTPM** (e.g., Azure Confidential VM with paravisor):
   the vTPM is provided by code that runs inside the TD and whose measurement
   is captured in MRTD/RTMR.
2. **In-TD swtpm in the initrd**: bundle `swtpm` into the TD's initrd such
   that it is measured into MRTD; no out-of-TD vTPM service.

Running with an out-of-TCB vTPM (e.g., a vTPM provided by the host hypervisor
without paravisor measurement) is **unsafe** and explicitly out of scope.
The kernel **does not** detect or enforce this — it is an operator obligation.

### supportedProviders flow

The set of accepted PCR-extension states is encoded as a Go constant slice
`supportedProviders` in `enclave/tdx/providers.go`. The default ships one
provider:

```go
{
    Name:           "default-tpm-pcrs-7-11",
    PCRs:           []int{7, 11},
    ExpectedDigest: nil, // bootstrap mode — populated empirically on first deploy
    HashAlg:        tpm2.AlgSHA256,
}
```

PCR 7 captures Secure Boot policy; PCR 11 captures the Linux IMA / dm-verity
disk-image root-hash measurement. **Operators on a different vTPM stack must
edit `supportedProviders` and rebuild.**

#### First deployment (bootstrap mode)

When **every** entry in `supportedProviders` has `ExpectedDigest == nil`, the
TDX backend boots in bootstrap mode. The startup self-check emits a WARN log
containing the empirically measured PCR digest in copy-pasteable hex:

```
WARN[ts] TDX backend in bootstrap mode — no provider has a populated ExpectedDigest.
       Current PCR digests by provider:
         default-tpm-pcrs-7-11 (PCRs 7,11): 0x<64-hex-chars>
       Populate the matching entry in supportedProviders[].ExpectedDigest
       and rebuild before production deployment.
```

The operator pastes the measured digest into source as
`ExpectedDigest: []byte{0x..., 0x..., ...}` and rebuilds. From that point on
the gate becomes strict: any boot whose PCR state does not match a populated
entry will `log.Fatal` and refuse to start.

#### Adding more providers

Adding a second acceptable PCR state (e.g., for a planned firmware upgrade)
is also a code edit + redeploy. The TPM enforces a PolicyOR over all
populated branches, so any of them satisfies the unseal policy.

### Out of scope (this repository)

The following are explicitly NOT covered by `make build-tdx` or this
repository's CI:

- **TD disk image construction**: initrd, OVMF, td-shim, dm-verity hash chain.
- **vTPM provisioning**: swtpm setup, paravisor configuration, EK/SRK
  pre-eviction.
- **dm-crypt automation**: disk encryption keys derivation, PCR-locked
  unlock flows.
- **Launch orchestration**: systemd units, node-launcher integration, kernel
  command-line wiring.
- **On-chain TDX whitelisting**: `TDXValidationHook` contract deployment and
  `whitelistEnclaveType("TDX", ...)` registration are operator and
  contract-team work tracked in their respective repositories.

These are tracked in deployment runbooks and `node-launcher` work, not here.

### Hardware-in-the-loop validation

The unit-test suite (`make test-tdx`) runs entirely on the TPM2 simulator
plus a mock quote provider — no TDX silicon required, suitable for CI. Real
behavior on a TDX host is validated separately via the deployment pipeline:

1. Boot a TDX-capable host with kernel >= 6.7 and configfs-tsm enabled.
2. Provision a vTPM that satisfies the in-TCB requirement above.
3. `make build-tdx && ./build/story-kernel run` and verify the startup
   self-check WARN/INFO format and a quote round-trip.

## Data Directory

Story Kernel uses a fixed data directory at `/opt/story-kernel/` instead of the conventional
`~/.story-kernel/` under the user's home directory.

**Why `/opt/story-kernel/`?**

In SGX, the Gramine manifest — including all file paths — is loaded into enclave memory and
measured into `mr_enclave` (code commitment). If the manifest contained a user-dependent path
like `/home/ubuntu/.story-kernel/`, every validator would need the exact same OS username to
produce matching code commitments. Since different cloud providers use different default users
(AWS: `ubuntu`, Azure: `azureuser`, GCP: varies), a user-dependent path would break
cross-environment reproducibility.

By using `/opt/story-kernel/` — a fixed, OS-agnostic path following the
[Filesystem Hierarchy Standard](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s13.html) —
all validators produce identical manifests and therefore identical code commitments, regardless
of their OS user or cloud provider.

> **Note:** While the data directory is OS-agnostic, the manifest still contains Ubuntu-specific
> system library paths (e.g., `/lib/x86_64-linux-gnu/`). See [Software Requirements](#software-requirements)
> for details on OS support.

**Setup:**

```bash
sudo mkdir -p /opt/story-kernel
sudo chown $USER:$USER /opt/story-kernel
```

## Running with Gramine SGX

### 1. Generate Gramine Manifest

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

This will display the `mr_enclave` (code commitment) value needed for registration.

### 4. Initialize Configuration

```bash
gramine-sgx story-kernel init --home /opt/story-kernel
```

This creates a configuration directory at `/opt/story-kernel/` with a `config.toml` file.

> **Note:** The `init` command must be run separately because the production manifest
> hardcodes `argv` to `["story-kernel", "start", "--home", "/opt/story-kernel"]`.
> After initialization, the service starts automatically with the correct data directory.

### 5. Configure the Client

Edit `/opt/story-kernel/config.toml`:

```toml
log-level = "info"

[grpc]
listen_addr = ":50051"

[light_client]
chain_id = "devnet-1"
rpc_addr = "http://localhost:26657"
primary_addr = "http://localhost:26657"
witness_addrs = ["http://witness1:26657", "http://witness2:26657"]
trusted_height = 1000000
trusted_hash = "ABCD1234..."
```

### 6. (Optional) Enable TLS/mTLS

By default, the gRPC server runs without TLS. To secure the connection between Story and story-kernel:

**Generate certificates:**

```bash
# Create CA (ECDSA P-256 recommended for performance)
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Story-Kernel-CA"

# Create server cert (for story-kernel)
# NOTE: Replace SAN values with actual hostnames/IPs in production
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=story-kernel"
echo "subjectAltName = IP:127.0.0.1, DNS:localhost" > server-ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -extfile server-ext.cnf

# Create client cert (for story consensus client)
openssl ecparam -genkey -name prime256v1 -out client.key
openssl req -new -key client.key -out client.csr -subj "/CN=story-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365

# Restrict key file permissions
chmod 600 ca.key server.key client.key
```

> Certificate rotation requires a service restart. Gramine SGX users must add cert paths to the manifest's `allowed_files`.

**Server-side TLS only** (story-kernel verifies its identity to story):

```toml
# In /opt/story-kernel/config.toml
[grpc]
listen_addr = ":50051"
tls_cert_file = "/path/to/server.crt"
tls_key_file = "/path/to/server.key"
```

**Mutual TLS** (both sides verify each other):

```toml
# In /opt/story-kernel/config.toml
[grpc]
listen_addr = ":50051"
tls_cert_file = "/path/to/server.crt"
tls_key_file = "/path/to/server.key"
tls_ca_file = "/path/to/ca.crt"      # enables client cert verification
```

On the **story consensus client** side, configure in `story.toml`:

```toml
[dkg]
kernel-endpoints = ["tls://127.0.0.1:50051"]
kernel-tls-ca-file = "/path/to/ca.crt"
kernel-tls-cert-file = "/path/to/client.crt"   # for mTLS
kernel-tls-key-file = "/path/to/client.key"     # for mTLS
```

> If no TLS fields are set, the gRPC connection runs in plaintext (insecure) mode — no changes needed for existing deployments.

### 7. Start the Service

```bash
gramine-sgx story-kernel
```

The manifest's `loader.argv` is hardcoded to `["story-kernel", "start", "--home", "/opt/story-kernel"]`,
so no additional arguments are needed.

### 8. (Optional) Setup as Systemd Service

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

## Development

### Running Tests

```bash
make test
```

### Regenerating Protobuf Files

```bash
make proto-gen
```

### Code Linting

```bash
make lint
```

### Pre-commit Hooks

Install pre-commit hooks:

```bash
pip install pre-commit
pre-commit install
```

## Project Structure

```
story-kernel/
├── cmd/              # CLI commands (init, start)
├── config/           # Configuration handling
├── crypto/           # Cryptographic utilities
├── enclave/          # SGX enclave operations (seal, quote)
├── proto/            # Protocol buffer definitions
├── server/           # gRPC server implementation
├── service/          # DKG service logic
├── store/            # State and key storage
├── story/            # Story chain client
└── types/            # Common types and protobuf conversions
```

## API Reference

The service exposes a gRPC API with the following methods:

| Method | Description |
|--------|-------------|
| `GenerateAndSealKey` | Generate and seal Ed25519/Secp256k1 key pairs |
| `GenerateDeals` | Generate DKG deals for distribution |
| `ProcessDeals` | Process received DKG deals |
| `ProcessResponses` | Process DKG responses |
| `FinalizeDKG` | Finalize DKG and produce distributed key share |
| `PartialDecryptTDH2` | Perform TDH2 partial decryption |

## Light Client Recovery

Story Kernel uses a CometBFT light client backed by a sealed LevelDB to verify on-chain state.
The light client's trusted state is sealed with SGX, ensuring confidentiality and integrity.
`config.toml`, however, resides in `allowed_files` and is not sealed.

### Initialization strategy

On startup, the kernel determines its light client initialization strategy as follows:

| Sealed DB state | Action |
|-----------------|--------|
| Valid | Resume from sealed DB, use existing session nonce |
| Expired / Invalid | Re-initialize from `config.toml`, generate new session nonce |
| Missing | Initialize from `config.toml` (first boot), generate new session nonce |

A session nonce (32-byte random value) is stored in the sealed light client DB and
embedded in all sealed DKG files via the `NonceBindingSealer`. When the light client is
re-initialized from `config.toml` (due to expiration, corruption, or DB deletion), a new
nonce is generated. Any pre-existing sealed DKG files created under the prior nonce will
fail verification at use time and must be re-created through a new DKG round.

### Recovery after light client state loss

If the light client state is lost (DB deleted or expired beyond the trusted period),
the kernel will re-initialize from `config.toml` with a new session nonce. Existing
sealed DKG files will no longer be usable due to nonce mismatch. The operator must
re-register for the current DKG round to resume participation.

### Preventing light client state loss

To avoid the need for re-registration, operators should:

- **Keep the kernel running.** The light client state expires after the trusted period
  (~2 weeks of inactivity). Restarting within this window resumes normally from the sealed DB.
- **Monitor the kernel process.** If the kernel goes down, restart it promptly before the
  trusted period expires.
- **Do not delete files under `/opt/story-kernel/`.** The sealed light client DB and DKG
  state are critical persistent data.

## Security Considerations

- **Code Commitment**: The `mr_enclave` value uniquely identifies the enclave code. Any modification to the binary or the Gramine manifest changes this value.
- **Sealed Storage**: Private keys are sealed using SGX sealing keys and can only be unsealed by the same enclave on the same platform.
- **Remote Attestation**: The service generates DCAP quotes that can be verified by remote parties.
- **SGX Debug Mode**: The manifest sets `sgx.debug = false` for production. Debug mode disables enclave memory protection and must never be enabled in production.
- **File Access**: The Gramine manifest restricts enclave file access to `/opt/story-kernel/` only. `/etc/ssl/certs/` is in `allowed_files` (not `trusted_files`) because CA certificate bundles differ across machines and would break MRENCLAVE reproducibility.
- **Fixed Data Path**: The data directory is `/opt/story-kernel/` (not `~/.story-kernel/`) to ensure all validators produce the same MRENCLAVE regardless of OS user. See the [Data Directory](#data-directory) section for details.
- **MRENCLAVE Reproducibility**: The entire Gramine manifest — every byte — is measured into the code commitment. All values that could vary (log level, binary name) are hardcoded in the manifest. See [Software Requirements](#software-requirements) for the exact versions required.
- **Light Client Session Binding**: All sealed DKG files are bound to the light client DB session via a nonce. When the light client is re-initialized from `config.toml`, a new nonce is generated and prior sealed files are invalidated. See the [Light Client Recovery](#light-client-recovery) section for details.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Security

For security concerns, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
