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

# Build the binary with cb-mpc library
make build-with-cpp
```

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
chain_id = "odyssey-1"
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

## Security Considerations

- **Code Commitment**: The `mr_enclave` value uniquely identifies the enclave code. Any modification to the binary or the Gramine manifest changes this value.
- **Sealed Storage**: Private keys are sealed using SGX sealing keys and can only be unsealed by the same enclave on the same platform.
- **Remote Attestation**: The service generates DCAP quotes that can be verified by remote parties.
- **SGX Debug Mode**: The manifest sets `sgx.debug = false` for production. Debug mode disables enclave memory protection and must never be enabled in production.
- **File Access**: The Gramine manifest restricts enclave file access to `/opt/story-kernel/` only. `/etc/ssl/certs/` is in `allowed_files` (not `trusted_files`) because CA certificate bundles differ across machines and would break MRENCLAVE reproducibility.
- **Fixed Data Path**: The data directory is `/opt/story-kernel/` (not `~/.story-kernel/`) to ensure all validators produce the same MRENCLAVE regardless of OS user. See the [Data Directory](#data-directory) section for details.
- **MRENCLAVE Reproducibility**: The entire Gramine manifest — every byte — is measured into the code commitment. All values that could vary (log level, binary name) are hardcoded in the manifest. See [Software Requirements](#software-requirements) for the exact versions required.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Security

For security concerns, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
