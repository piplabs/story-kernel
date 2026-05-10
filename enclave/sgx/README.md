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

Edit `/etc/sgx_default_qcnl.conf` to set the PCCS endpoint:

```json
{
  "pccs_url": "https://global.acccache.azure.net/sgx/certification/v4/",
  "collateral_service": "https://global.acccache.azure.net/sgx/certification/v4/"
}
```

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

By default, the gRPC server runs without TLS. To secure the connection
between Story consensus client and story-kernel:

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

> Certificate rotation requires a service restart. Gramine SGX users must add
> cert paths to the manifest's `allowed_files`.

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
kernel-tls-key-file = "/path/to/client.key"    # for mTLS
```

> If no TLS fields are set, the gRPC connection runs in plaintext (insecure)
> mode — no changes needed for existing deployments.

### 7. Start the Service

```bash
gramine-sgx story-kernel
```

The manifest's `loader.argv` is hardcoded to `["story-kernel", "start",
"--home", "/opt/story-kernel"]`, so no additional arguments are needed.

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
