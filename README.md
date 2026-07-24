# Story Kernel

[![Website](https://img.shields.io/badge/story.foundation-4B3263?style=flat&logo=google-chrome&logoColor=white)](https://www.story.foundation)
[![X](https://img.shields.io/badge/@StoryProtocol-000000?style=flat&logo=x&logoColor=white)](https://x.com/StoryProtocol)
[![codecov](https://codecov.io/gh/piplabs/story-kernel/branch/main/graph/badge.svg)](https://codecov.io/gh/piplabs/story-kernel)

> ⚠️ **WARNING**: This software has not been audited and is not production-ready. Use at your own risk.

Story Kernel is a Trusted Execution Environment (TEE) client for Story
Protocol's Distributed Key Generation (DKG) system. It runs inside a TEE
(Intel SGX or Intel TDX) to provide secure key generation, management, and
threshold decryption operations.

## Features

- **Distributed Key Generation (DKG)**: Implements Pedersen DKG protocol for secure distributed key generation
- **Remote Attestation**: Generates hardware-signed quotes (DCAP for SGX, raw V4/V5 quote for TDX direct mode) for trust establishment
- **Sealed Storage**: Keys are encrypted and sealed to the enclave's identity
- **TDH2 Partial Decryption**: Supports threshold decryption using the TDH2 scheme
- **Light Client Verification**: Verifies on-chain state using CometBFT light client

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Story Kernel                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │             TEE Backend (SGX or TDX)             │  │
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

The TEE backend is selected at build time. See **[enclave/README.md](enclave/README.md)** for the
backend abstraction overview, then drill into:

- **[enclave/tdx/README.md](enclave/tdx/README.md)** — Intel TDX overview (runtime requirements,
  vTPM-in-TCB requirement, the `supportedProviders` PolicyOR flow, bootstrap mode). For a
  production TDX node, build and operate the image under **[launcher/](launcher/)**.

## Build

| Target | TEE backend | When to use |
|--------|-------------|-------------|
| `make build`     | noop | Local development. Every TEE operation fail-closes — DO NOT run on devnet or mainnet. |
| `make build-sgx` | sgx  | Production SGX/Gramine build (run under Gramine). |
| `make build-tdx` | tdx  | Production Intel TDX build. See [enclave/tdx/README.md](enclave/tdx/README.md). |

Test/lint targets follow the same split: `make test` / `make lint` run under the SGX backend;
`make test-noop` / `make lint-noop` exercise the package-level shim and noop fail-closed paths
without TEE hardware; `make test-tdx` / `make lint-tdx` exercise the TDX backend with the TPM2
simulator and a mock quote provider — also no hardware required for unit tests.

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

The TDX backend reuses the same path for parity, even though TDX does not measure the filesystem
layout into the code commitment.

> **Note:** While the data directory is OS-agnostic, the SGX manifest still contains
> Ubuntu-specific system library paths (e.g., `/lib/x86_64-linux-gnu/`), which pins the
> build OS so MRENCLAVE stays reproducible.

**Setup:**

```bash
sudo mkdir -p /opt/story-kernel
sudo chown $USER:$USER /opt/story-kernel
```

## Configuration

`story-kernel init` writes a `config.toml` to the data directory. The settings
below are backend-agnostic — they apply to both the SGX and TDX builds.

### Client configuration

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

### (Optional) TLS / mTLS

By default the gRPC server runs in plaintext. To secure the connection between
the Story consensus client and story-kernel:

```bash
# Create CA (ECDSA P-256 recommended for performance)
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Story-Kernel-CA"

# Server cert (for story-kernel) — replace SAN values in production
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=story-kernel"
echo "subjectAltName = IP:127.0.0.1, DNS:localhost" > server-ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -extfile server-ext.cnf

# Client cert (for the story consensus client) — needed for mTLS
openssl ecparam -genkey -name prime256v1 -out client.key
openssl req -new -key client.key -out client.csr -subj "/CN=story-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365

chmod 600 ca.key server.key client.key
```

Server-side TLS only (story-kernel proves its identity to story):

```toml
# /opt/story-kernel/config.toml
[grpc]
listen_addr = ":50051"
tls_cert_file = "/path/to/server.crt"
tls_key_file = "/path/to/server.key"
```

Mutual TLS (both sides verify each other) — add the CA file:

```toml
# /opt/story-kernel/config.toml
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

> If no TLS fields are set, the gRPC connection runs in plaintext (insecure) —
> no changes needed for existing deployments. Certificate rotation requires a
> service restart.
>
> **SGX:** the certificate paths must also be added to the Gramine manifest's
> `allowed_files` so they are readable from inside the enclave.

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
├── enclave/          # TEE backend abstraction (see enclave/README.md)
│   ├── sgx/          # SGX backend (Gramine, DCAP)
│   └── tdx/          # TDX backend (configfs-tsm direct path)
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
The light client's trusted state is sealed by the active TEE backend, ensuring confidentiality
and integrity. `config.toml`, however, resides in the backend's allowed-files list and is not
sealed.

### Initialization strategy

On startup, the kernel determines its light client initialization strategy as follows:

| Sealed DB state | Action |
|-----------------|--------|
| Valid | Resume from sealed DB, use existing session nonce |
| Expired / Invalid | Re-initialize from `config.toml`, generate new session nonce |
| Missing | Initialize from `config.toml` (first boot), generate new session nonce |

A session nonce (32-byte random value) is stored in the sealed light client DB and embedded in
all sealed DKG files via the `NonceBindingSealer`. When the light client is re-initialized from
`config.toml` (due to expiration, corruption, or DB deletion), a new nonce is generated. Any
pre-existing sealed DKG files created under the prior nonce will fail verification at use time
and must be re-created through a new DKG round.

### Recovery after light client state loss

If the light client state is lost (DB deleted or expired beyond the trusted period), the kernel
will re-initialize from `config.toml` with a new session nonce. Existing sealed DKG files will
no longer be usable due to nonce mismatch. The operator must re-register for the current DKG
round to resume participation.

### Preventing light client state loss

To avoid the need for re-registration, operators should:

- **Keep the kernel running.** The light client state expires after the trusted period
  (~2 weeks of inactivity). Restarting within this window resumes normally from the sealed DB.
- **Monitor the kernel process.** If the kernel goes down, restart it promptly before the
  trusted period expires.
- **Do not delete files under `/opt/story-kernel/`.** The sealed light client DB and DKG state
  are critical persistent data.

## Security Considerations

Backend-specific security notes (MRENCLAVE reproducibility, sealed-storage semantics, debug-mode
gating, file-access whitelist) live with each backend's package and documentation:

- **TDX**: see the *vTPM-in-TCB requirement* and *supportedProviders flow* sections in
  [enclave/tdx/README.md](enclave/tdx/README.md), and the verification scripts under
  [launcher/attestation/](launcher/attestation/).

Cross-cutting:

- **Light Client Session Binding**: All sealed DKG files are bound to the light client DB
  session via a nonce. When the light client is re-initialized from `config.toml`, a new nonce
  is generated and prior sealed files are invalidated. See [Light Client Recovery](#light-client-recovery).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the
process for submitting pull requests.

## Security

For security concerns, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE)
file for details.
