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

- **[enclave/sgx/README.md](enclave/sgx/README.md)** — Intel SGX setup (Gramine 1.9, MRENCLAVE
  reproducibility, manifest sign + run, optional TLS/mTLS, systemd unit).
- **[enclave/tdx/README.md](enclave/tdx/README.md)** — Intel TDX overview (runtime requirements,
  vTPM-in-TCB requirement, the `supportedProviders` PolicyOR flow, bootstrap mode), with the
  host setup guide:
  - **[enclave/tdx/setup/direct.md](enclave/tdx/setup/direct.md)** — direct configfs-tsm path
    (bare-metal, GCP CVMs, IBM Cloud, OCI, future AWS TDX). Paravisor-mediated TDX guests
    (e.g., Azure CVM TDX with OpenHCL) are intentionally out of scope.

## Build

| Target | TEE backend | When to use |
|--------|-------------|-------------|
| `make build`     | noop | Local development. Every TEE operation fail-closes — DO NOT run on devnet or mainnet. |
| `make build-sgx` | sgx  | Production SGX/Gramine build. See [enclave/sgx/README.md](enclave/sgx/README.md). |
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
> Ubuntu-specific system library paths (e.g., `/lib/x86_64-linux-gnu/`). See
> [enclave/sgx/README.md](enclave/sgx/README.md) for the OS pinning requirement.

**Setup:**

```bash
sudo mkdir -p /opt/story-kernel
sudo chown $USER:$USER /opt/story-kernel
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
gating, file-access whitelist) live with each backend's documentation:

- **SGX**: see *Security Considerations (SGX-specific)* in
  [enclave/sgx/README.md](enclave/sgx/README.md).
- **TDX**: see the *vTPM-in-TCB requirement* and *supportedProviders flow* sections in
  [enclave/tdx/README.md](enclave/tdx/README.md), and the per-vendor setup guides under
  [enclave/tdx/setup/](enclave/tdx/setup/).

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
