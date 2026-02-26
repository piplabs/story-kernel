# Story Kernel

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

- Ubuntu 24.04
- Go 1.24+
- Gramine 1.8+

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
echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list

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

### 4. Install Gramine

Follow the official Gramine installation guide: https://gramine.readthedocs.io/en/stable/installation.html

For Ubuntu, you can use:

```bash
sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/gramine.list

sudo apt update
sudo apt install -y gramine
```

### 5. Clone and Build

```bash
git clone https://github.com/piplabs/story-kernel.git
cd story-kernel

# Build the binary with cb-mpc library
make build-with-cpp
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
gramine-sgx story-kernel init
```

This creates a configuration directory at `~/.story-kernel` with a `config.toml` file.

### 5. Configure the Client

Edit `~/.story-kernel/config.toml`:

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

### 6. Start the Service

```bash
gramine-sgx story-kernel start
```

### 7. (Optional) Setup as Systemd Service

```bash
sudo tee /etc/systemd/system/story-kernel.service > /dev/null <<EOF
[Unit]
Description=Story DKG TEE Service
After=network.target

[Service]
User=$USER
WorkingDirectory=$HOME/story-kernel
ExecStart=/bin/bash -lc "gramine-sgx story-kernel start 2>&1 | systemd-cat -t story-kernel"
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

- **Code Commitment**: The `mr_enclave` value uniquely identifies the enclave code. Any modification to the binary changes this value.
- **Sealed Storage**: Private keys are sealed using SGX sealing keys and can only be unsealed by the same enclave on the same platform.
- **Remote Attestation**: The service generates DCAP quotes that can be verified by remote parties.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Security

For security concerns, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
