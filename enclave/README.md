# TEE Backends

Story Kernel runs inside a Trusted Execution Environment (TEE) so that key
material, attestation quotes, and the DKG state machine all live behind a
hardware boundary. Two backends are supported, selected at build time by Go
build tag:

| Build tag | Backend | Package | Hardware |
|---|---|---|---|
| `sgx` (default for `make build-sgx`) | Intel SGX, run under Gramine LibOS | `enclave/sgx` | Intel CPU with SGX + DCAP |
| `tdx` (`make build-tdx`) | Intel TDX, native Linux guest | `enclave/tdx` | Intel CPU with TDX + supported guest interface |
| `noop` (default `make build`) | Fail-closed shim, no TEE | (built-in) | Local development only |

Selection is **build-time**: a single binary cannot run on both SGX and TDX.
The `cmd/tee_*.go` blank imports under build tags are the only build-time
selectors. There is no runtime negotiation.

## Common contract

Both production backends implement the same Go interface so the rest of the
kernel (`service/`, `server/`, `store/`) is backend-agnostic:

| Interface | Purpose |
|---|---|
| `enclave.Quoter` | Produce an attestation quote that binds 64 bytes of caller data into the hardware-signed report (`V4.report_data` for TDX, `report_data` for SGX). |
| `enclave.Sealer` | Encrypt arbitrary bytes such that only the same enclave on the same platform can decrypt. |
| `enclave.SealDB` | Sealed key-value store backed by the sealer. Used for the light-client trusted state and DKG sealed shares. |

Implementations live at:

- `enclave/sgx/` — Gramine SGX seal + DCAP quote + sealed DB
- `enclave/tdx/` — TDX configfs-tsm or paravisor quote + vTPM-PolicyOR seal + sealed DB

## Quote semantics in one sentence

The on-chain validation hooks (`SGXValidationHook` and `TDXValidationHook` in
the `story` contracts repo) treat the kernel as a black-box trust anchor whose
quote binds two 32-byte commitments:

1. **codeCommitment** — proves *what code* is running (MRENCLAVE for SGX,
   `keccak256(MRTD || RTMR0..3)` for TDX, both compared against the
   `DKG.enclaveTypeData[enclaveType].codeCommitment` whitelist).
2. **dataCommitment** — proves *which on-chain registration* this kernel is
   attesting to. Computed by the kernel as `keccak256(validatorAddr || round
   || startBlockHeight || startBlockHash || dkgPubKey || enclaveCommKey)` and
   bound into the quote at a backend-specific location.

The dataCommitment binding location varies because the underlying mechanism
varies, but the on-chain semantics are uniform: the kernel proves it
generated the keys it claims to have generated, and the chain whitelists the
exact code that produced them.

## Backend-specific docs

- **[enclave/sgx/README.md](sgx/README.md)** — Intel SGX setup: Gramine 1.9
  install, manifest reproducibility (Ubuntu 24.04 + Go 1.24.0 + Gramine 1.9
  pinned for matching MRENCLAVE), `make build-sgx` workflow, sign + run,
  systemd unit.
- **[enclave/tdx/README.md](tdx/README.md)** — Intel TDX setup: runtime
  requirements (kernel ≥ 6.7), vTPM-in-TCB requirement, the
  `supportedProviders` PolicyOR flow, bootstrap-mode digest population, and
  per–guest-interface setup guides:
  - **[enclave/tdx/setup/direct.md](tdx/setup/direct.md)** — direct
    configfs-tsm path (bare-metal, GCP CVMs, IBM Cloud, OCI, future AWS TDX).
  - **[enclave/tdx/setup/paravisor.md](tdx/setup/paravisor.md)** —
    paravisor-mediated path (currently OpenHCL on Hyper-V, used by Azure
    Confidential VM TDX).
