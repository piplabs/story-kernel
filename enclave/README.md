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
- `enclave/tdx/` — TDX configfs-tsm quote + vTPM-PolicyOR seal + sealed DB

## Quote semantics in one sentence

The on-chain validation hooks (`SGXValidationHook` and `TDXValidationHook` in
the `story` contracts repo) treat the kernel as a black-box trust anchor whose
quote binds two 32-byte commitments:

1. **codeCommitment** — proves *what code* is running (MRENCLAVE for SGX,
   `keccak256(RTMR3)` for the supported TDX direct path, both compared
   against the `DKG.enclaveTypeData[enclaveType].codeCommitment` whitelist).
   For TDX the kernel self-extends RTMR3 once at startup with SHA-384 of its
   own ELF, so the value is `SHA-384(0x00..00 || SHA-384(elf))` and binds
   the running Go binary (see `enclave/tdx/backend.go::extendBinaryMeasurementOnce`).
   The Story-side TDX hook checks the platform half separately as
   `keccak256(MRTD || RTMR0 || RTMR1 || RTMR2)` via its platform approval
   list — RTMR2 captures TD initrd + cmdline (a boot-image property) and
   lives in the platform half, not the binary half.
2. **dataCommitment** — proves *which on-chain registration* this kernel is
   attesting to. Computed by the kernel as `keccak256(validatorAddr || round
   || startBlockHeight || startBlockHash || dkgPubKey || enclaveCommKey)` and
   bound into the quote at a backend-specific location.

The dataCommitment binding location varies because the underlying mechanism
varies, but the on-chain semantics are uniform: the kernel proves it
generated the keys it claims to have generated, and the chain whitelists the
exact code that produced them.

## Backend-specific docs

- **[enclave/tdx/README.md](tdx/README.md)** — Intel TDX setup: runtime
  requirements (kernel ≥ 6.7), vTPM-in-TCB requirement, the
  `supportedProviders` PolicyOR flow, and bootstrap-mode digest population.
  For a production TDX node, build and operate the image under
  [launcher/](../launcher/).
