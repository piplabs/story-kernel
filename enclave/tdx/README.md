# TDX Backend

Intel TDX backend for Story Kernel. This document covers backend-level
concepts; per-host setup procedures are in [setup/](setup/). For the TEE
backend overview see [enclave/README.md](../README.md).

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                  Story Kernel (TDX)                    │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐    │
│  │   DKG    │  │ vTPM-    │  │  Light Client      │    │
│  │ Service  │  │ PolicyOR │  │  (sealed DB)       │    │
│  │          │  │  Seal    │  │                    │    │
│  └──────────┘  └──────────┘  └────────────────────┘    │
│       │              │                                 │
│       ▼              ▼                                 │
│  ┌──────────────────────────────────────────────────┐  │
│  │   platform.QuoteProvider (vendor adapter)        │  │
│  │   ┌──────────────┐    ┌─────────────────────┐    │  │
│  │   │   direct     │ OR │     paravisor       │    │  │
│  │   │ configfs-tsm │    │ vTPM HCL + IMDS QGS │    │  │
│  │   └──────────────┘    └─────────────────────┘    │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
                          │
                      gRPC API
```

## Guest interface dispatch

TDX has two structurally different guest interfaces. The kernel registers
both as `platform.Vendor` adapters, probes them at startup, and uses the
first one that succeeds. An operator override is available via
`STORY_TDX_VENDOR=direct|paravisor`.

| Adapter | Mechanism | `V4.report_data` | When applicable |
|---|---|---|---|
| `direct` (`enclave/tdx/platform/direct/`) | configfs-tsm via `go-tdx-guest` (kernel ≥ 6.7) | guest-controlled (mirrors SGX `report_data` semantics) | bare-metal, GCP CVMs, IBM Cloud, OCI, future AWS TDX — anywhere the upstream Linux TDX guest interface is exposed |
| `paravisor` (`enclave/tdx/platform/paravisor/`) | vTPM `/dev/tpmrm0` + HCL envelope at NV `0x01400001` + IMDS QGS endpoint `http://169.254.169.254/acc/tdquote` | paravisor-locked to `SHA256(VariableData)` | guests where a paravisor mediates TDX. Currently OpenHCL on Hyper-V (Azure CVM TDX) is the only production deployment of this shape |

The branching key is the **guest interface**, not the cloud vendor. Any
future paravisor-style guest with the same wire-level shape (HCL-style
envelope + IMDS-style QGS endpoint) reuses the `paravisor` adapter without
code changes.

For the on-chain validation flow that decodes both paths uniformly via the
`STBN` Path-B bundle, see `TDXValidationHook.sol` and
`enclave/tdx/platform/bundle.go`.

## Runtime requirements

| Component | Requirement | Why |
|---|---|---|
| Linux kernel | **>= 6.7** for `direct` adapter | configfs-tsm interface (`/sys/kernel/config/tsm/report/`) is the only direct attestation path. The legacy `/dev/tdx_guest` ioctl is **not** used as a fallback. |
| TDX device | `/sys/kernel/config/tsm/report/` (direct) **or** vTPM HCL envelope (paravisor) | One must be present and reachable. |
| vTPM | Reachable at `/dev/tpmrm0` (preferred) or `/dev/tpm0` | Sealing is bound to the vTPM PolicyOR over PCRs. Required by **both** adapters because sealing always uses the vTPM. |
| Persistent TPM handle | **0x81000001 reserved** | Storage-root key is evicted to this conventional SRK handle. Operators must not assign this handle to other applications. |

## vTPM-in-TCB requirement

The TDX backend's sealing security depends on the vTPM being inside the TD's
Trusted Computing Base. Two acceptable deployment models:

1. **Paravisor with in-TD vTPM** (e.g., Azure Confidential VM with OpenHCL
   paravisor): the vTPM is provided by code that runs inside the TD and
   whose measurement is captured in MRTD/RTMR.
2. **In-TD swtpm in the initrd**: bundle `swtpm` into the TD's initrd such
   that it is measured into MRTD; no out-of-TD vTPM service.

Running with an out-of-TCB vTPM (e.g., a vTPM provided by the host
hypervisor without paravisor measurement) is **unsafe** and explicitly out
of scope. The kernel **does not** detect or enforce this — it is an
operator obligation.

## supportedProviders flow

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
disk-image root-hash measurement. **Operators on a different vTPM stack
must edit `supportedProviders` and rebuild.**

### First deployment (bootstrap mode)

When **every** entry in `supportedProviders` has `ExpectedDigest == nil`,
the TDX backend boots in bootstrap mode. The startup self-check emits a
WARN log containing the empirically measured PCR digest in copy-pasteable
hex:

```
WARN[ts] TDX backend in bootstrap mode — no provider has a populated ExpectedDigest.
       Current PCR digests by provider:
         default-tpm-pcrs-7-11 (PCRs 7,11): 0x<64-hex-chars>
       Populate the matching entry in supportedProviders[].ExpectedDigest
       and rebuild before production deployment.
```

The operator pastes the measured digest into source as `ExpectedDigest:
[]byte{0x..., 0x..., ...}` and rebuilds. From that point on the gate
becomes strict: any boot whose PCR state does not match a populated entry
will `log.Fatal` and refuse to start.

### Adding more providers

Adding a second acceptable PCR state (e.g., for a planned firmware upgrade)
is also a code edit + redeploy. The TPM enforces a PolicyOR over all
populated branches, so any of them satisfies the unseal policy.

## Out of scope (this repository)

The following are explicitly NOT covered by `make build-tdx` or this
repository's CI:

- **TD disk image construction**: initrd, OVMF, td-shim, dm-verity hash chain.
- **vTPM provisioning**: swtpm setup, paravisor configuration, EK/SRK
  pre-eviction.
- **dm-crypt automation**: disk encryption keys derivation, PCR-locked
  unlock flows.
- **Launch orchestration**: systemd units, node-launcher integration, kernel
  command-line wiring.
- **On-chain TDX whitelisting**: `TDXValidationHook` contract deployment
  and `whitelistEnclaveType(bytes32(2), ...)` registration are operator and
  contract-team work tracked in their respective repositories.

These are tracked in deployment runbooks and `node-launcher` work, not here.

## Hardware-in-the-loop validation

The unit-test suite (`make test-tdx`) runs entirely on the TPM2 simulator
plus a mock quote provider — no TDX silicon required, suitable for CI. Real
behavior on a TDX host is validated separately via the deployment pipeline:

1. Boot a TDX-capable host with the appropriate guest interface (see
   [setup/](setup/) for per-vendor steps).
2. Provision a vTPM that satisfies the in-TCB requirement above.
3. `make build-tdx && ./build/story-kernel start --home /opt/story-kernel`
   and verify the startup self-check WARN/INFO format and a quote
   round-trip.

## Per–guest-interface setup

- **[setup/direct.md](setup/direct.md)** — direct configfs-tsm path. Use
  this on bare-metal TDX hosts and any cloud whose hypervisor exposes the
  upstream Linux TDX guest interface (GCP, IBM, OCI, future AWS TDX).
- **[setup/paravisor.md](setup/paravisor.md)** — paravisor-mediated path.
  Use this on guests where a paravisor intercepts TDX operations and locks
  `V4.report_data`. Currently the only production deployment of this shape
  is OpenHCL on Hyper-V, used by Azure Confidential VM TDX.

## Build

```bash
make build-tdx
```

Other TDX-related Make targets:

| Target | Notes |
|---|---|
| `make test-tdx` | Unit tests under `tdx` build tag, TPM2 simulator, mock quote provider — no hardware required. |
| `make lint-tdx` | golangci-lint under the TDX build tag. |
