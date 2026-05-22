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
│  │   ┌──────────────┐                               │  │
│  │   │   direct     │                               │  │
│  │   │ configfs-tsm │                               │  │
│  │   └──────────────┘                               │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
                          │
                      gRPC API
```

## Vendor selection

The TDX backend uses a vendor adapter to acquire the V4 quote. Only the
`direct` adapter (`enclave/tdx/platform/direct/`) ships today; it calls
`configfs-tsm` via `go-tdx-guest` and only works when the host exposes the
upstream Linux TDX guest interface (kernel ≥ 6.7, `/sys/kernel/config/tsm/report/`).
At process start, `backend.init` walks the platform registry in registration
order and uses the first vendor whose `Probe()` succeeds.

**Operators leave `STORY_TDX_VENDOR` unset.** The variable exists as an
escape hatch: setting `STORY_TDX_VENDOR=<name>` forces a specific adapter
by name and skips auto-detect; the kernel logs the chosen vendor at info
level on startup so you can confirm which one ran. Today the only legal
value is `direct`; passing a name that is not registered fails fast at
startup.

### Out of scope

The following guest interfaces are explicitly NOT supported:

- **Paravisor-mediated TDX guests** (e.g., Azure Confidential VM TDX with
  OpenHCL). On those hosts `V4.report_data` is paravisor-locked, the
  upstream `configfs-tsm` interface is unavailable, and the on-chain
  `TDXValidationHook` accepts raw V4/V5 quotes only. Earlier prototypes
  carried a `paravisor` adapter that emitted "Path-B STBN" bundles; it
  was removed because the chain-side verifier never consumed it.
- **Bare-metal hosts with `/dev/tdx_guest` only** (no configfs-tsm). The
  legacy ioctl path is intentionally not wired as a fallback; upgrade the
  host kernel to 6.7+ instead.

The Story-side `TDXValidationHook` accepts raw V4/V5 quotes: it checks
`codeCommitment = keccak256(RTMR2)` and separately approves
`keccak256(MRTD || RTMR0 || RTMR1)`.

## Supported platforms

| Cloud / SKU | Region | Vintage | RTMR1 (boot chain) | Binary commitment `keccak256(RTMR2)` | Platform commitment `keccak256(MRTD‖RTMR0‖RTMR1)` |
|---|---|---|---|---|---|
| GCP `c3-standard-4` | europe-west4-a | **v1** — provisioning ≤ 2026-05-11 | `c041916a…cba4` | `0xf6825d2c…37a7` | `0x824e5e0e…0faf` |
| GCP `c3-standard-4` | europe-west4-a | **v2** — provisioning ≥ 2026-05-12 | `176bab53…57d4f` | `0xf6825d2c…37a7` | `0x9acca7cf…c785` |

`DKG.enclaveTypeData[2].codeCommitment` is the binary column;
`TDXValidationHook.approvedPlatforms[…]` is the platform column.

> **Why this fans out.** RTMR2 measures the TD's initrd + kernel cmdline
> (NOT the story-kernel binary) and is stable across rebuilds; RTMR0
> measures the SKU identity (TDX module + ACMs); RTMR1 captures OVMF +
> bootloader and shifts whenever the cloud provider rolls out new
> firmware. **A vintage = a distinct RTMR1.** One binary commitment fans
> out to N platform commitments — that is the "matrix-sum (1 binary × N
> platforms)" horizontal-scaling pattern: deploy the same TD image
> everywhere; let governance approve each vintage's platform commitment
> on the hook.

### Raw measurements (48-byte fields)

```text
# Common across both vintages
MRTD  = feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162
RTMR0 = 70e9cd9b25c0277e61f9aa328a6346fb684de307babd31c17cd9aeecf9f8f75a6e8ccc5822a09a4b6d3db529c0adfb6c
RTMR2 = 261eb562e22a8468350019ef9a979dca3e6d1b9f8ab6db7a9544c19086e5e1b4b437e80696d34f8cd4da42999dbcab34

# RTMR1 per vintage
RTMR1_v1 = c041916ac1f5592fff0ce4cdf1c94b96870ae5786d857f605179f73ce6e9114892f29f8463c8ff2d27af6174f98acba4
RTMR1_v2 = 176bab53534ff9e5b1a9a4476ed377ef041ed44b3a3225359456f3746e3051774b00f5a6cd710b876fdf91f506a57d4f
```

### Adding a row

**Append a new row to the table above whenever a new SKU/vintage is
qualified, the TD image or initrd changes, or a firmware roll-out shifts
the vintage on existing hosts.** Then bump the affected commitment in
`contracts/script/GenerateAlloc.s.sol` (PR #831 hybrid hook script) and
redeploy / reapprove on the on-chain hook.

#### Recapture procedure

1. SSH to the target TDX host. Make sure the story-kernel build you care
   about is the one that owns the running TD (a host reboot resets RTMR2,
   so reboot after switching initrd / cmdline).
2. Pull a fresh quote off the configfs-tsm interface:
   ```bash
   sudo rmdir /sys/kernel/config/tsm/report/req 2>/dev/null
   sudo mkdir /sys/kernel/config/tsm/report/req
   sudo dd if=/dev/zero of=/sys/kernel/config/tsm/report/req/inblob bs=64 count=1
   sudo dd if=/sys/kernel/config/tsm/report/req/outblob of=/tmp/quote.bin bs=1 count=8192
   sudo rmdir /sys/kernel/config/tsm/report/req
   ```
3. Pull the 48-byte fields at the V4 TD\_QUOTE\_BODY offsets:
   ```bash
   q=/tmp/quote.bin
   echo "MRTD  = $(xxd -p -s 184 -l 48 $q | tr -d '\n')"
   echo "RTMR0 = $(xxd -p -s 376 -l 48 $q | tr -d '\n')"
   echo "RTMR1 = $(xxd -p -s 424 -l 48 $q | tr -d '\n')"
   echo "RTMR2 = $(xxd -p -s 472 -l 48 $q | tr -d '\n')"
   ```
4. Compute the 32-byte commitments off-chain
   (`python3 -c "from eth_utils import keccak; print(keccak(bytes.fromhex('<hex>')).hex())"`).
5. Append a new row to the table above with the SKU, vintage tag, raw fields,
   and derived commitments. Bump the affected platform commitment in
   `contracts/script/GenerateAlloc.s.sol` (PR #831 hybrid hook script) and
   redeploy / reapprove.

> **Vintage tagging.** A vintage is *defined by RTMR1* — same RTMR1 means
> same firmware/OVMF/bootloader chain, regardless of when the VM was
> created. Newly provisioned instances inherit the host's current vintage.
> When GCP/Azure/IBM roll out a firmware update, brand new VMs will start
> reporting a new RTMR1; old VMs that survive the rollout keep their old
> RTMR1 until they are recreated.

## Runtime requirements

| Component | Requirement | Why |
|---|---|---|
| Linux kernel | **>= 6.7** | configfs-tsm interface (`/sys/kernel/config/tsm/report/`) is the only supported attestation path. The legacy `/dev/tdx_guest` ioctl is **not** used as a fallback. |
| TDX device | `/sys/kernel/config/tsm/report/` | Must be present and reachable. |
| vTPM | Reachable at `/dev/tpmrm0` (preferred) or `/dev/tpm0` | Sealing is bound to the vTPM PolicyOR over PCRs. |
| Persistent TPM handle | **0x81000001 reserved** | Storage-root key is evicted to this conventional SRK handle. Operators must not assign this handle to other applications. |

## vTPM-in-TCB requirement

The TDX backend's sealing security depends on the vTPM being inside the TD's
Trusted Computing Base. The supported deployment model is:

- **In-TD swtpm in the initrd**: bundle `swtpm` into the TD's initrd such
  that it is measured into MRTD; no out-of-TD vTPM service.

Running with an out-of-TCB vTPM (e.g., a vTPM provided by the host
hypervisor without in-TD measurement) is **unsafe** and explicitly out
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
- **vTPM provisioning**: in-TD swtpm setup, EK/SRK pre-eviction.
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

## Build

```bash
make build-tdx
```

Other TDX-related Make targets:

| Target | Notes |
|---|---|
| `make test-tdx` | Unit tests under `tdx` build tag, TPM2 simulator, mock quote provider — no hardware required. |
| `make lint-tdx` | golangci-lint under the TDX build tag. |
