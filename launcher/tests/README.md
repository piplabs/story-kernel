# tests/

Self-contained tests for launcher/ components. Two tiers:

| Tier | Where it runs | Coverage |
|---|---|---|
| **macOS-local / CI fast** | Any POSIX host with bash + python3 + shellcheck | Script syntax, logic, schema, formula round-trips |
| **Linux + TDX** | A real TD (see `docs/operator-guide.md`) | End-to-end boot, PCR extension, dm-verity behavior |

The Linux+TDX tier is intentionally *not* automated here — it requires
real hardware. Instead, `docs/operator-guide.md` describes the manual
checks the first operator performs before declaring a release stable.

## Running locally

```sh
launcher/tests/run-all.sh
```

This invokes each `*_test.sh` in alphabetical order and exits non-zero
if any fail.

## What's covered locally

| Test | What it asserts |
|---|---|
| `shellcheck_test.sh` | Every shell script under launcher/ passes shellcheck (POSIX sh) |
| `diff-cmdline_test.sh` | `boot/diff-cmdline.sh` correctly detects drift between kernel-cmdline and mkosi.conf |
| `code-commitment_test.sh` | The keccak256(RTMR3-after-extend) computation in `build/build.sh` is correct against a known test vector |
| `manifest_test.sh` | A synthetic `manifest.json` matches the documented schema (jq-based) |
| `systemd-unit_test.sh` | Every systemd unit in mkosi.skeleton/ parses (systemd-analyze if available, regex fallback otherwise) |

## What's NOT covered locally

| Concern | Where it is covered instead |
|---|---|
| Actual image build | `build/verify-reproducible.sh` on a Linux builder |
| PCR 12 extension at boot | First-boot operator check + `attestation/verify-rtmr3.sh` |
| dm-verity rejecting a tampered block | Manual: corrupt a byte, attempt boot, kernel panic expected |
| Hardening flags actually applied at runtime | Manual: boot, attempt `ptrace`, expect EPERM |
